#!/usr/bin/env bash
# A JSON source sent to a custom table (`<Name>_CL`), end to end in the Kusto emulator (ADR 0013):
# `sluice connect sentinel --sample` writes the table and its data collection rule, then
# `sluice analyze --native sentinel` proves a transformation for it with a Sentinel rule on the
# table, writes the rule back with an archive flow, and does so again on the rule it wrote.
#
#   SLUICE_KUSTO_URL=http://127.0.0.1:8090 scripts/sentinel-custom-check.sh
#
# kql-check.sh runs it once the emulator is up.
set -euo pipefail

url="${SLUICE_KUSTO_URL:-http://127.0.0.1:8090}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sluice() { cargo run --locked -q -p sluice-cli -- "$@"; }

sluice demo --out "$work/demo" >/dev/null
# Records as a flat JSON application sends them, and as the table stores them (an empty field is
# a missing one).
mkdir -p "$work/samples"
cp "$work"/demo/samples/*.ndjson "$work/samples/"
python3 -I - "$work/demo/samples/windows-security.ndjson" "$work/samples/windows-security.ndjson" <<'EOF'
import json, sys
with open(sys.argv[2], "w") as out:
    for line in open(sys.argv[1]):
        record = json.loads(line)
        flat = {k: v for k, v in record.items() if v not in ("", None, [], {}) and not isinstance(v, dict)}
        out.write(json.dumps(flat) + "\n")
EOF

sluice connect sentinel --sample "$work/samples/windows-security.ndjson" --table Win \
    --out "$work/connect" \
    --workspace /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w \
    >/dev/null
mkdir -p "$work/rules"
cat >"$work/rules/failed-logons.yaml" <<'EOF'
id: 11111111-1111-1111-1111-111111111111
name: Failed logons on a custom table
kind: Scheduled
query: |
  Win_CL
  | where EventID == 4625
  | project TimeGenerated, TargetUserName, IpAddress
EOF

analyze() {
    sluice analyze --input "$work/samples" --sources "$work/demo/sluice.yaml" \
        --sentinel-rules "$work/rules" --kusto "$url" --sentinel-table windows-security=Win_CL \
        --native sentinel --sentinel-dcr "$1" --rules-complete --out "$2" | grep '^  native'
}
analyze "$work/connect/Win.dcr.json" "$work/first"
kql="$work/first/sentinel/windows-security.transform.kql"
grep -q "extend \['Message'\]" "$kql" || { echo "Message is not removed" >&2; exit 1; }
grep -q "project-rename" "$kql" || { echo "the rule's own renames are gone" >&2; exit 1; }

# Again, on the rule Sluice wrote: its part is replaced, not added.
cp "$work/first/sentinel/dcr.json" "$work/again.json"
analyze "$work/again.json" "$work/second"
cmp -s "$kql" "$work/second/sentinel/windows-security.transform.kql" \
    || { echo "a second run changed the transformation" >&2; exit 1; }
echo "custom table: proven, written, and written the same again"
