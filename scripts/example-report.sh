#!/usr/bin/env bash
# Writes docs/example-report.html: the report of an analysis of real attack data, so a reader
# sees what Sluice proposes before installing anything. The data is OTRF Security-Datasets'
# APT29 day 1 (MIT, Copyright (c) 2021 Open Threat Research Forge): Security and Sysmon of four
# machines while the APT29 emulation ran. It is fetched into a user cache, never the repository,
# and checked against its SHA-256. The rules are the example's own (examples/apt29/rules).
# The analysis is deterministic, so the file only changes when the report or the analysis does.
#
#   scripts/example-report.sh           write it again
#   scripts/example-report.sh --check   fail when the committed file is not what Sluice writes now
set -euo pipefail
cd "$(dirname "$0")/.."
url=https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip
sha256=98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5
cache=${XDG_CACHE_HOME:-$HOME/.cache}/sluice-datasets/otrf-apt29-day1
mkdir -p "$cache"
zip=$cache/apt29_evals_day1_manual.zip
if ! echo "$sha256  $zip" | sha256sum --check --status 2>/dev/null; then
  curl -fsSL --max-time 600 -o "$zip.part" "$url"
  echo "$sha256  $zip.part" | sha256sum --check --status || {
    echo "the APT29 dataset does not have the expected SHA-256" >&2
    exit 1
  }
  mv "$zip.part" "$zip"
fi

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
mkdir -p "$out/samples"
# Security and Sysmon records, as the dataset holds them, one per line.
python3 -I - "$zip" "$out/samples" <<'EOF'
import json, sys, zipfile
out = {"security": open(f"{sys.argv[2]}/security.ndjson", "w"),
       "sysmon": open(f"{sys.argv[2]}/sysmon.ndjson", "w")}
with zipfile.ZipFile(sys.argv[1]) as z:
    for name in sorted(z.namelist()):
        with z.open(name) as f:
            for raw in f:
                try:
                    event = json.loads(raw)
                except ValueError:
                    continue
                channel = str(event.get("Channel", "")).lower()
                source = "security" if channel == "security" else (
                    "sysmon" if channel == "microsoft-windows-sysmon/operational" else None)
                if source:
                    out[source].write(json.dumps(event) + "\n")
EOF

cargo run --locked --release -q -p sluice-cli -- analyze --input "$out/samples" \
  --sources examples/apt29/sources.yaml --rules examples/apt29/rules --rules-complete \
  --out "$out/analysis" >/dev/null
if [[ ${1:-} == --check ]]; then
  if cmp -s "$out/analysis/report.html" docs/example-report.html; then
    echo "docs/example-report.html is current"
  else
    echo "docs/example-report.html is out of date: run scripts/example-report.sh and commit it" >&2
    exit 1
  fi
else
  cp "$out/analysis/report.html" docs/example-report.html
  echo "wrote docs/example-report.html ($(wc -c < docs/example-report.html) bytes)"
fi
