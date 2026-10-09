#!/usr/bin/env bash
# Replay smoke test: `sluice replay` from an archive into a real Vector `http_server` source.
#
# Usage: scripts/replay-smoke.sh <archive_dir>   (for example out/up/archive after live-smoke.sh)
#
# Checks that `sluice search --count` agrees with the archive's raw line count, and that a
# filtered replay delivers exactly the events the same search selects, unchanged.
set -euo pipefail

archive="${1:?usage: replay-smoke.sh <archive_dir>}"
target_dir="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p sluice-cli
bin="${target_dir}/release/sluice"
work=$(mktemp -d)
trap 'kill "${vector_pid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

raw=$(find "$archive" -name '*.ndjson.gz' -exec zcat {} + 2>/dev/null | grep -c . || true)
counted=$("$bin" search --archive "$archive" --count 2>/dev/null)
echo "archive lines $raw, search --count $counted"
[ "$raw" -eq "$counted" ] || fail "search does not see every archived event"

select=(--archive "$archive" --source windows-security --where EventID=4624)
"$bin" search "${select[@]}" 2>/dev/null | sort > "$work/expected.ndjson"
expected=$(wc -l < "$work/expected.ndjson")
[ "$expected" -gt 0 ] || fail "nothing to replay"

cat > "$work/vector.yaml" <<EOF
data_dir: $work
sources:
  replay:
    type: http_server
    address: 127.0.0.1:9199
    decoding: { codec: json }
    framing: { method: newline_delimited }
transforms:
  # The http_server source adds its own fields; drop them to compare with the archive.
  original:
    type: remap
    inputs: [replay]
    source: |
      del(.path)
      del(.source_type)
      del(.timestamp)
sinks:
  out:
    type: file
    inputs: [original]
    path: $work/replayed.ndjson
    encoding: { codec: json }
EOF
vector --quiet --config "$work/vector.yaml" &
vector_pid=$!
for _ in $(seq 50); do
  (exec 3<>/dev/tcp/127.0.0.1/9199) 2>/dev/null && break
  sleep 0.2
done

"$bin" replay "${select[@]}" --url http://127.0.0.1:9199 --batch 100
kill -TERM "$vector_pid"
wait "$vector_pid" || true

replayed=$(wc -l < "$work/replayed.ndjson")
echo "expected $expected, replayed $replayed"
[ "$expected" -eq "$replayed" ] || fail "replay lost or added events"

# Compare content without Vector's receive fields, which the archive keeps and the replay target
# re-adds.
python3 - "$work/expected.ndjson" "$work/replayed.ndjson" <<'EOF' || fail "replayed events differ from the archive"
import json, sys
def canonical(path):
    rows = []
    for line in open(path):
        event = json.loads(line)
        for key in ("path", "source_type", "timestamp"):
            event.pop(key, None)
        rows.append(json.dumps(event, sort_keys=True))
    return sorted(rows)
sys.exit(canonical(sys.argv[1]) != canonical(sys.argv[2]))
EOF
echo "replay smoke test passed"
