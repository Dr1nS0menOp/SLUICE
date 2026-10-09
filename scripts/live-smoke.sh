#!/usr/bin/env bash
# Live smoke test of `sluice up` with demo traffic and the real Vector (ADR 0005).
#
# Runs for ~3 minutes, then checks that recipes were promoted, that Vector enforces them (the
# Windows logon `Message` field is dropped after promotion and summaries arrive), that every
# input event reached the archive after a graceful stop, and that Vector exits with Sluice. Then
# replays part of that archive (scripts/replay-smoke.sh).
# Requires `scripts/install-vector.sh`.
set -euo pipefail

seconds="${1:-200}"
out=out/up
target_dir="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p sluice-cli
bin="${target_dir}/release/sluice"
rm -rf "$out"

"$bin" up --config examples/up/sluice-up.yaml --rules examples/rules/sigma --demo-traffic > "$out.log" 2>&1 &
pid=$!
sleep "$seconds"
"$bin" status
# What `sluice mcp` reads: per-template explanations, source health and rule requirements.
status_json=$(curl -fsS http://127.0.0.1:8686/status)
rules_json=$(curl -fsS http://127.0.0.1:8686/rules)
kill -TERM "$pid"
wait "$pid"

fail() { echo "FAIL: $*" >&2; exit 1; }
siem=$(cat "$out"/siem/*.ndjson)
archived=$(find "$out/archive" -name '*.gz' -exec zcat {} + | wc -l)
forwarded=$(grep -c -v sluice_summary <<< "$siem" || true)
summaries=$(grep -c sluice_summary <<< "$siem" || true)
promoted=$(grep -c "recipe promoted" "$out.log" || true)
logon_reduced=$(grep '"EventID":4624' <<< "$siem" | grep -c -v '"Message"' || true)

echo "archived $archived, forwarded $forwarded, summaries $summaries, promoted $promoted"
[ "$promoted" -gt 0 ] || fail "no recipe was promoted"
[ "$logon_reduced" -gt 0 ] || fail "Vector did not enforce the logon recipe"
[ "$summaries" -gt 0 ] || fail "no summaries arrived"
[ "$forwarded" -lt "$archived" ] || fail "nothing was reduced"
grep -q '"actions":\["' <<< "$status_json" || fail "status explains no template"
grep -q '"source":"windows-security","logsource"' <<< "$status_json" || fail "status has no source health"
grep -q '"stateful":true' <<< "$rules_json" || fail "/rules does not list the correlation rule"
! pgrep -f "vector --config $out/vector.yaml" > /dev/null || fail "Vector outlived sluice"
echo "live smoke test passed"
bash scripts/replay-smoke.sh "$out/archive"
