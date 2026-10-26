#!/usr/bin/env bash
# Writes docs/example-report.html: the report of `sluice demo --scale 100`, the synthetic hour of
# a small company network, so a reader sees what Sluice proposes before installing anything.
# The demo is deterministic, so the file only changes when the report or the analysis does.
#
#   scripts/example-report.sh           write it again
#   scripts/example-report.sh --check   fail when the committed file is not what Sluice writes now
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cargo run --locked --release -q -p sluice-cli -- demo --scale 100 --out "$out" >/dev/null
if [[ ${1:-} == --check ]]; then
  if cmp -s "$out/report.html" docs/example-report.html; then
    echo "docs/example-report.html is current"
  else
    echo "docs/example-report.html is out of date: run scripts/example-report.sh and commit it" >&2
    exit 1
  fi
else
  cp "$out/report.html" docs/example-report.html
  echo "wrote docs/example-report.html ($(wc -c < docs/example-report.html) bytes)"
fi
