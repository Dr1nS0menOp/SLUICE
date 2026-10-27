#!/usr/bin/env bash
# Differential test of `sluice mcp` against a real MCP client: the official Python SDK (MIT),
# fetched by uv into its cache, in the versions pinned below (ADR 0035). Needs uv.
#   bash scripts/mcp-check.sh
set -euo pipefail

# The 1.x line and the 2.x line of the SDK. Both open stdio with `initialize` (2.3.0 asks for
# 2025-11-25 there, though it speaks the stateless 2026-07-28 elsewhere).
SDKS=("mcp==1.30.0" "mcp==2.3.0")

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
cargo build --locked -q -p sluice-cli
sluice="${CARGO_TARGET_DIR:-$root/target}/debug/sluice"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$sluice" demo --scale 2 --out "$work/out" >/dev/null
for sdk in "${SDKS[@]}"; do
  echo "== $sdk"
  # -I: the client runs isolated from the working directory and the user's site packages.
  uv run -q --no-project --with "$sdk" python -I "$root/scripts/mcp-client.py" \
    "$sluice" "$work/out" "$work/out/samples" "$work/out/sluice.yaml" "$root/examples/rules/sigma"
done
