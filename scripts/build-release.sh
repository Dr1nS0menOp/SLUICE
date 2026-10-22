#!/usr/bin/env bash
# Builds the static release binaries (musl, x86_64 and aarch64) and their SHA-256 sums into
# dist/. Static binaries run on any Linux distribution, WSL2 included. Requires
# scripts/install-zig.sh.
#
#   ./scripts/build-release.sh               # both targets
#   ./scripts/build-release.sh x86_64        # one target
set -euo pipefail

command -v cargo-zigbuild >/dev/null || { echo "run scripts/install-zig.sh first" >&2; exit 1; }
[ "$#" -gt 0 ] || set -- x86_64 aarch64
target_dir="${CARGO_TARGET_DIR:-target}"
version=$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "sluice-cli"))')
mkdir -p dist

for arch in "$@"; do
    target="${arch}-unknown-linux-musl"
    rustup target add "${target}" >/dev/null
    echo "==> ${target}"
    cargo zigbuild --locked --release --target "${target}" -p sluice-cli
    name="sluice-${version}-${target}"
    cp "${target_dir}/${target}/release/sluice" "dist/${name}"
    (cd dist && sha256sum "${name}" > "${name}.sha256")
    file "dist/${name}" 2>/dev/null || true
done
