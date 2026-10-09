#!/usr/bin/env bash
# Installs the Vector release Sluice is verified against (see docs/compatibility.md) into
# ~/.local, without root. The download is checked against Vector's published SHA-256 sums.
#
#   ./scripts/install-vector.sh            # installs to ~/.local/opt and links ~/.local/bin/vector
set -euo pipefail

VERSION="0.59.0"
case "$(uname -m)" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64 | arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ARCHIVE="vector-${VERSION}-${TARGET}.tar.gz"
BASE="https://github.com/vectordotdev/vector/releases/download/v${VERSION}"
PREFIX="${HOME}/.local/opt/vector-${VERSION}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "Downloading Vector ${VERSION} (${TARGET})"
curl --proto '=https' --tlsv1.2 -fsSL -o "${WORK}/${ARCHIVE}" "${BASE}/${ARCHIVE}"
curl --proto '=https' --tlsv1.2 -fsSL -o "${WORK}/SHA256SUMS" "${BASE}/vector-${VERSION}-SHA256SUMS"

echo "Verifying checksum"
(cd "${WORK}" && grep " ${ARCHIVE}\$" SHA256SUMS | sha256sum --check --strict -)

mkdir -p "${PREFIX}" "${HOME}/.local/bin"
tar -xzf "${WORK}/${ARCHIVE}" -C "${PREFIX}" --strip-components=2
ln -sf "${PREFIX}/bin/vector" "${HOME}/.local/bin/vector"
"${HOME}/.local/bin/vector" --version
