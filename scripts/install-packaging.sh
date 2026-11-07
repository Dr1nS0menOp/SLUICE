#!/usr/bin/env bash
# Installs the tools that package a release into ~/.local, without root: nfpm (the .deb and
# .rpm packages), checked against the SHA-256 sums pinned below (from nfpm's checksums.txt),
# and cargo-cyclonedx (the software bill of materials).
#
#   ./scripts/install-packaging.sh    # then: scripts/package.sh
set -euo pipefail

NFPM_VERSION="2.48.0"
CYCLONEDX_VERSION="0.5.9"
case "$(uname -m)" in
    x86_64)
        ARCH="x86_64"
        SHA256="6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750" ;;
    aarch64 | arm64)
        ARCH="arm64"
        SHA256="a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ARCHIVE="nfpm_${NFPM_VERSION}_Linux_${ARCH}.tar.gz"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "Downloading nfpm ${NFPM_VERSION} (${ARCH})"
curl --proto '=https' --tlsv1.2 -fsSL -o "${WORK}/${ARCHIVE}" \
    "https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/${ARCHIVE}"
echo "Verifying checksum"
echo "${SHA256}  ${WORK}/${ARCHIVE}" | sha256sum --check --strict -

mkdir -p "${HOME}/.local/bin"
tar -xzf "${WORK}/${ARCHIVE}" -C "${WORK}" nfpm
install -m 0755 "${WORK}/nfpm" "${HOME}/.local/bin/nfpm"
"${HOME}/.local/bin/nfpm" --version | head -n 1

cargo install --locked --version "${CYCLONEDX_VERSION}" cargo-cyclonedx
