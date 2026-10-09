#!/usr/bin/env bash
# Installs the release toolchain for static Linux binaries into ~/.local, without root: Zig
# (used as the C compiler and linker for musl targets) and cargo-zigbuild. The Zig download is
# checked against the SHA-256 sums pinned below (from https://ziglang.org/download/index.json).
#
#   ./scripts/install-zig.sh       # then: scripts/build-release.sh
set -euo pipefail

ZIG_VERSION="0.16.0"
ZIGBUILD_VERSION="0.23.4"
case "$(uname -m)" in
    x86_64)
        ARCH="x86_64"
        SHA256="70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00" ;;
    aarch64 | arm64)
        ARCH="aarch64"
        SHA256="ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17" ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ARCHIVE="zig-${ARCH}-linux-${ZIG_VERSION}.tar.xz"
PREFIX="${HOME}/.local/opt/zig-${ZIG_VERSION}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "Downloading Zig ${ZIG_VERSION} (${ARCH})"
curl --proto '=https' --tlsv1.2 -fsSL -o "${WORK}/${ARCHIVE}" \
    "https://ziglang.org/download/${ZIG_VERSION}/${ARCHIVE}"
echo "Verifying checksum"
echo "${SHA256}  ${WORK}/${ARCHIVE}" | sha256sum --check --strict -

mkdir -p "${PREFIX}" "${HOME}/.local/bin"
tar -xJf "${WORK}/${ARCHIVE}" -C "${PREFIX}" --strip-components=1
ln -sf "${PREFIX}/zig" "${HOME}/.local/bin/zig"
"${HOME}/.local/bin/zig" version

cargo install --locked --version "${ZIGBUILD_VERSION}" cargo-zigbuild
