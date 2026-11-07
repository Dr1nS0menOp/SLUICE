#!/usr/bin/env bash
# Packages the static binaries scripts/build-release.sh wrote into dist/: a .deb and an .rpm per
# architecture (packaging/nfpm.yaml), the container image's build context (dist/image, with
# packaging/Dockerfile), and a CycloneDX software bill of materials of the binary
# (sluice-VERSION.cdx.json). Each file gets its SHA-256 sum. Requires
# scripts/install-packaging.sh.
#
#   ./scripts/package.sh                 # every binary in dist/
set -euo pipefail
cd "$(dirname "$0")/.."

command -v nfpm >/dev/null || { echo "run scripts/install-packaging.sh first" >&2; exit 1; }
cargo cyclonedx --version >/dev/null 2>&1 || {
    echo "run scripts/install-packaging.sh first" >&2
    exit 1
}
version=$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "sluice-cli"))')

shopt -s nullglob
binaries=(dist/sluice-"${version}"-*-unknown-linux-musl)
[[ ${#binaries[@]} -gt 0 ]] || {
    echo "no binaries of ${version} in dist/: run scripts/build-release.sh first" >&2
    exit 1
}

rm -rf dist/image
mkdir -p dist/image
cp packaging/Dockerfile dist/image/Dockerfile
for binary in "${binaries[@]}"; do
    arch=${binary#dist/sluice-"${version}"-}
    arch=${arch%-unknown-linux-musl}
    case "$arch" in
        x86_64) docker_arch=amd64 ;;
        aarch64) docker_arch=arm64 ;;
        *) echo "unknown architecture ${arch}" >&2; exit 1 ;;
    esac
    install -m 0755 "$binary" "dist/image/sluice-${docker_arch}"
    for packager in deb rpm; do
        echo "==> ${packager} ${arch}"
        # nfpm names architectures as Go does and maps them to each package format's own. It
        # expands variables in some fields only, so the configuration is filled in here.
        sed -e "s|\${SLUICE_VERSION}|${version}|" -e "s|\${SLUICE_ARCH}|${docker_arch}|" \
            -e "s|\${SLUICE_BINARY}|${binary}|" packaging/nfpm.yaml > dist/nfpm.yaml
        nfpm package --config dist/nfpm.yaml --packager "$packager" --target dist/
    done
done

echo "==> software bill of materials"
# Describes the binary as built for Linux: its dependencies, without those only the build uses.
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) cargo cyclonedx \
    --manifest-path crates/sluice-cli/Cargo.toml --format json --spec-version 1.5 \
    --describe binaries --target x86_64-unknown-linux-musl --no-build-deps -qq
# It writes one file per binary next to the crate's manifest.
mv crates/sluice-cli/sluice_bin.cdx.json "dist/sluice-${version}.cdx.json"
# Reproducible output has no serialNumber, which attestations need: one that follows from the
# version and the commit, so the same build gets the same SBOM.
python3 -I - "dist/sluice-${version}.cdx.json" "${version}" "$(git rev-parse HEAD)" <<'EOF'
import json, sys, uuid
path, version, commit = sys.argv[1:]
with open(path) as f:
    bom = json.load(f)
name = f"https://github.com/Dr1nS0menOp/SLUICE/releases/v{version}#{commit}"
bom = {**{k: bom[k] for k in ("bomFormat", "specVersion")},
       "serialNumber": uuid.uuid5(uuid.NAMESPACE_URL, name).urn,
       **{k: v for k, v in bom.items() if k not in ("bomFormat", "specVersion")}}
with open(path, "w") as f:
    json.dump(bom, f, indent=2)
    f.write("\n")
EOF

rm -f dist/nfpm.yaml
cd dist
for file in sluice_"${version}"_*.deb sluice-"${version}"-*.rpm "sluice-${version}.cdx.json"; do
    sha256sum "$file" > "$file.sha256"
    echo "  ${file}"
done
