#!/usr/bin/env bash
# Checks what scripts/package.sh wrote, as people install it (ADR 0040): the .deb in Debian and
# Ubuntu, the .rpm in Fedora, and the container image, each running `sluice --version` and
# `sluice demo`. Needs Docker; checks the packages of this machine's architecture.
#
#   ./scripts/package-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

command -v docker >/dev/null || { echo "==> packages: skipped (no docker)"; exit 0; }
version=$(cargo metadata --format-version 1 --no-deps --locked |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "sluice-cli"))')
case "$(uname -m)" in
    x86_64) deb_arch=amd64 rpm_arch=x86_64 ;;
    aarch64) deb_arch=arm64 rpm_arch=aarch64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
deb=dist/sluice_${version}_${deb_arch}.deb
rpm=dist/sluice-${version}-1.${rpm_arch}.rpm
for file in "$deb" "$rpm" "dist/image/sluice-${deb_arch}"; do
    [[ -f $file ]] || { echo "no ${file}: run scripts/package.sh first" >&2; exit 1; }
done

# What every installation must do: say its version and run the demo with the proof holding.
check='sluice --version | grep -qx "sluice '"$version"'" && sluice demo --scale 1 --out /tmp/demo | grep -q "no detection changed"'

for image in debian:12 ubuntu:24.04; do
    echo "==> .deb in ${image}"
    docker run --rm -v "$PWD/dist:/dist:ro" "$image" sh -c \
        "dpkg -i /dist/$(basename "$deb") >/dev/null && $check && echo '    ok'"
done
echo "==> .rpm in fedora:42"
docker run --rm -v "$PWD/dist:/dist:ro" fedora:42 sh -c \
    "rpm -i /dist/$(basename "$rpm") && $check && echo '    ok'"

echo "==> the container image"
tag=sluice-package-check:${version}
if docker buildx version >/dev/null 2>&1; then
    docker buildx build -q --load -t "$tag" dist/image >/dev/null
else
    # Without buildx, the legacy builder, given the platform BuildKit would set.
    DOCKER_BUILDKIT=0 docker build -q --build-arg "TARGETARCH=${deb_arch}" -t "$tag" dist/image \
        >/dev/null 2>&1
fi
# Captured first: `grep -q` stops reading early, which pipefail would count as a failure.
said=$(docker run --rm "$tag" --version)
[[ $said == "sluice ${version}" ]] || { echo "the image says $said" >&2; exit 1; }
said=$(docker run --rm "$tag" demo --scale 1 --out /tmp/demo)
grep -q "no detection changed" <<<"$said" || { echo "$said" >&2; exit 1; }
# It runs as a user without privileges.
[[ $(docker inspect --format '{{.Config.User}}' "$tag") == 65532 || \
   $(docker inspect --format '{{.Config.User}}' "$tag") == nonroot ]] || {
    echo "the image runs as root" >&2
    exit 1
}
docker rmi -f "$tag" >/dev/null
echo "    ok"
echo "PACKAGES CHECKED"
