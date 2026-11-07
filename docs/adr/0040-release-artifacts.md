# ADR 0040: Packages, a container image and attestations for each release

- Status: Accepted
- Date: 2026-11-08

## Context

Up to 0.2.0 a release was two static binaries (musl, x86_64 and aarch64, ADR 0007) with their
SHA-256 sums. A sum shows that a download is complete, not who built it. Security teams that are
to run Sluice next to their SIEM ask how the binary was built and from what. They also install
software through their package manager or as a container.

## Decision

1. **Packages.** Each release has a `.deb` and an `.rpm` per architecture, built with nfpm
   (`packaging/nfpm.yaml`, `scripts/package.sh`) from the same static binary. They put it in
   `/usr/bin/sluice`, with the licence and the README, and need no dependencies.
2. **A container image**, `ghcr.io/dr1ns0menop/sluice:<version>` and `:latest`, for linux/amd64
   and linux/arm64 (`packaging/Dockerfile`). It holds the static binary on Google's distroless
   `static` base, pinned by digest, and runs as a user without privileges. The base adds the
   files a process expects (`/tmp`, `/etc/passwd`), nothing else. Sluice carries its own CA
   roots (webpki-roots), so the base's are not needed. The proof's engines are not in the image.
3. **A software bill of materials.** `sluice-<version>.cdx.json` is a CycloneDX 1.5 SBOM of the
   binary as built for Linux, with its dependencies and without those only the build uses
   (cargo-cyclonedx).
4. **Attestations.** The release workflow attests the build provenance of every binary, package
   and the image (SLSA provenance, GitHub's artifact attestations), and the SBOM of the
   binaries. `gh attestation verify <file> --repo Dr1nS0menOp/SLUICE` checks that a file was
   built by this repository's workflow from the tagged commit. The image's attestation is
   pushed to the registry with it.
5. **Pinned tools.** nfpm is downloaded at a pinned version and checked against its SHA-256 sum,
   and cargo-cyclonedx is installed at a pinned version (`scripts/install-packaging.sh`), as Zig
   and cargo-zigbuild are.
6. **Tested before a release.** `scripts/package-check.sh` installs the `.deb` in Debian and
   Ubuntu and the `.rpm` in Fedora, runs the image, and runs `sluice demo` in each. CI builds the
   packages and the image on every push, so a broken step shows up before a tag.

## Consequences

- Releases are larger: six binaries and packages, an SBOM, and an image in the registry.
- Verification needs the GitHub CLI, or any tool that reads Sigstore bundles. The SHA-256 sums
  stay for those without either.
- The image is built from the binaries the release attaches, so the image and the downloads are
  the same program.
