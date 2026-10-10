# ADR 0007: Packaging as static binaries and one image with Vector

- Status: Accepted
- Date: 2026-10-09

## Context

Sluice runs on Linux only (ADR 0003), on x86_64 and aarch64, often on hosts the operator does not
want to install a toolchain or shared libraries on. `sluice up` runs Vector as its child process
(ADR 0005), so a deployment needs both binaries, at versions verified together
(`docs/compatibility.md`).

## Decision

1. **Static musl binaries** for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`,
   built by `scripts/build-release.sh` with `cargo-zigbuild`. Zig is the C compiler and linker
   for both targets, so one Linux host (or CI runner) builds both without Docker, root or a
   cross toolchain. `scripts/install-zig.sh` installs the pinned Zig (checksum-verified) and
   `cargo-zigbuild` into the user's home.
2. **The container image packages those binaries, it does not compile.** The `Dockerfile` copies
   `dist/docker/<arch>/sluice` onto `timberio/vector:0.59.0-distroless-static`, pinned by digest.
   What runs in a container is byte for byte the released binary, next to the Vector it is
   verified with, and nothing else (no shell, no package manager).
3. **Releases are drafts.** A `v*` tag builds the binaries and attaches them with SHA-256 sums to
   a draft GitHub release; a maintainer publishes it. Publishing the image to a registry is left
   until the project has one.
4. `cargo install --path crates/sluice-cli` remains the route for people who build from source.
   Publishing to crates.io waits for a repository URL and a release (`publish = false`).

## Consequences

- Bumping Vector means updating `install-vector.sh`, the Dockerfile's tag and digest, and
  `docs/compatibility.md` together.
- The base image installs Vector as `/usr/local/bin/vector` (its entrypoint); the container
  configuration names that path. Checked on the pinned digest through the registry API:
  the layer holds `vector 0.59.0 (x86_64-unknown-linux-musl)`, static-pie. The image's layers
  plus the static `sluice`, run in a user-namespace chroot with `/dev` bind-mounted (Docker
  provides `/dev`; without it spawning Vector fails, because its stdin is `/dev/null`), ran
  `sluice up --demo-traffic` end to end: reloads, promotions, archive and SIEM output.
- Zig prints `ignoring deprecated linker optimization setting '1'` while linking; it is harmless.
- The image cannot be built on a machine without Docker access; CI builds both architectures and
  runs the amd64 image on every push.
