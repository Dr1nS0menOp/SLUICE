# ADR 0003: Linux is the only supported platform

- Status: Accepted
- Date: 2026-10-09

## Context

Sluice runs next to Vector in the place where logs flow: on servers, VMs and containers. In
practice those are Linux. Supporting Windows and macOS as well would cost CI time, extra code paths
(file paths, service management, signals) and testing effort, without serving the people who
deploy Sluice.

## Decision

- **Supported:** Linux (x86_64 and aarch64), including WSL2.
- **Developing on Windows:** WSL2 is the supported way. The sources may live on the Windows
  filesystem, but every build and test runs inside WSL (`scripts/wsl.ps1`).
- **Not supported:** native Windows and macOS builds. We don't test them, we don't ship release
  binaries for them, and we accept no platform-specific code for them.
- **Code may assume Linux** wherever that makes it simpler (paths, signals, systemd, `/proc`),
  without `cfg` fallbacks.

## Consequences

- CI runs on Linux only.
- Release artifacts: static Linux binaries (musl, x86_64 and aarch64) and a container image.
- A "laptop" in the product goals means a Linux laptop, WSL2 or a Linux VM or container.
- macOS contributors develop in a Linux container or VM.
