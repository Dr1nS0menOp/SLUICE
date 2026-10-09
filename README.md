# Sluice

**An open-source autopilot for security data.** Sluice cuts what you send to your SIEM, and it
proves on your own traffic and rules that no detection changes.

> Status: early development. Nothing here is ready for production yet.

## The idea

Security teams pay for every byte their SIEM ingests, yet much of that data is padding: rendered
boilerplate, empty fields, duplicates, and high-volume events no rule will ever match.

Pipeline tools can cut it, but a person still has to decide what to cut, build the pipeline and
maintain it. Sluice does that work itself:

1. **Discovers** the log templates in your traffic.
2. **Decides** what is fat: format fat (lossless), volume fat (rule-guided) and semantic fat
   (AI-judged).
3. **Proves** that the cut leaves the alert set of your rules unchanged, both ways.
4. **Enforces** the cut with [Vector](https://vector.dev), keeps checking it, and rolls back by
   itself on any mismatch.

Every event is archived at full fidelity before any cut, so any slice can be replayed into any
SIEM.

## Safety contract

These rules are enforced in code, and AI output can never override them:

1. Unknown data passes through untouched.
2. Everything is archived at full fidelity before any cut.
3. Anything a rule could match is forwarded in full.
4. Rare is never cut.
5. Every cut is proven before it is enforced, and is re-verified continuously afterwards.

## Platform

Sluice runs on Linux (x86_64 and aarch64), including WSL2. Windows and macOS aren't supported. On
those systems, run Sluice in WSL2, a VM or a container.

## Building

Sluice is a Rust workspace. The toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo build --release
./scripts/check.sh        # every quality gate: fmt, clippy, tests, docs, cargo-deny
```

## Documentation

- [Architecture decisions](docs/adr/)
- [Compatibility](docs/compatibility.md)
- [Contributing](CONTRIBUTING.md)

## License

To be decided before the first public release.
