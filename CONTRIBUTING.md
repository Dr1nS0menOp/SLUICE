# Contributing to Sluice

Thanks for helping. Sluice decides which security data reaches a SIEM, so correctness comes before
features. Read this before opening a pull request.

## Ground rules

- **The safety contract is non-negotiable** (see the README). Code that decides what gets forwarded
  must fail closed: when in doubt, forward in full. A change that weakens a guardrail needs a test
  that shows why it is still safe.
- **Determinism.** Core logic takes its seeds and time as inputs. Tests run offline and give the
  same result every run.
- **No third-party rule content.** Don't commit SigmaHQ or other rule sets. Write your own minimal
  example rules instead.

## License of contributions

Sluice is licensed under AGPL-3.0-only ([LICENSE](LICENSE)). By opening a pull request you agree
that your contribution is licensed under the same terms. Only add dependencies whose licenses are
in the allow-list in `deny.toml`; `cargo deny` checks this.

## Before you push

Every gate must pass:

```sh
bash scripts/check.sh
```

This runs `cargo fmt`, `cargo clippy` (pedantic, warnings are errors), the tests, `cargo doc` and
`cargo deny`.

Sluice supports only Linux ([ADR 0003](docs/adr/0003-linux-only.md)). On Windows, develop in
WSL2. You can keep the sources on the Windows filesystem and run every cargo command inside WSL:

```powershell
./scripts/wsl.ps1 bash scripts/check.sh
```

On macOS, use a Linux container or VM.

Beyond the gates, these scripts check behaviour against the real tools. CI runs all but the last:

| Script | Checks |
|--------|--------|
| `scripts/vector-check.sh` | `vector validate` and `vector test` on generated configurations (part of `check.sh` when Vector is installed) |
| `scripts/live-smoke.sh` | `sluice up` with demo traffic and the real Vector: promotion, enforcement, archive, graceful stop, then `replay-smoke.sh` |
| `scripts/sigma-differential.sh [--sigmahq]` | Rule requirements against pySigma, on the examples or the full SigmaHQ set |
| `scripts/helm-check.sh` | The Helm chart: lint, refused without a control token, its configuration through `sluice up --check` and `vector validate` |
| `scripts/bench.sh [source] [scale]` | Data plane throughput with the real Vector ([docs/notes/benchmarks.md](docs/notes/benchmarks.md)) |

Install Vector with `scripts/install-vector.sh` and the release toolchain with
`scripts/install-zig.sh`; both verify checksums and need no root.

## Structure

- `crates/sluice-core` holds the domain model and the safety logic. It is pure: no I/O.
- Adapter crates wrap third-party engines behind traits defined in core. Third-party types never
  appear in a public API.
- `crates/sluice-cli` is the only place that handles args, files and process exit codes.

Design decisions are recorded in [docs/adr/](docs/adr/). If your change makes one, add an ADR.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), for example
`feat(rules): compile superset pre-filter from Sigma selections`.
