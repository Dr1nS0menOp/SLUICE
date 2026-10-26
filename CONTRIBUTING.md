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

This runs `cargo fmt`, `cargo clippy` (pedantic, warnings are errors), the tests, `cargo doc`,
the check that `docs/example-report.html` is what the demo writes now, and `cargo deny`. With Vector installed and Docker running, it also runs the generated code in the
real engines (Vector, the Kusto emulator, Elasticsearch, Fluent Bit and the OpenTelemetry
Collector) and fails when one removes more than Vector does.

Sluice supports only Linux ([ADR 0003](docs/adr/0003-linux-only.md)). On Windows, develop in
WSL2. You can keep the sources on the Windows filesystem and run every cargo command inside WSL:

```powershell
./scripts/wsl.ps1 bash scripts/check.sh
```

On macOS, use a Linux container or VM.

These scripts check behaviour against the real tools. `check.sh` runs the first five when their
engine is there. CI runs all of them but `kql-check.sh`, whose emulator image is 4.5 GB, and
`bench.sh`:

| Script | Checks |
|--------|--------|
| `scripts/vector-check.sh` | `vector validate` and `vector test` on generated configurations |
| `scripts/kql-check.sh` | Generated KQL and Sentinel's analytics rules in the Kusto emulator, including a custom table end to end (`sentinel-custom-check.sh`) |
| `scripts/elastic-check.sh` | Generated ingest pipelines and Elastic's rules in Elasticsearch |
| `scripts/fluentbit-check.sh` | Generated Lua filters in Fluent Bit |
| `scripts/otel-check.sh` | Generated `transform` statements in the OpenTelemetry Collector |
| `scripts/sigma-differential.sh [--sigmahq]` | Rule requirements against pySigma, on the examples or the full SigmaHQ set |
| `scripts/bench.sh [source] [scale]` | Data plane throughput with the real Vector ([docs/notes/benchmarks.md](docs/notes/benchmarks.md)) |
| `scripts/example-report.sh` | Writes `docs/example-report.html`, the demo's report the README links to |

`scripts/real-data/` takes samples from real systems (`collect-sentinel.sh`, `collect-elastic.sh`,
`collect-linux.sh`, `collect-windows.ps1`) and repeats the real-data runs of
[docs/testing-plan.md](docs/testing-plan.md) (`run.sh`). Keep the samples outside the repository.

Install Vector with `scripts/install-vector.sh` and the release toolchain with
`scripts/install-zig.sh`; both verify checksums and need no root.

### Update the docs in the same pull request

A change is not done until the documentation describes it. Before you push, update what your
change touches: the README, [Using Sluice](docs/usage.md), the [user guide](docs/guide.md),
[architecture](docs/architecture.md), the [glossary](docs/glossary.md), `CHANGELOG.md` under
`[Unreleased]`, and the ADR or note it belongs to. Search the docs for the old wording and any
number you changed (the demo's output, a measured saving). When the report or the analysis
changes, regenerate [the example report](docs/example-report.html) with
`scripts/example-report.sh`.

## Structure

- `crates/sluice-core` holds the domain model and the safety logic. It is pure: no I/O.
- Adapter crates wrap third-party engines behind traits defined in core. Third-party types never
  appear in a public API.
- `crates/sluice-cli` is the only place that handles args, files and process exit codes.

Design decisions are recorded in [docs/adr/](docs/adr/). If your change makes one, add an ADR.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), for example
`feat(rules): compile superset pre-filter from Sigma selections`.
