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

## Before you push

Every gate must pass:

```sh
./scripts/check.sh
```

This runs `cargo fmt`, `cargo clippy` (pedantic, warnings are errors), the tests, `cargo doc` and
`cargo deny`.

On Windows with Smart App Control enabled, native builds are blocked. Run the gates inside WSL:

```powershell
./scripts/wsl.ps1 bash scripts/check.sh
```

## Structure

- `crates/sluice-core` holds the domain model and the safety logic. It is pure: no I/O.
- Adapter crates wrap third-party engines behind traits defined in core. Third-party types never
  appear in a public API.
- `crates/sluice-cli` is the only place that handles args, files and process exit codes.

Design decisions are recorded in [docs/adr/](docs/adr/). If your change makes one, add an ADR.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), for example
`feat(rules): compile superset pre-filter from Sigma selections`.
