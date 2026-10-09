# Sluice: project guide

Sluice is an open-source autopilot for security data. It shrinks SIEM ingest without changing any
detection. [PLAN.md](PLAN.md) has the product plan, and [docs/adr/](docs/adr/) has the decisions.
It is a standalone project, unrelated to the homelab repo.

The code is meant for public release, so it has to be clean enough for strangers to read, review
and contribute to.

## Language and layout

- **Linux only** ([ADR 0003](docs/adr/0003-linux-only.md)), WSL2 included. Code may assume Linux.
  Don't add Windows or macOS code paths or `cfg` fallbacks.
- Rust (edition 2024), in a Cargo workspace under `crates/`. Community recipes are YAML under
  `recipes/`.
- `rust-toolchain.toml` pins the toolchain. Everything else follows from it.
- One crate per responsibility. Dependencies point inward, toward `sluice-core`:
  - `sluice-core`: domain types and pure logic. No I/O, no async, no heavy dependencies.
  - Adapter crates (`sluice-rules`, `sluice-vector`, …) wrap third-party engines behind traits
    defined in core.
  - `sluice-cli`: the only crate that owns process concerns, such as args, files, exit codes and
    logging setup.
- Third-party types never cross a crate's public API. Map them into our own types. This keeps
  young dependencies such as `rsigma` replaceable.

## Code standards

- **Errors.**
  - Libraries use `thiserror` enums, one per crate.
  - Only `sluice-cli` uses `anyhow`.
  - No `unwrap()`/`expect()` outside tests, unless an invariant makes failure impossible; then
    `expect("why this cannot fail")`.
  - No `panic!` on input data.
- **Safety contract first.** Code that decides whether data is forwarded must fail closed: when in
  doubt, forward in full. Every guardrail gets a test named after the contract rule it enforces.
- **Determinism.** No hidden clocks or randomness in core logic. Pass in seeds and time. Use
  `BTreeMap`/sorted output wherever results are serialized or compared.
- **Types over strings.** Use newtypes for IDs (`TemplateId`, `RuleId`, `FieldPath`) and enums for
  closed sets. Make invalid states unrepresentable.
- **Public items get doc comments** that explain *why* and any invariants. Write no comments that
  restate the code.
- **`unsafe` is forbidden** (`#![forbid(unsafe_code)]` via workspace lints).
- **Small functions and modules.** Split a module that passes about 400 lines.
- **Naming** follows the Rust API Guidelines (C-CASE, C-CONV, C-GETTER).

## Quality gates (must pass before anything counts as done)

`scripts/check.sh` runs all of them: fmt, clippy `-D warnings`, tests, `cargo doc -D warnings`
and cargo-deny. CI (`.github/workflows/ci.yml`) runs the same gates.

**On the author's Windows machine, never run cargo natively.** Smart App Control blocks
freshly built binaries. Run everything in WSL:

```powershell
./scripts/wsl.ps1 bash scripts/check.sh      # all gates
./scripts/wsl.ps1 cargo test -p sluice-core  # any single cargo command
```

- The target dir lives on the Linux filesystem (`~/.cache/sluice-target`).
- PowerShell 5.1 mangles quotes passed to `wsl.exe`. Put anything with pipes, quotes or regexes
  in a `.sh` file and run it with `./scripts/wsl.ps1 bash <file>`.
- The gates use `--locked`. After adding a dependency, update the lockfile first, for example
  with `cargo metadata --format-version 1`.
- Don't pipe gate output through `tail` without `PIPESTATUS`, because the exit code is lost.

- Lints are configured once in `[workspace.lints]` (clippy `pedantic` as warn, with justified
  allows only).
- **Tests:**
  - Unit tests sit next to the code.
  - Cross-crate behaviour goes in `tests/`.
  - Property tests (`proptest`) cover anything with an "for all inputs" claim. The core one: the
    alert set over full data equals the alert set over forwarded data.
- Tests run offline and are deterministic.

## Dependencies

- Declare them in `[workspace.dependencies]` and inherit them with `dep.workspace = true`.
- Pin young or fast-moving crates to an exact version (`=x.y.z`): `rsigma-*`, `vrl`.
- The `vrl` version must match the targeted Vector release. When bumping, update the table in
  `docs/compatibility.md`.
- Before adding a crate, check its license (MIT/Apache-2.0/MPL-2.0/BSD are fine), its maintenance,
  and whether a smaller option exists.
- Keep no third-party rule content in the repo. SigmaHQ is DRL-licensed, so it is fetched at
  runtime into a user cache.

## Knowledge capture

Anything learned while building gets written down where the next contributor will find it:

- An architectural decision goes in a new ADR, `docs/adr/NNNN-title.md` (Status, Context, Decision,
  Consequences).
- A verified third-party API fact or gotcha goes in `docs/notes/<topic>.md` (for example
  `vrl.md`, `rsigma.md`), with the version it was verified against.
- A convention change goes in this file.

## Workflow

- Never commit. The user commits; end each piece of work with a ready commit message
  (Conventional Commits).
- Code, docs and commit messages are in English.
