# ADR 0001: Implement Sluice in Rust

- Status: Accepted (spike passed 2026-10-09; see "Validation")
- Date: 2026-10-09

## Context

Sluice has two halves:

- **Data plane:** Vector, which is written in Rust. Throughput comes from here.
- **Control plane:** Sluice itself. It discovers templates, decides reductions, proves them, and
  compiles Vector config. It runs on a sampling budget, so its cost grows with the number of
  templates, not the number of events.

The first plan used Python for the control plane. Two things are central to the product:

- The safety contract: a cut is enforced only after it is proven not to change any detection.
- Adoption as an open-source tool that runs on a laptop or a simple VM.

## Decision

Write the control plane in Rust, as a Cargo workspace. Keep community recipes as YAML.

## Rationale

1. **The proof runs the same code as enforcement.** Reductions compile to VRL. The `vrl` crate
   (MPL-2.0) is the compiler and runtime Vector embeds. Sluice runs that same VRL program in its
   shadow proof. In Python, every reduction needs a second reference implementation, and any
   difference between the two is a silent detection regression. That bug class matters most
   here, and Rust removes it by construction.
2. **Distribution.** Sluice ships as a single static binary, with no interpreter or virtualenv on
   the target host.
3. **One ecosystem with Vector.** VRL is parsed, type-checked and diagnosed with the official
   tooling instead of being generated as unchecked strings.
4. **Libraries exist:**
   - Sigma: `rsigma-parser` and `rsigma-eval` (MIT), including correlations.
   - DuckDB: `duckdb`.
   - MCP: `rmcp`, the official SDK.
   - HTTP: `axum`, `reqwest`.

## Consequences

- **pySigma leaves the runtime.** It stays as a test oracle: CI runs differential tests that
  compare our Sigma evaluation with pySigma on the same events.
- **rsigma is young** (first release February 2026, weekly 0.x releases). We pin exact versions and
  hide it behind our own `RuleEngine` trait, so it can be replaced without touching the core.
- **Drain is ported**, not imported. The algorithm is small and gets property tests.
- **VRL version coupling.** The `vrl` version Sluice embeds must match the one in the Vector
  release we target. Sluice checks this at startup against `vector --version` and documents a
  compatibility table.
- **Slower iteration than Python.** Clear crate boundaries and fast unit tests offset this.
- **Smaller contributor pool for the core.** Recipes, the most common contribution, stay YAML.

## Alternatives considered

- **Python:** fastest to M1 and has pySigma, but needs a duplicate reduction implementation and
  is harder to distribute.
- **Python now, Rust later:** builds the foundation twice.
- **Go:** good distribution, but it is not the VRL/Vector ecosystem, so it has the same
  dual-implementation problem as Python.

## Validation

**Result (2026-10-09, Linux/WSL2, Rust 1.99):** both checks passed on the first build. See
`docs/notes/vrl.md` and `docs/notes/rsigma.md` for the verified API. Native Windows builds are
blocked on the author's machine by Smart App Control, which affects the dev environment, not this
decision.

The spike had to do both of the following:

1. Compiled and run a VRL program on a JSON event with the `vrl` crate, on Windows/MSVC.
2. Parsed and evaluated a Sigma rule, including a correlation rule, with `rsigma`, and inspected
   its parsed detection AST, which the superset pre-filter compiler needs.
