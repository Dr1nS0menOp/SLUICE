# Test plan: the bug hunt after M11

The phase PLAN.md calls "Hard cutoff after M11": no new features; after the maintainer's code
review, every function gets small unit tests written to break it. This plan says what to test
first, how, what "done" means, and where the gaps are today (counted 2026-10-14).

## Principles

- **Unit tests first.** One focused test module per function where it helps, next to the code
  (`mod tests` or `<module>/tests.rs`). Each test checks one thing and is named after what it
  proves (`a_rule_for_another_event_id_protects_nothing_here`); safety tests start with the
  contract rule (`c3_…`).
- **Aim to break, not to confirm.** For every function: the empty input, one element, the
  boundary on both sides, huge input, hostile strings (quotes, braces, `\`, `$`, newlines,
  non-ASCII, emoji), every branch, every error variant.
- **Property tests** (`proptest`) wherever a claim holds "for all inputs".
- **Mutation testing** (`cargo-mutants`, after checking its license and maintenance) on
  `sluice-core` first: a mutant that survives is a missing test.
- **Every bug found** gets a regression test named after what it broke, then the fix.
- Integration and differential tests (Vector, Kusto emulator, live smoke) stay as they are; this
  phase adds below them, it does not replace them.

## Where we stand

| Crate | Lines | Unit tests | Integration tests | Risk | Modules without tests of their own |
|---|---:|---:|---:|---|---|
| sluice-core | 3,732 | 66 | 0 | **highest**: every safety decision | `guard/protection.rs`, `guard/model.rs`, `rules.rs`, `template.rs`, `ids.rs` |
| sluice-rules | 4,015 | 53 | 13 | **high**: a wrong extraction is a fail-open | `sentinel/extract.rs` (594 lines), `wazuh/decoders.rs`, `wazuh/chains.rs`, `wazuh/xml.rs`, `sigma/fields.rs`, `sigma/engine.rs` (partly covered by the module test files) |
| sluice-vector | 4,962 | 56 | 15 | **high**: generated code runs on every event | `program.rs`, `runtime.rs`, `config.rs`, `deployed.rs` (covered from `tests/config.rs`), `windows/columns.rs` |
| sluice-discover | 1,435 | 21 | 16 | medium: templates decide what rarity sees | `lib.rs`, `shape.rs` |
| sluice-autopilot | 2,472 | 27 | 20 | medium | `analyze.rs`, `live.rs`, `spot.rs`, `report/` |
| sluice-server | 4,579 | 27 | 0 | medium; **high** for auth | `running.rs`, `control.rs`, `routes.rs`, `config.rs`, `status.rs` (most covered only through `tests.rs`) |
| sluice-kql | 1,724 | 10 | 2 | medium | `schema.rs` (data) |
| sluice-sentinel, sluice-wazuh | 1,553 | 20 | 0 | medium: credentials, untrusted API data | `sentinel/azure.rs` |
| sluice-archive, sluice-mcp, sluice-ai | 2,699 | 24 | 6 | medium | `scan.rs`, `layout.rs`, `advisor.rs`, `prompt.rs` |
| sluice-cli | 2,249 | 6 | 14 | low: thin wiring | most modules; covered end to end |
| sluice-synth | 1,887 | 4 | 8 | low: test data | the generators |

Most risk sits where the fewest unit tests are per line: `sluice-rules` (Sentinel extraction,
Wazuh decoders and chains), `sluice-core`'s protection logic, and `sluice-vector`'s program
generation.

## Order

1. **sluice-core**: guard, protection, predicate, proof, field paths. Target: every public
   function tested, line coverage ≥ 95 %, mutation score ≥ 90 %.
2. **sluice-rules**: the three extractors. Target: ≥ 90 % lines, every construct of each
   language seen in the real rule sets (SigmaHQ, Azure-Sentinel, the Wazuh ruleset) has a test.
3. **sluice-vector**: program, predicate compilation, deployed, summary. Target: ≥ 90 %.
4. **sluice-discover**, **sluice-autopilot**, **sluice-server** (`running`, routes and auth
   first), **sluice-kql**, then the API clients. Target: ≥ 85 %.
5. **sluice-cli**, **sluice-archive**, **sluice-mcp**, **sluice-ai**, **sluice-synth**.
   Target: ≥ 70 %, the rest stays covered end to end.

Coverage is measured with `cargo llvm-cov` (to be added to the gates once the targets hold);
the numbers are a floor, not the goal. The goal is that a wrong change fails a test.

## What to test, with example cases

### sluice-core (unit + property + mutation)

| Function | Cases |
|---|---|
| `GuardrailConfig::is_rare_count` | 99 and 100 events; share exactly 1,000 ppm and one below; `source_events` 0; `u64::MAX` (no overflow) |
| `Predicate::any` / `all` | empty `any` matches nothing, empty `all` everything; `Always` absorbs `any`; nested flattening; one child returns the child |
| `Predicate::may_match_with` | fixed `EventID` equal / different / absent; case-sensitive vs not; field not in the template's paths; keywords always may match |
| `Predicate::names_fields`, `tests` | keywords only, nested `Any(All(Field))`, `Always` |
| `FieldPath::covers` | `a` covers `a.b` but not `ab`; equal paths; empty path |
| `guard` | `renamed` matrix (key set × schema × rule convention; text × field tests × keywords); `applies` with `text_lines_only`; exactly 256 and 257 data-plane tests; archive off before rare (order of `refuse_all`); `dedup` keeps order; `rules_complete` off refuses L2 and L3 but keeps L1 |
| `Protection::allowed_drops` | parent and child of a protected field; `drop_empty` exceptions; unknown fields |
| `select_proven` | an engine error proves nothing; rollback converges; extra alerts also fail |
| `inventory::is_safe_relative_path`, `file_name` | done; add Windows drive letters and `%2e%2e` |

Property tests to add: for every predicate and event, the compiled superset never matches less
(`may_match_with` true whenever the predicate matches); `guard` never drops a field a known
applicable rule lists; `is_rare_count` is monotonic in events.

### sluice-rules (unit)

| Area | Cases |
|---|---|
| Sigma pre-filter | every modifier (`contains`, `startswith`, `endswith`, `re`, `cidr`, `windash`, `base64offset`, `all`); `1 of`, `all of them`, `not`, parentheses; correlations whose base rule is missing |
| Sentinel extract | first `where` per table reference; `in~`, string EventIDs, `let` lists; `union`, `search`, `pack_all()`; unknown function widens; a lambda parameter named like a table; comments and multi-line strings |
| Wazuh | `if_sid` cycles and missing parents; `overwrite="yes"`; `<list>` without field; decoders whose program name is a regex; a file that is not XML |

### sluice-vector (unit + differential)

`syntax::string` and `syntax::path` with hostile names; every `MatchOp` compiled and compiled
without VRL warnings; `source_program` ordering (key sets before text, fewest wildcards first);
`reduction` with and without `keep_whole_when`; `deployed` (done for wiring; add: profile tags,
a source with a program but no route, an empty configuration); `summary::key_value` for every
lineage branch.

### sluice-discover, sluice-autopilot, sluice-server (unit, then integration)

Mask: message tags, IPs, hex, UUIDs, numbers inside words. Categorical split at 6 and 7 values.
Lifecycle: every transition edge, including held, paused and approved. Report: the empty proof
note, the rules verdict for every mix of statuses, HTML escaping of every field. Server
`running`: startup with a proven, an unproven and a missing configuration; a deployed
configuration equal to the safe one; an unreadable file; two profiles where one has no program.
Routes: every route without a token, with a wrong one, with a valid one; OIDC with an expired,
a wrongly signed and a replayed token.

### API clients (unit, against fakes)

Azure and Wazuh: error bodies, empty pages, `nextLink` loops, unsafe names (done for Wazuh),
secrets never in errors or `Debug` output (done for Azure credentials), timeouts.

## Gaps this plan closes first

1. `guard/protection.rs` has no tests of its own: the conditional protection that most savings
   depend on is only tested through `guard`.
2. `sentinel/extract.rs`, the largest extractor, relies on 19 module tests and real-rule runs;
   every construct needs its own case.
3. `program.rs` and `runtime.rs` are tested only through generated configurations.
4. `running.rs` (new) has two integration tests; its edge cases are untested.
5. No mutation testing and no coverage measurement yet.

## Done when

Every crate meets its target, every public function has at least one test that fails when it
is broken, mutation score on `sluice-core` ≥ 90 %, every bug found has its regression test, the
gates are green, and the real-data runs (Windows, Linux, Sentinel) reproduce their numbers.
