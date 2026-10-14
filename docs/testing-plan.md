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
| sluice-sentinel, sluice-wazuh | 1,553 | 20 | 0 | medium: credentials, untrusted API data | none (`azure.rs` done 2026-10-14) |
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

## Bugs found

Each was fixed with a regression test named after what it broke.

| # | Where | What was wrong | Effect | Test |
|---|---|---|---|---|
| 1 | `sluice-core` `predicate.rs` | Case-insensitive tests compared with ASCII lower-casing, so `ÉCHEC` and `échec` counted as different | A rule an engine fires (Unicode folding) was ruled out for a template, and its fields could be removed: fail-open | `c3_non_ascii_values_are_never_ruled_out_case_insensitively` |
| 2 | `sluice-core` `logsource.rs` | The same for log source attributes | A rule could be excluded from a source it applies to: fail-open | `c3_non_ascii_attributes_are_never_told_apart_by_case` |
| 3 | `sluice-core` `predicate.rs` | `any()` did not absorb an `Always` nested in a hand-built `Any` | An unbounded rule was not recognized as one (safe, but not simplified) | `c3_always_nested_in_a_hand_built_disjunction_absorbs_it` |
| 4 | `sluice-rules` Sentinel extraction | `table("SecurityEvent")`, `union isfuzzy=true *`, `union Security*` and `find` were not read as reading tables | A query read Windows tables Sluice did not see: fail-open | `c3_tables_named_at_run_time_by_wildcard_or_by_find_may_read_every_windows_table` |
| 5 | `sluice-rules` Wazuh decoders | `program_name` with `type="osregex"` or `pcre2` was read as a literal | `^ssh.` as a regex also takes `sshX`, which the keyword bound missed: fail-open | `c3_a_program_name_that_is_a_regex_does_not_bound_its_rules` |
| 6 | `sluice-vector` `predicate.rs` | A field test compared a float value by its text (`4625.0`), while keyword tests already widened floats | A rule on `EventID: 4625` could miss a record whose value is the float `4625.0`: fail-open | `c3_a_float_value_may_match_any_number_text` |
| 7 | `sluice-core` `proof.rs` | The roll-back loop of `select_proven` had no bound: mutation testing showed a broken roll-back loops forever | A bug there would hang the control plane instead of failing the cycle | `c5_the_selection_never_needs_more_rounds_than_recipes_plus_one` |
| 8 | `sluice-vector` `predicate.rs` | The VRL compiler used three variables per test; VRL's type checker is quadratic in the number of variables (measured: 100 tests 3.5 s, 800 tests 271 s in a debug build) | Large rule sets made every cycle's compile slow; 3,000 tests did not finish in 20 minutes | `thousands_of_alternatives_compile_without_overflowing_the_stack` (now 3,000 tests, bounded at 30 s; one variable per nesting level, short-circuiting) |
| 9 | `sluice-discover` `shape.rs` | Discovery rendered a `null` discriminator as `null` and a whole float as `4624.0`; VRL's `to_string` gives `""` and `4624` | Events of such templates were never classified in the data plane: always forwarded, no saving (safe, but lost) | `discriminators_render_as_vrl_to_string_does`, `null_and_whole_floats_render_as_discovery_now_renders_them` |
| 10 | `sluice-vector` `deployed.rs` (used by `sluice prove` and the guard of what runs) | Only programs under the names Sluice expects were proven; a program under another name (left from a one-profile layout, or renamed) or an extra `sluice_` remap that changes events passed as "nothing reduced" | A configuration could run reductions no proof covered: fail-open | `c3_a_program_under_another_name_is_reported_unproven`, `c3_an_extra_remap_that_changes_events_is_reported_unproven`, `c3_a_deployed_program_sluice_cannot_place_switches_savings_off` |
| 11 | `sluice-ai` `redact.rs` | Redaction before a sample goes to a model missed IPv6 and MAC addresses, JWTs, and base64 secrets with `/`, `+` or `=` (an AWS secret key split into pieces shorter than 20) | Those values reached a cloud model unchanged: a privacy leak | `ipv6_addresses_are_replaced`, `mac_addresses_are_replaced`, `jwts_and_base64_secrets_are_replaced` |
| 12 | `sluice-mcp` `replay` | With `--allow-replay` the assistant chose the destination URL; log text it reads through `search_archive` can carry injected instructions | An attacker who can write a log line could have archived events sent to their own server: exfiltration | `replay_refuses_any_destination_it_was_not_started_with` (now `--replay-to URL`, an allowlist) |
| 13 | `sluice-vector` `config.rs`, `live.rs` | Source ids that differ only in case, `-` or `_` (`windows-security`, `windows_security`) became the same Vector component names, and the second overwrote the first; ids with `/` or `..` name archive and sample paths | One source's events went nowhere (a detection gap), or paths left their directory | `sources_whose_component_names_would_collide_are_refused` |
| 14 | `sluice-sentinel` `azure.rs` | A list followed any `nextLink` with the bearer token, to any host, and without noticing a link that repeats | A tampered or buggy response could send the ARM token elsewhere, or loop the fetch forever | `c1_a_next_link_to_another_host_never_gets_the_token`, `a_next_link_that_repeats_stops_the_list` |
| 15 | `sluice-sentinel` `inventory.rs` | An alert rule without an `enabled` flag was counted as disabled and not read | A running rule could be missing from the inventory while it claimed to be complete: fail-open | `c3_a_rule_without_an_enabled_flag_is_read` |
| 16 | `sluice-sentinel` `azure.rs` | A token endpoint or proxy that repeats the request in its error put the client secret, form-encoded, into the error message | The secret could reach a terminal or a log | `c1_the_secret_never_appears_in_a_token_error` |
| 17 | `sluice-wazuh` `inventory.rs` | A file listing without `total_affected_items` stopped after its first page, and a listing that came up short was not noticed | Rule files missing from an inventory that said it was complete: fail-open | `c3_a_listing_without_a_total_fails_instead_of_passing_as_complete`, `c3_a_listing_that_comes_up_short_fails` |
| 18 | `sluice-wazuh` `client.rs` | `logtest` never renewed its JWT (Wazuh's default lifetime is 900 s), and error messages carried whole response bodies | A proof against a large sample failed after 15 minutes (safe, but no proof); errors could repeat event text at any length | `an_expired_jwt_is_renewed_once`, `a_401_after_renewal_fails_closed`, `error_bodies_are_cut_to_an_excerpt` |
| 19 | `sluice-cli` `input.rs` | Reading a rules directory followed symbolic links without end; `.XML`/`.YAML` files were skipped; a sample with a byte order mark failed on line 1 | A link loop crashed the run (stack overflow); a rule file in upper case was silently left out: fail-open | `a_symbolic_link_loop_ends_and_each_directory_is_read_once`, `files_are_found_recursively_sorted_and_by_extension_in_any_case`, `a_byte_order_mark_and_crlf_line_ends_are_not_part_of_a_record` |
| 20 | `sluice-autopilot` `analyze.rs` | Problems reading Sentinel rules were printed by the CLI but not added to the analysis, unlike Sigma's and Wazuh's | The report, the server's status and MCP showed no problem for a Sentinel rule file that could not be read | `sentinel_rule_problems_are_listed_in_the_analysis` |
| 21 | `sluice-kql` `syntax.rs` | A field or column name with a newline, tab or other control character was put into `['…']` unescaped | A JSON key from a log line could make the generated KQL fail to parse (the KQL is advisory, so no data was lost, but the check broke) | `names_escape_what_a_literal_escapes_and_refuse_the_rest`, `a_field_or_column_name_kql_cannot_quote_widens_to_true` |
| 22 | `sluice-server` `oidc` | Sign-in by `email` did not look at `email_verified` | With a provider where users choose their own address, someone could register an operator's address and sign in as them | `c1_an_address_the_provider_has_not_verified_names_nobody` |
| 23 | `sluice-sentinel` `inventory.rs` | A run of equal file names searched every written path for each suffix (found by mutation testing as a timeout) | Thousands of equal names made the fetch quadratic | `many_colliding_names_each_get_their_own_file` |

Mutation testing (`cargo-mutants` 27.1.0, MIT) on `sluice-core`, 2026-10-14: 246 mutants, 214
caught, 30 unviable, 0 timeouts, 2 missed. Both are closed:
- `attribute_may_match` with one side alone non-ASCII now has a test (the Kelvin sign `K`).
- The `op != Exists` guard in `merge_alternatives` was redundant and is gone: merging two
  `exists` tests on one field changes nothing.

A first run, with a shared target directory, reported 0 missed: its results were noise (see
below).

Running it:
- `unset CARGO_TARGET_DIR` first. `scripts/wsl.ps1` points every build at
  `~/.cache/sluice-target`, and with `--jobs` above 1 the mutants then overwrite each other's test
  binaries.
- `ulimit -v 6000000` caps each process. A mutant can make a test allocate without end; one
  `sluice-rules` mutant reached 12.6 GB, and the OOM killer took WSL down with it
  (`wsl --shutdown` recovers).
- Then `cargo mutants -p CRATE --jobs 2 --timeout 180 --output DIR`. Each job builds in its own
  copy.
- Watch the disk. Each job's copy holds a full debug build, and WSL's `ext4.vhdx` grows with it
  but never shrinks on its own. On 2026-10-14 it reached 153 GB and filled C:. Run one crate at a
  time, and delete the copies and `~/.cache/sluice-target` when done. To give the space back to
  Windows, run `sudo fstrim -av` in WSL, then `wsl --shutdown` and `compact vdisk` in `diskpart`
  as Administrator. WSL's sparse mode is disabled by Microsoft over data corruption; don't force
  it.

Known limits found, not fixed: a workspace function whose name is all lower case looks like a
KQL built-in to the Sentinel extractor, so a rule calling it is not widened unless the function
was fetched with `sluice rules fetch sentinel` (which resolves it).

## Done when

Every crate meets its target, every public function has at least one test that fails when it
is broken, mutation score on `sluice-core` ≥ 90 %, every bug found has its regression test, the
gates are green, and the real-data runs (Windows, Linux, Sentinel) reproduce their numbers.
