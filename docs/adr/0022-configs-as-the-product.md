# ADR 0022: Configurations as the product: proposals, `sluice prove` and a CI action

- Status: Accepted
- Date: 2026-10-14

## Context

Sluice's output is a Vector configuration plus the proof that it changes no detection (ADR 0017:
Sluice does not run a fleet; Vector and the operator's tooling do). Until now that output was
either applied by `sluice up` itself or written once by `sluice analyze`. Teams that manage
configuration in Git want a change to arrive as a reviewable diff, and want CI to refuse a diff
that would change a detection, whoever wrote it: Sluice, a colleague, or an AI assistant.

A proof is only worth something if it is about the file that will run. Re-running the analysis
in CI would prove what Sluice would generate now, not the configuration in the pull request.

## Decision

1. **Proposals, by default.** `sluice up` writes each newly proven configuration to
   `proposals_dir` (default `<data_dir>/proposals`) as `vector.yaml` with `proposal.json` (per
   rule profile: the proof of exactly what the configuration saves, whether that proof is
   empty, what the rules' completeness rests on, bytes in and out, the templates), instead of
   applying it. Both files are replaced atomically, the configuration last. The operator
   deploys a proposal by writing it over `vector_config`, by hand or from Git. `auto_apply:
   true` restores the old behaviour, Sluice applying its own proposals, for demos and labs;
   it excludes `proposals_dir`. (Decided with the maintainer on 2026-10-14: Sluice writes
   configurations and recommendations; people decide what runs.)
2. **What runs is proven every cycle, and switched off when it fails.** In proposal mode each
   cycle reads the deployed configuration back, as `sluice prove` does (3), and proves it on the window, per
   rule profile. One that proves is loaded into Vector (so deploying means writing the file;
   Sluice reloads Vector after proving it). One that fails, or that cannot be read, is replaced
   at once by the safe configuration, which sends every event unchanged, and the status and
   console say so (`switched_off`). That is the only change Sluice makes without review, and it
   only ever sends the SIEM more data. On a restart, Sluice keeps the deployed configuration
   only if it is exactly the one it last proved; otherwise it starts with the safe one.
3. **`sluice prove` proves the file as it is.** It reads each source's program back out of the
   configuration (`sluice_vector::deployed`), compiles it with the `vrl` crate, runs the sample
   through it, and compares the rules' alerts (Sigma, and Sentinel rules in the Kusto emulator)
   on the full and the forwarded sample. Exit status 1 when they differ, and also when the sample
   raises no alert at all (an empty proof shows nothing; `--allow-no-alerts` accepts it);
   `--json` for CI.
4. **Only Sluice's wiring is provable.** The proof models the program and its route; anything
   around them that could drop events would make it describe something else. So `prove`
   refuses a configuration where a program does not reroute what it fails on, the route does
   not split exactly on `%sluice.route`, an output that must reach the destinations goes
   nowhere, or a transform is not one Sluice generates (`sluice_…` of type `remap`, `route`,
   `reduce` or `sample`, and no remap that can `abort`). Sources and sinks are the operator's
   and are reviewed like any configuration change.
5. **A GitHub Action** (`action.yml`) installs the release binary matching the action's tag,
   checks its SHA-256 sum, runs `sluice prove`, writes the result to the job summary and fails
   the job when the proof fails.
6. **The load test measures the configuration, not Sluice.** `scripts/load-test.sh CONFIG
   SAMPLES SOURCES [RULES]` runs each source's sample through the configuration's own
   transforms on a stock Vector into blackhole sinks and prints events per second next to what
   `sluice prove` says about the same files.

## Consequences

- A pull request that edits a program, a route or a recipe by hand is proven like one Sluice
  wrote; one that adds a filter in front of a program is refused instead of passing with a
  proof that no longer describes it. The `abort` check is lexical, so a program that merely
  mentions the word (in a template's text, say) is refused too: fail closed.
- Switching off is coarse: when the deployed configuration fails, every saving stops, not only
  the failing one, because Sluice does not edit a reviewed file. The next proposal leaves the
  failing recipe out. With `auto_apply`, ADR 0005's per-recipe rollback applies instead.
- A deployment reaches Vector only after a cycle has proven it (up to `cycle_secs`); a Vector
  that restarts on its own in between loads the file unproven, for at most one cycle.
- An operator who runs the proposal on their own Vector fleet, not the one `sluice up` starts,
  gets the proof in CI (`sluice prove`) but not the switch-off: Sluice cannot reach that fleet.
- The Action can only be exercised once a release with binaries exists; its proving step was
  run locally with the same environment variables GitHub sets. The load test's path for
  live configurations (records already JSON, shaped) is written but was measured on
  `sluice analyze` configurations only.
- Tests named after contract rules 3 and 5: refused edits (`sluice-vector` config tests); a
  proposal that leaves the running configuration untouched, and a deployed proposal that is
  proven, then switched off the moment a broken one is deployed (`sluice-server`); `prove`
  passing the generated configuration, failing one that loses alerts, and failing an empty
  proof (`sluice-cli`).
