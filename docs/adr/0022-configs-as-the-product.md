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

1. **Proposals.** `proposals_dir` in the `sluice up` configuration makes the control plane write
   each newly proven configuration to `DIR/vector.yaml`, with `DIR/proposal.json` (per rule
   profile: the proof of exactly what the configuration enforces, bytes in and out, the
   enforced templates), instead of applying it. The running Vector keeps the configuration
   with nothing enforced, so nothing is cut before a reviewer merges and deploys the proposal
   with their own tooling. Both files are replaced atomically, the configuration last.
2. **`sluice prove` proves the file as it is.** It reads each source's program back out of the
   configuration (`sluice_vector::deployed`), compiles it with the `vrl` crate, runs the sample
   through it, and compares the rules' alerts (Sigma, and Sentinel rules in the Kusto emulator)
   on the full and the forwarded sample. Exit status 1 when they differ; `--json` for CI.
3. **Only Sluice's wiring is provable.** The proof models the program and its route; anything
   around them that could drop events would make it describe something else. So `prove`
   refuses a configuration where a program does not reroute what it fails on, the route does
   not split exactly on `%sluice.route`, an output that must reach the destinations goes
   nowhere, or a transform is not one Sluice generates (`sluice_…` of type `remap`, `route`,
   `reduce` or `sample`, and no remap that can `abort`). Sources and sinks are the operator's
   and are reviewed like any configuration change.
4. **A GitHub Action** (`action.yml`) installs the release binary matching the action's tag,
   checks its SHA-256 sum, runs `sluice prove`, writes the result to the job summary and fails
   the job when the proof fails.
5. **The load test measures the configuration, not Sluice.** `scripts/load-test.sh CONFIG
   SAMPLES SOURCES [RULES]` runs each source's sample through the configuration's own
   transforms on a stock Vector into blackhole sinks and prints events per second next to what
   `sluice prove` says about the same files.

## Consequences

- A pull request that edits a program, a route or a recipe by hand is proven like one Sluice
  wrote; one that adds a filter in front of a program is refused instead of passing with a
  proof that no longer describes it. The `abort` check is lexical, so a program that merely
  mentions the word (in a template's text, say) is refused too: fail closed.
- In proposal mode, rollbacks are proposals as well: a recipe that fails its proof leaves the
  next proposal without it. The live safety net of ADR 0005 (automatic rollback) applies only
  where Sluice applies the configuration itself.
- The Action can only be exercised once a release with binaries exists; its proving step was
  run locally with the same environment variables GitHub sets. The load test's path for
  live configurations (records already JSON, shaped) is written but was measured on
  `sluice analyze` configurations only.
- Tests named after contract rules 3 and 5: refused edits (`sluice-vector` config tests), a
  proposal that leaves the running configuration untouched (`sluice-server`), and `prove`
  passing the generated configuration and failing one that loses alerts (`sluice-cli`).
