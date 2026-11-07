# ADR 0038: What 1.0 promises

- Status: Accepted
- Date: 2026-11-08

## Context

Up to 0.2.0 the README said that the commands, `plan.json` and the report may still change: an
alpha. People who script Sluice, read `plan.json` with their own tools (the plan is meant to be
carried out by any tool, ADR 0023) or run `sluice prove` in CI cannot build on that. A 1.0
release has to say what holds across 1.x, and the code has to keep it.

Sluice's output is of two kinds. Some is for tools: `plan.json`, the `--json` output of `prove`
and `verify`, the exit codes. Some is for people: the report, the terminal's wording, the
configurations, which are proven before they are written and change whenever Sluice saves
better. Promising the second kind would freeze the very thing that should improve.

## Decision

1. **What is stable** is listed in [docs/stability.md](../stability.md): the commands and flags,
   the exit codes, the files Sluice reads, `plan.json`'s format and the JSON of `prove --json` and
   `verify --json`. A 1.x release does not break them. A flag is deprecated, with a warning, for
   at least one minor release before it goes in a major.
2. **What is not** is listed there too: what Sluice saves, the configurations it writes, the
   report and the terminal's wording, the crates' APIs, and whatever the README calls
   experimental.
3. **`plan.json` is described by a JSON Schema** (`docs/plan.schema.json`), generated from the
   types that write the plan (schemars), as the recipe schema is. A test fails when the
   committed schema is stale, and another validates the demo's plan against it. Fields that are
   left out when empty are optional in the schema.
4. **A format, not a version, decides compatibility.** `format` stays `sluice.plan/1`. Within it,
   fields are only added; a reader ignores fields it does not know. A new format comes only
   in a major release, and a reader refuses a format it does not read. The plan also names the
   Sluice that wrote it (`sluice`), so that refusal can say which one to use.
5. **Exit codes are part of the interface.** 0 is done or holds; 1 is an error or a detection
   that would change; 2 is a wrong command line (clap); 3 is a plan that is out of date
   (`sluice verify`, ADR 0039).
6. **The safety contract is never weakened.** This is not a matter of versions.

## Consequences

- Tools can read `plan.json` against a schema and rely on it for 1.x.
- A change to a stable part is a review question: does it only add? If not, it waits for 2.0.
- The report, the configurations and the savings keep improving in minor releases.
- Experimental parts stay free to change, so the README's list of them is now a promise too: what
  it does not name is stable.
