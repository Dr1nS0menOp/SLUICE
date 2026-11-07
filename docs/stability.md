# What stays stable

From 1.0 on, Sluice follows [Semantic Versioning](https://semver.org/) for the parts below.
A 1.x release does not break them, and a change that would can only come in 2.0
([ADR 0038](adr/0038-what-1-0-promises.md)). This page is for people who script Sluice, read
its files with their own tools, or run it in CI.

## Stable

**The commands and their flags.** These are `sluice demo`, `analyze`, `prove`, `verify`,
`rules requirements`, `rules fetch`, `recipes`, `connect` and `mcp`, with the flags
`sluice <command> --help` lists and [usage](usage.md) describes.

- A minor release may add a command or a flag. It never changes what an existing one does in a
  way that matters to a script.
- A flag that is to go is first *deprecated*: it keeps working and prints a warning for at least
  one minor release, and goes only in the next major.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | Done. For `prove` and `verify`: the configuration or plan holds. |
| 1 | An error, or a detection would change (`prove`, `verify`). |
| 2 | The command line is wrong (the argument parser's error). |
| 3 | `verify`: the plan is out of date, since rules were added or changed after it was proven. Run `sluice analyze` again. |

**The files Sluice reads.**

- The sources file (`sources: [{ id, logsource, format, schema }]`).
- Recipe files, as `recipes/recipe.schema.json` describes them.
- The rule directories each `--*-rules` flag takes.
- The `inventory.json` that `sluice rules fetch` writes. A later 1.x reads what an earlier one
  fetched.

**`plan.json`.** Its format is `sluice.plan/1`, described by
[`plan.schema.json`](plan.schema.json), and the file says so in `format`.

- Within a format, fields may be added. A field is never renamed, never removed, and its
  meaning never changes. A reader must ignore fields it does not know, as `sluice verify` does.
- A new format, `sluice.plan/2`, comes only in a major release. A Sluice refuses a plan of a
  format it does not read, and says which Sluice wrote it.
- `plan.json` names the Sluice that wrote it (`sluice`), and every rule it was proven with, as
  a fingerprint of what Sluice read the rule as (`rules`).

**The JSON of `prove --json` and `verify --json`.** Fields may be added; none is renamed,
removed or given another meaning.

**The safety contract.** The six rules in the [README](../README.md#safety-contract) are never
weakened, in any release.

## Not stable

These change whenever Sluice gets better at its job, in any release:

- **What Sluice saves.** The recipes, the guardrails' thresholds where they keep more, the
  implied values it learns, and so the percentages. Each saving is proven before it is written.
- **The configurations it writes:** `vector.yaml`, the data collection rule, ingest pipelines,
  Lua filters and OTTL statements. Their contents change, and each is proven in its engine
  before it is written. Deploy the one Sluice wrote with the plan it came with.
- **What is meant for people:** `report.html`, `rules.json` and the wording on the terminal.
  Don't parse them; read `plan.json` or the `--json` output instead.
- **The Rust crates.** They are not published (`publish = false`), and their APIs are internal.
- **What the README calls experimental.** It may change in a minor release.

## Versions of the engines

[Compatibility](compatibility.md) lists the engine version each configuration is proven
against. A minor release may move to a newer Vector, Fluent Bit or collector, and says so in
the [CHANGELOG](../CHANGELOG.md). A plan stays readable across such a change, and
`sluice verify` proves its configuration again.

## Supported versions

Fixes go into the latest 1.x release. A vulnerability is fixed there first
([security policy](../SECURITY.md)).
