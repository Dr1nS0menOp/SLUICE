# ADR 0023: The savings plan as the product

- Status: Accepted
- Date: 2026-10-16

## Context

Until now the only thing that carried out a saving was `vector.yaml`. A Sentinel user without
Vector got a report to read and nothing to run, and every new target (a DCR transformation, an
Elastic ingest pipeline, a Splunk ingest action) would have had to re-derive what is allowed
from the autopilot's internals. PLAN.md M12 (decided 2026-10-14) makes the output tool-neutral:
one plan, many generators.

## Decision

1. **`plan.json` (`sluice.plan/1`)** is written by `sluice analyze` and `sluice demo` next to
   `vector.yaml` and `report.html`. It is `sluice_autopilot::SavingsPlan`, built from the proven
   selection, and holds:
   - `proof`: whether it holds, the alerts on full and forwarded data, the empty-proof note,
     rules per set, and on what grounds the rules count as complete (ADR 0021).
   - `total`: the sample's volume, in and as forwarded.
   - `sources`, each with its log source, field naming convention and kinds of event (largest
     first). Per kind of event: how to recognise it (`shape`, the exact template shape a
     classifier is compiled from), its volume, `remove_fields`, `remove_empty_fields_except`,
     `keep_whole_when` (events a rule could match keep every field, contract rule 3),
     `count_instead` (`forward_when` and the summary `keys`), why proposals were narrowed or
     refused, and where the proposal came from.
2. **`runs_in` says where each saving can run.** Removing fields from a key-set template can
   run in a pipeline tool, in the SIEM's own ingestion or in the collection agent (`pipeline`,
   `siem_ingest`, `agent`; the agent since ADR 0027 and ADR 0028). Counting needs state across
   events, and a text template is recognised by a regex over its line, which only a pipeline
   tool does, so those are `pipeline` only. A kind of event sent unchanged has none.
3. **The plan is a view of the proof, not a second decision.** It is built from the same
   selection `vector.yaml` is compiled from, so what a generator reads is exactly what was
   proven. A generator that cannot express part of a template's plan must leave that template
   unchanged (contract rule 1); it may never do more than the plan allows.
4. **Generators read the plan.** Vector is the first (`vector.yaml`, proven by `vector test`);
   the Sentinel DCR transformation (ADR 0013) is the next. Each is labelled proven (checked
   against the real engine) or advisory.

## Consequences

- New targets need no access to the autopilot: they read `plan.json`.
- The format is versioned; a change in meaning bumps `sluice.plan/N`.
- `report.html` still renders from the report; turning it into a rendering of the plan is left
  for later, so both stay in step through the shared selection.
- `sluice up` in proposal mode writes `plan-<profile>.json` per rule profile next to
  `proposal.json` (which names it under `plan`), built from what the proposal deploys
  (`SavingsPlan::deployed`: the enforced recipes and their proof), before `vector.yaml` is
  replaced (2026-10-17).
