# ADR 0033: An object the removals emptied is not sent, and its saving goes to its fields

- Status: Proposed (branch `study/field-value`)
- Date: 2026-10-26

## Context

The generators remove fields by path. When they remove every field of a nested object, the object
stayed behind as `{}`. In ECS-shaped data (Beats, the Elastic agent) that is common: on the demo's
Windows logoff (4634), 34 of the 262 bytes sent were `"agent":{},"ecs":{},"host":{"os":{}}`. An
empty object carries nothing, but a SIEM still stores and bills it.

Two things make it less simple than deleting every `{}`:

- An event may *arrive* with an empty object. A rule can test that a field exists, so such an
  object must be sent as it came. VRL's `flatten`, which recognition uses, drops empty objects,
  so recognition cannot tell the two apart.
- The proof credits savings to the paths it sees removed (ADR 0032, modes). A removed object seen
  as one path is neither a recipe's field nor an implied value, and its bytes went to the wrong
  mode.

## Decision

1. **Every generator that removes nested fields removes an object it emptied.** The objects above
   a plan's removable fields, not covered by a removed path, are `Plan::emptiable_objects` in
   `sluice-core`, the deepest first. Vector, the ingest pipeline and the Lua filter note before
   their removals whether each held a field, and remove it after them only if it did and holds
   none now. The collector needs no note: its recognition is exact map by map, so a record with an
   extra empty object is never taken. Sentinel's transformation removes whole columns only and
   does not change.
2. **No rule can tell.** The guardrails protect a field together with everything above and below
   it (`covers` both ways), so an object a rule reads keeps its fields and never empties.
3. **The proof follows a removed object into its fields.** Each field counts as its own path, and
   the object once more as its shell (`"name":{` and `}`), so the bytes add up to what the object
   took. The report gathers the fields of an object a recipe removes whole under that object, and
   credits a shell to implied values when only implied values emptied it, otherwise to the rules.
4. **Proven as before.** The differential tests fail if a real Fluent Bit or collector leaves a
   `{}` where Vector does not, and the ingest pipeline is compared with Vector's output exactly,
   including an object that came empty.

## Consequences

- The demo saves 79.6 % instead of 79.2 %, with 41 = 41 alerts; `implied` alone saves 34.9 %, as
  the total and as its mode. Flat samples (real Windows, Sentinel, OTRF) are unchanged.
- An event's shape changes beyond the fields a recipe or an implied value names: a parent object
  can be missing. The put-back steps read a missing parent as a missing field, as before, and
  rebuild what they rebuilt.
- A generator for a new engine must do the same, or it keeps `{}`: that is safe (it keeps more
  than Vector), but its saving is then a little lower than the report says.
