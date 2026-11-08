# ADR 0041: Three modes: duplicates, implied, counts

- Status: Accepted
- Date: 2026-11-08

## Context

1.0 had two modes (ADR 0032): `rules`, the recipes' savings, and `implied`. But `rules` held
two very different savings. Removing a field that repeats the event (a rendered `Message`, the
original line next to its parsed fields) or an empty one keeps every event and every value.
Counting events no rule could match sends counts in their place, so individual events, with
their users and addresses, reach the SIEM no more and stay in the archive only. Both are proven.
But many teams want the first without the second: an analyst who looks up an IP address in the
SIEM should find every event with it. There was no way to ask for that.

## Decision

1. **Three modes.** `duplicates` is the recipes' field removals (`drop_fields`,
   `drop_empty_fields`). `implied` is the implied values, as before. `counts` is the recipes'
   routing (`forward_matching`, `summarize`). A recipe that does both is split, and keeps only
   what the modes asked for allow.
2. **`rules` stays** and means `duplicates,counts`, so 1.0's command lines keep their meaning
   (ADR 0038). All three run by default, as both did.
3. **`duplicates,implied` is called lossless.** Every event reaches the SIEM, and every value it
   had is there or comes back exactly from the plan. The README puts the choice first.
4. **The report and the plan split the saving three ways.** A removed field is credited to
   `implied` or `duplicates`; counting gets what the rest of the saving comes to.
   `saved_by_mode` in `plan.json` is keyed by the mode's name, and also holds `rules`, the sum
   of `duplicates` and `counts`, whenever both ran, as 1.0 wrote it.

## Consequences

- `--mode duplicates` saved 33.1 % on OTRF's APT29 sample, `duplicates,implied` 60.9 %, all
  three 78.1 %, each with the same 987 alerts.
- The plan's schema now allows any mode name as a key of `saved_by_mode`; 1.0's keys are still
  written for 1.0's modes.
- An AI advisor's recipes are split the same way. Whatever a recipe removes, the guardrails
  keep what a rule reads, and a recipe of your own decides what counts as a duplicate.
