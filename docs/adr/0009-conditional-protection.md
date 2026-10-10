# ADR 0009: Conditional protection, per-template scoping and complete log sources

- Status: Accepted
- Date: 2026-10-10

## Context

Run against real Windows events of the author's machine (System, Application and PowerShell
Operational, 22,448 events) with the full SigmaHQ rule set (3,152 rules), Sluice saved nothing
although the proof held. Three causes, all from the guardrails being coarser than the contract
requires:

1. **Scoping by log source only.** A rule with `category: database` applied to Windows System
   data, because an undeclared category on data means "unknown" (fail closed). One keyword rule
   for databases then protected every field of every Windows source without a category.
2. **Scoping ignored the template.** A rule that needs `EventID: 5805` protected every field of
   an `EventID=7036` template.
3. **A keyword rule protected its fields on every event.** SigmaHQ's "Mimikatz Use" searches every
   value of every Windows event, so `Message` could never be dropped anywhere.

Contract rule 3 says *anything a rule could match is forwarded in full*. It does not say fields a
rule could read are kept on events the rule cannot match.

## Decision

1. **Complete log sources.** A source may declare `complete: true` on its log source: the
   attributes it gives are all there are, so a rule naming a missing one does not apply. Off by
   default, because an incomplete descriptor would hide rules (Sysmon is `process_creation` and
   more without saying so). The Sigma engine scopes identically (an absent attribute is reported
   as a value no rule names).
2. **Per-template scoping.** A rule applies to a template only if its pre-filter is not ruled out
   by the template's fixed discriminator values (`Predicate::may_match_with`). Only equality on a
   fixed field is decided; keywords, regexes and other fields never rule anything out.
3. **Conditional protection.** A field claimed by a rule whose pre-filter is bounded and does not
   cover the whole template is dropped only from events outside that pre-filter
   (`EffectiveRecipe::keep_whole_when`); events the rule could match are forwarded whole. This is
   sound because pre-filters widen `not`, `null` and `exists: false` to "every event": their
   remaining tests only get harder to pass when fields are removed, so a rule cannot fire on a
   reduced event whose original its pre-filter rejects.
4. **Tighter pre-filters.** `|all` becomes a conjunction (it was the looser disjunction), a
   keyword list under `'|all'` requires every keyword, and inner wildcards (`a*b`) bound a test
   by their literal pieces (starts with the first, ends with the last, contains the longest;
   for keywords, the longest piece of at least three characters) instead of widening to
   "every event". One such rule used to block every reduction on all Linux data.
5. **A cost limit.** A combined pre-filter of more than 256 tests falls back to the fail-closed
   choice (keep the fields, or forward everything) with reason `ProtectionTooBroad`.

## Consequences

- On the same real data: 30.8 MB → 23.5 MB (23.8 %) with 206 = 206 alerts, in 5.6 s for all
  SigmaHQ rules; Vector 0.59 runs the generated configuration and agrees with the `vrl` crate on
  every generated test, including both sides of each conditional protection.
- On real Linux logs of the author's Wazuh server (auth.log and syslog, 177,008 lines, ISO
  timestamps): 35.0 MB → 25.0 MB (28.6 %), 76,638 cron session lines summarized, accepted by
  `vector validate` and `vector test`. No SigmaHQ rule fires on that sample, so the proof there
  shows only that nothing new fires.
- Operators get savings on sources they describe precisely; undescribed attributes stay
  conservative.
- The data plane evaluates protecting pre-filters per event. Merging tests that differ only in
  their values, and compiling large value lists to one regex alternation, keeps that cheap; the
  cost limit bounds the rest.
- Generated unit tests cover summarized, forwarded-reduced and forwarded-whole events per
  template.
- `crates/sluice-autopilot/tests/conditional.rs` checks the soundness claim without the proof's
  rollback: for random events and rules built on the hard cases (keywords, `|all`, inner
  wildcards, `null`, `not`), the data plane the guardrails alone allow raises exactly the alerts
  of the full data.
