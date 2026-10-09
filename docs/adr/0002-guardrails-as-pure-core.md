# ADR 0002: The safety contract as a pure function in core

- Status: Accepted
- Date: 2026-10-09

## Context

Every reduction Sluice enforces must satisfy the safety contract (README). Proposals come from
three places: community recipes, operators and AI models. Rule knowledge comes from several
engines (Sigma, Wazuh, later SPL/KQL). The safety logic has to be easy to audit and test
exhaustively, and no proposal source may be able to bypass it.

## Decision

1. **Proposals and enforcement are different types.** A `Recipe` is a validated proposal, and
   only `Recipe::new` builds one, so it is not `Deserialize`. An `EffectiveRecipe` is what may be
   enforced, and the only function that produces one with reductions is `guard::guard`.
2. **Guardrails are a pure function** of the template, the recipe, the rule requirements and the
   config. There is no I/O, clock or randomness, so every contract rule has plain unit tests,
   named `cN_…` after the contract rule they enforce.
3. **Engines meet core through `RuleRequirements`.** These are engine-neutral facts: scope,
   referenced fields, raw-text matching, statefulness and a superset pre-filter. Adapters must
   over-approximate. "Unknown" is explicit in the types (`RequiredFields::Unknown`,
   `Predicate::Always`, `RuleRequirements::opaque`), so an empty set can never be mistaken for
   "needs nothing".
4. **Every refusal is explained.** Each refused or narrowed proposal yields an `Adjustment` that
   names the contract rule and a typed `Reason`. Reports, `explain` and the MCP server build on
   these.
5. **Core builds pre-filters but never evaluates them.** `Predicate` is an AST that compiles to
   VRL. Matching semantics exist only in VRL (see ADR 0001).
6. **Provenance is never trust.** An AI-authored recipe goes through exactly the same checks as
   any other.

## Consequences

- Adding a rule engine means writing an adapter that emits `RuleRequirements`. The guardrails
  don't change.
- Fail-closed defaults cost savings when an adapter is unsure. That trade-off is intended and
  shows up in the report as adjustments.
- Contract rule 5 (proof before enforcement) is enforced by the shadow proof, not by `guard`.
  `guard` produces candidates; the proof promotes them.
