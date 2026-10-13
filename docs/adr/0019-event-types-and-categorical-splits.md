# ADR 0019: Templates follow the kind of event

- Status: Accepted
- Date: 2026-10-12

## Context

Templates are the unit the rarity floor counts (contract rule 4: rare is never cut), recipes
target and the guardrails reason about. The review of 2026-10-11 (PLAN.md) found that they
follow an event's shape rather than its meaning:

- **Text.** Drain routes on the program name and joins lines at 40 % equal tokens. sshd's
  `Accepted password for …` and `Failed password for …` became one template,
  `sshd <*> password for <*> from …`. Three failed logons among 597 accepted ones were not rare,
  and a summarizing recipe took them with the rest. Masking turned Cisco message ids such as
  `%ASA-6-302013:` into `%ASA-<NUM>-<NUM>:`, so different events of a firewall looked identical.
- **JSON.** The fields that name the kind of event were fixed to `EventID`, `event.code`,
  `event.action` and `action`. CloudTrail (`eventName`), Okta (`eventType`) and others name it
  elsewhere, so all their kinds of event shared templates whenever their keys matched.

## Decision

1. **Categorical positions split Drain clusters.** Lines are grouped per cluster and per masked
   token sequence until the clusters are final. A wildcard position whose values number at most
   `categorical_max_values` (default 6) in the cluster, or that holds only message ids, is a word
   such as `Accepted` or `Failed` rather than a parameter. Each of its values gets a template of
   its own: the cluster's tokens with that value in place of `<*>`. Other wildcards stay. The
   rarity floor then counts each variant.
2. **Message ids keep their digits.** A Cisco-style tag, `%FACILITY-SEVERITY-MNEMONIC:`, is not
   masked.
3. **Event-type fields per source.** `event_type: [...]` on a source adds fields to the ones
   discovery uses everywhere, and well-known products get defaults: `aws` (`eventSource`,
   `eventName`), `okta` (`eventType`), `m365` (`Workload`, `Operation`), `azure` (`category`,
   `operationName`), `gcp` (`protoPayload.serviceName`, `protoPayload.methodName`) and
   `kubernetes` (`verb`, `objectRef.resource`). A field an event lacks does not count.

4. **One template per kind of JSON event, rare shapes apart.** When an event has event-type
   values, its frequent key sets share one template, whose id depends on the source and those
   values only. The template lists each accepted key set (`TemplateShape::Keyset::variants`) and
   their union (`paths`), which the guardrails use as before. The classifier accepts exactly
   those key sets, so a shape discovery never saw passes through (contract rule 1). A key set
   below the guardrails' rarity floor keeps a template of its own, so a rare shape of a frequent
   kind of event is never cut (contract rule 4). Events without event-type values keep one
   template per exact key set: there, the shape is the only sign of the kind.

Raising Drain's similarity threshold or routing on more tokens was considered and not done:
both split every cluster, also at parameters such as the sudo user (docs/notes/drain.md), while
the categorical split only separates what alternates among a few values.

## Consequences

- A rare variant of a frequent line is rare to the guardrails. On the review's case, the three
  failed logons got a template of their own and were forwarded; the 597 accepted ones were
  summarized as before. The demo kept 75.0 % (it was 75.3 %) with 41 = 41 alerts.
- A value the window never saw at a categorical position matches no template in the data plane,
  so such lines pass through unchanged until the next cycle (contract rule 1). Before, the
  wildcard matched them.
- A parameter with few values in a small deployment, such as three user names, also splits.
  Frequent variants stay frequent and are cut as before; only the rare ones are forwarded. The
  synthetic sample's Linux auth source has 28 templates at 10 % scale.
- Template ids of split clusters change once. Enforced recipes on them go through shadow again.
- More event-type fields only ever split templates further, which is the safe direction. They
  also let the guardrails scope rules by those values, as they do for `EventID`: a CloudTrail
  rule on `eventName: CreateAccessKey` no longer applies to a `GetUser` template.
- An agent update that adds a field to every event no longer resets its source's templates. The
  new shape passes through for one cycle, then joins its kind's template, whose id and stage are
  unchanged; the cycle's proof covers it before it is cut.
- Whether a key set is rare depends on the window, so a shape near the floor can move between
  its own template (never cut) and its kind's (proven with it). Both are safe.
- A guardrail that reads `paths` sees every field of every variant, which can only bring more
  rules into scope.
