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
- Still open in M9 step 2: JSON key sets split every combination of optional fields into its own
  template, and the classifier matches the exact key set, so an agent update that adds a field
  resets every template of its source. Grouping those variants under their event type is the
  next part.
