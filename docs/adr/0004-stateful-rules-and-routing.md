# ADR 0004: Stateful rules don't block rule-guided routing

- Status: Accepted (supersedes the "protects the whole type" rule in PLAN.md)
- Date: 2026-10-09

## Context

The first plan said that any correlation or frequency rule "protects the whole type": while such a
rule applied, no event of that log type could be summarized.

In practice, one Sigma correlation on failed logons blocked rule-guided reduction for every
Windows Security event, including the highest-volume type (WFP 5156). The correlation can never
count those events.

## Decision

A stateful rule doesn't force `ForwardAll`. It is treated like any other rule: its pre-filter
joins the union that the route forwards in full.

## Why this is safe

- A correlation or frequency rule counts or relates only the events its own conditions match:
  - Sigma correlations count their base rules' matches.
  - Wazuh frequency rules count events that matched a parent (`if_matched_sid`).
  - Deprecated Sigma aggregations count selection matches.
- Every such event is inside the rule's superset pre-filter.
- Rule-guided routing forwards every pre-filter match **unchanged, completely and in order**, so
  the rule sees exactly the event stream it would have seen.
- Wazuh child rules without their own conditions have an unbounded pre-filter, and an unbounded
  rule still forces `ForwardAll`.
- The shadow proof (contract rule 5) evaluates the actual correlations on the forwarded data. If
  this reasoning were wrong for some rule, the recipe would be rolled back.

## Consequences

- `RuleRequirements::stateful` stays. It constrains future operations that remove, merge or
  reorder *matching* events, such as de-duplication, which isn't built yet.
- `Reason::StatefulRule` is removed until such an operation exists.
- On the demo data, L2 becomes possible for Windows Security types the failed-logon correlation
  can't count.
