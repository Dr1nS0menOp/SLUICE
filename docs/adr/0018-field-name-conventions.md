# ADR 0018: Field names are part of the safety contract

- Status: Accepted
- Date: 2026-10-12

## Context

A review on 2026-10-11 (PLAN.md, "Review 2026-10-11") ran `sluice analyze` on synthetic process
creations that carried the same data under two sets of field names. A Sigma rule on
`Image|endswith: \whoami.exe` and a recipe that summarizes every event gave:

- with Sysmon's names (`Image`): 3 alerts on the full data, 3 on the forwarded data, and the 3
  matching events forwarded whole;
- with Elastic's names (ECS, `process.executable`): the rule "did not apply" to the template,
  because the guardrails compared the rule's field names with the template's, found none of them
  and ruled the rule out. Nothing protected its fields, all 600 events were summarized, the 3
  matches included, and the proof read 0 = 0 and passed. A SIEM that stores ECS and converts the
  Sigma rule with a field mapping would have lost three alerts.

The proof cannot catch this. Both alert sets are empty because rsigma, too, finds no `Image` in an
ECS record. The protection has to come from the guardrails, and they must not read "this rule's
fields are absent" as "this rule reads nothing here".

## Decision

1. **A convention for field names.** `Schema` (`sluice-core`) names the convention a set of field
   names follows: `sigma`, `ecs`, `cim`, `asim`, `ocsf`, `udm`, `sentinel` (the columns of the
   Sentinel tables that are not ASIM), `splunk` (fields as Splunk extracts them, ADR 0026), or
   `undeclared`, the default. (Since 2026-10-27, ADR 0034: `cim` and `splunk` are removed.)
2. **Sources declare it.** `Source.schema` (`schema:` in the sources file and in the `sluice up`
   configuration), copied into every `Template`. A source with a `shape` follows the shape's
   convention unless it says otherwise: the Windows shapes write Sigma's names (ADR 0014), the ASIM
   shapes ASIM's, `Syslog` and `CommonSecurityLog` their own columns.
3. **Rules carry theirs.** `RuleRequirements.field_names` is `Some(Schema::Sigma)` for Sigma
   rules. Wazuh rules (decoder fields, scoped by their own machinery), Sentinel rules (the columns
   of the tables Sluice shapes) and operator rules (a field picked from the source's own records)
   set `None`: they relate their names to the data themselves.
4. **A mismatch widens, never narrows.** On a template with named fields (a JSON key set), a rule
   with a convention applies as `RuleRequirements::widened`: any field, on any event, raw text
   included, as long as its log source may apply to the template. Its pre-filter and field list
   are not consulted, since they name fields the template may carry under other names. Only a
   declared convention equal to the rule's counts as a match (`Schema::can_read`). Widened rules
   protect identically, so one stands for all, and the template gets a single
   `Reason::FieldNamesDiffer` (contract rule 3) naming the first rule and how many there are:
   with all of SigmaHQ, hundreds of rules can apply to one template. Text templates were exempt
   here; ADR 0020 closes that gap, since a SIEM parses fields out of the line that a rule then
   tests.
5. **Operators are told.** `sluice analyze` and `sluice up` print a hint for every JSON source that
   has not declared a convention while Sigma rules are loaded.

## Consequences

- Records in another convention than Sigma's get no cuts that a Sigma rule of their log source
  could object to, until Sluice maps conventions. The safe loss is savings, not detections. A
  source whose log source no loaded Sigma rule can apply to is unaffected.
- The configuration of existing deployments changes: a JSON source that was cut thanks to Sigma
  rules needs `schema: sigma`. Every example, the Helm values and the synthetic demo declare it.
  A pre-release breaking change, with a hint instead of a silent loss.
- Sigma keyword rules match values whatever the names, but are widened too. That costs a little
  saving on sources in another convention, and keeps the rule simple.
- `SecurityEvent` follows Sigma's names only for the data items that have a column; the rest live
  in its `EventData` XML. A Sigma rule on such an item finds no field there and is ruled out, as
  before. That loses no detection Sentinel runs, since the same rule converted to KQL finds no
  such column either; Sentinel's own rules, which parse `EventData`, are read by ADR 0015.
- Declaring `sigma` for records that use other names is still unsafe. It is a claim by the
  operator, and the proof cannot check it. The documentation says so where it explains `schema`.
- A mapping between conventions (pySigma's processing pipelines, applied to the rule's fields and
  to the pre-filter; the data side already keeps its names) lets `can_read` accept more pairs
  without changing the guardrails. That is the next step of M9.
- A property to keep: widening a rule never allows an additional cut. Tests named after contract
  rule 3 cover an ECS template, an undeclared template, matching and non-matching log sources,
  rules without a convention and text templates (`sluice-core` guard tests), and the end-to-end
  case above (`crates/sluice-autopilot/tests/field_names.rs`).
