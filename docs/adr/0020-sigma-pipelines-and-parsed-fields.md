# ADR 0020: Sigma processing pipelines, summary-key lineage and fields parsed from text

- Status: Accepted
- Date: 2026-10-13

## Context

ADR 0018 made a mismatch of field-name conventions fail closed: a Sigma rule on an ECS template
is widened, so nothing it could read is cut. That is safe, but an ECS source with SigmaHQ loaded
then saves almost nothing. The SIEM itself does not have this problem: it converts each Sigma rule
with a pySigma *processing pipeline* that renames the rule's fields to the store's. Sluice should
read the rule the way the SIEM runs it.

The review of 2026-10-11 (PLAN.md) found two more gaps of the same family:

- **Summary keys lost on the way.** A `SecurityEvent` 5156 template summarized by `Application`
  and `DestAddress` produced one record of 600 events with both keys `null`: those data items live
  in the `EventData` column (an object, or an XML string), not at the top level.
- **Fields parsed out of text lines.** A Sigma rule that tests named fields, such as a webserver
  rule on `cs-uri-query`, applied to raw nginx lines. The SIEM parses the field out of the line
  before the rule runs; Sluice sees only the line. The rule's pre-filter could never match it, so
  every line went to summaries, and the proof (rsigma, on the same unparsed line) read 0 = 0 and
  passed. Fail-open, invisible to the proof. ADR 0018 had exempted text templates on the grounds
  that they have no names to compare; that was the hole.

## Decision

1. **Pipelines map rules, not data.** `--sigma-pipeline SCHEMA=PIPELINE` (on `analyze` and `up`)
   loads a pySigma processing pipeline for one convention: a YAML file, or a name built into
   `rsigma_eval` (`ecs_windows`, `sysmon`, `fibratus_windows`). `SigmaRules::parse_with` applies it
   to a copy of every rule and correlation (`SigmaPipeline`, `sluice-rules`). The copy keeps the
   rule's id and gets `field_names: Some(schema)`; at most one pipeline per convention.
2. **Refused pipelines.** A pipeline for `sigma` or `undeclared` is refused, as is one that
   depends on the source (`${source.*}` placeholders): Sluice applies it once, not per source.
3. **One rule, the right copy.** The Sigma engine routes each event to the collection of its
   source's convention, so the proof evaluates exactly the copy the SIEM would run. The guardrails
   skip a widened rule when a copy with the same id can read the template's convention; the copy's
   own pre-filter and fields then scope it like any matching rule (contract rule 3 unchanged).
4. **Summary keys follow lineage.** A summary key is read from the field itself, else from
   `EventData.<key>` when the template carries that object, else from the `EventData` XML string
   with a regular expression on `<Data Name="key">` (`sluice-vector`, `summary.rs`). A key found
   nowhere stays `null`, as before.
5. **Parsed fields keep text lines whole.** On a text template, a rule with a convention whose
   pre-filter names a field is widened, mapped copy or not: its fields exist only after the SIEM's
   parser. The template gets one `Reason::FieldsParsedFromText` (contract rule 3) naming the first
   rule and how many distinct rules there are. Keyword-only rules search the line itself and are
   compared as they are. Rules without a convention (Wazuh, Sentinel, operator) are unaffected:
   their requirements already say what their own decoder reads.

## Consequences

- An ECS source with `--sigma-pipeline ecs=ecs_windows` is cut where no mapped rule can match,
  and the proof shows the mapped rules' alerts kept (`crates/sluice-autopilot/tests/field_names.rs`).
  Without a pipeline the behaviour of ADR 0018 holds.
- The pipeline is the operator's claim that it is the one the SIEM uses. A different pipeline in
  the SIEM is the same risk as a wrong `schema:`; the documentation says so.
- Every pipeline adds a full copy of the rule set to memory and one engine to the proof. With one
  or two conventions that is cheap; it grows linearly with the conventions in use.
- Text sources with Sigma field rules lose savings until Sluice knows the SIEM's parser. A parser
  that Sluice could replay (M9's parser packs, or an AI-proposed parser with a round-trip check)
  would let such rules be compared again; until then the safe loss is savings.
- `SecurityEvent` summaries now carry their keys: in the real Vector 0.59, the 5156 experiment
  gave two records of 300 with the right `Application`, instead of one of 600 with `null`.
- Tests named after contract rule 3: mapped copies used instead of widened, parsed fields on text
  lines, keyword rules on text lines, rules without a convention (`sluice-core` guard tests);
  lineage of summary keys in the real VRL compiler (`sluice-vector` summary tests); pipelines
  parsed, refused and applied (`sluice-rules`).
