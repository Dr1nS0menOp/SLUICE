# ADR 0025: Elastic Security detection rules as requirements

- Status: Accepted (requirements done; running the rules in Elasticsearch for the proof open)
- Date: 2026-10-17

## Context

PLAN.md M12 (decided 2026-10-14): requirements extractors, and where an engine can run offline
proofs, for each SIEM's own rule language, Elastic first. Elastic Security runs detection rules
in KQL, EQL, ES|QL, Lucene and machine learning jobs, of types `query`, `eql`, `esql`,
`threshold`, `new_terms`, `threat_match` and `machine_learning`. With an Elastic destination,
those rules decide what may be removed, not Sigma's (ADR 0024 proved its pipelines with Sigma
only).

## Decision

1. **Input: the rules as Kibana holds them** (`sluice_rules::ElasticRules`, `--elastic-rules
   DIR` for `analyze`, `up` and `rules requirements`): the NDJSON of `_export`, the JSON of
   `_find`, or the saved objects of Elastic's prebuilt rules package. No TOML parser is needed,
   and the rules are those the SIEM has. Only rules that run count (ADR 0021): the highest
   `version` of each `rule_id`, no `deprecated` rule, and no rule with `enabled: false`. The
   disabled ones are counted in one problem: enabling one later needs a new analysis, as adding
   a rule does.
2. **Fields are ECS** (`field_names: ecs`), so on sources in another convention the rules are
   read as widely as can be (ADR 0018). That is right for Elastic: its integration pipelines
   rename raw fields to ECS on ingestion, so the sample must be documents as Elastic stores
   them, as for the ingest pipelines (ADR 0024).
3. **KQL and EQL are parsed** (`elastic/kql.rs`, `elastic/eql.rs`) for every field they name
   and a superset pre-filter. A KQL value becomes tests that its alphanumeric tokens are
   contained, case-insensitively (a phrase or pattern needs all, an unquoted value any word):
   what a `text` field's analyzed match or a `keyword` field's exact match keeps, assuming the
   standard analyzer. EQL's `==`, `:`, `in`, `like` and `startsWith`/`endsWith`/
   `stringContains` become equalities or containment. Negation, ranges, nested queries,
   regexes, other functions and non-ASCII values widen to `true`; free text and wildcard field
   names read every field. Sequences, samples, pipes, `threshold` and `new_terms` are stateful.
4. **ES|QL and Lucene are not parsed**: an ES|QL rule reads every name in it (`x.*` reads
   `x`), may match any event, and is stateful; a Lucene rule may read anything. Machine
   learning rules may read anything (their jobs are not in the rule).
5. **Index patterns scope a rule** (`elastic/index.rs`): where an integration's data stream says
   unambiguously what the data is (`logs-system.security*` and `winlogbeat-*` are `windows`,
   `logs-aws.*` is `aws`, `logs-endpoint.*` is `elastic_defend`, …), the rule applies to sources
   of that product only, one requirement per product. A pattern that may hold anything
   (`logs-*`, `filebeat-*`, an integration not listed) makes it apply everywhere.

## Consequences

- On Elastic's 2,165 prebuilt rules that run (package `security_detection_engine` 9.5.8, all
  enabled as a test): every one is read; 135 may read any field (106 machine learning jobs, 18
  ES|QL `*`, 8 wildcard field names, 3 free text), 389 may match any event (mostly ES|QL), 923
  are stateful. `crates/sluice-rules/tests/elastic_prebuilt.rs` checks this when
  `SLUICE_ELASTIC_RULES` points at the package.
- One rule that may read any field and applies everywhere blocks every saving on ECS data:
  fail closed, and listed in the report.
- The proof does not run the rules yet; their requirements constrain every cut. Running them in
  Elasticsearch (EQL and ES|QL natively; KQL needs Kibana's translation) is the next step.
- The rules' licence (Elastic License 2.0) keeps them out of the repository; they are read from
  the user's export or cache.
