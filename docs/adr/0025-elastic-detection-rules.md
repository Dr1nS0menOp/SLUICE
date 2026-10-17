# ADR 0025: Elastic Security detection rules as requirements

- Status: Accepted
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
4. **ES|QL and Lucene are not fully parsed**: an ES|QL rule reads every name in it (`x.*` reads
   `x`; a bare `*` in `KEEP` or `DROP` may name any field), is stateful, and may match what its
   `WHERE` clauses keep (parsed as EQL conditions; `:` and `RLIKE` widen) up to the first
   command that is more than adding columns or dropping rows, leaving out conditions on columns
   it made. A Lucene rule may read anything. Machine learning rules may read anything (their
   jobs are not in the rule). A wildcard field name in KQL (`file.hash.*`) reads the fields
   below its whole segments (`file.hash`) and may match where that exists; one without
   (`proc*`) may read any field.
   A rule over Kibana's alert indices (`.alerts-security.*`) reads alerts other rules raised,
   which carry the fields of their events: what it tests about an alert bounds no source event,
   so it may match any, and keeps the fields it names everywhere.
5. **Index patterns scope a rule** (`elastic/index.rs`): where an integration's data stream says
   unambiguously what the data is (`logs-system.security*` and `winlogbeat-*` are `windows`,
   `logs-aws.*` is `aws`, `logs-endpoint.*` is `elastic_defend`, …), the rule applies to sources
   of that product only, one requirement per product. A pattern that may hold anything
   (`logs-*`, `filebeat-*`, an integration not listed) makes it apply everywhere.
6. **The proof runs the rules in Elasticsearch** (`sluice_elastic::ElasticEngine`,
   `--elasticsearch URL` for `analyze` and `up`): each evaluation loads the events into a fresh
   index and runs every EQL rule (`_eql/search`; an alert per event, a sequence's on its last
   event) and ES|QL rule (`_query` with its `FROM` replaced; an alert per row, by content), and
   every KQL and Lucene rule as the query Kibana builds from it (`_search`; `match`,
   `match_phrase`, `query_string` for wildcards, `exists`, `range`, `bool`; Lucene as a
   `query_string`), an alert per document, with the values of the fields a `threshold` or
   `new_terms` rule groups by. The
   index maps every scalar as `keyword`, and every field the rules name as ECS would (`*.ip` as
   `ip`, `keyword` with its `caseless` and `text` multi-fields), so a query is not refused for a
   field no event carries. Rules Elasticsearch refuses even so are set aside when the engine is
   built and covered by their requirements. A threshold or new-terms rule is compared per
   matching document and group, which is stricter than its count over the group: what keeps
   the documents and groups keeps the counts. With `--elastic-native`, the pipelines are proven
   with these rules too.

7. **`sluice rules fetch elastic --kibana URL [--space S]`** reads every rule of a Kibana space
   through `GET /api/detection_engine/rules/_find`, page by page, into `rules.ndjson` with an
   `inventory.json` that is complete only when the count matches Kibana's total (ADR 0021).
   Enabled machine learning rules are noted as not modelled.

## Consequences

- The fetch is tested on simulated pages only: the Security solution needs Elasticsearch with
  security and encryption keys, which the test container does not run.

- On Elastic's 2,165 prebuilt rules that run (package `security_detection_engine` 9.5.8, all
  enabled as a test): every one is read; 135 may read any field (106 machine learning jobs, 18
  ES|QL `*`, 8 wildcard field names, 3 free text), 389 may match any event (mostly ES|QL), 923
  are stateful. `crates/sluice-rules/tests/elastic_prebuilt.rs` checks this when
  `SLUICE_ELASTIC_RULES` points at the package.
- One rule that may read any field and applies everywhere blocks every saving on ECS data:
  fail closed, and listed in the report.
- Of the 2,059 prebuilt rules other than machine learning, 1,944 run in Elasticsearch 9.1.0
  for the proof (docs/notes/elasticsearch.md). The proof index approximates a real one: numbers
  are `keyword`, so a numeric comparison is on text, the same for full and reduced documents;
  a `text` field of ECS (`message`) is a `keyword` here, so a KQL value on it must be the whole
  value instead of a word of it; nested queries run on full paths.
- The rules' licence (Elastic License 2.0) keeps them out of the repository; they are read from
  the user's export or cache.
