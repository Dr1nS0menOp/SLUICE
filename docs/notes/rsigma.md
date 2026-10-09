# rsigma: verified notes

These notes were verified against `rsigma-parser`/`rsigma-eval` `=0.24.0` (MIT) on 2026-10-09.
The project lives at https://github.com/timescale/rsigma and targets Sigma spec v2.1.0. Its first
release was 2026-02, and it publishes 0.x releases often. Pin it exactly and keep it behind our
own trait.

## Evaluation

```rust
let coll = rsigma_parser::parse_sigma_yaml(yaml)?;   // multi-document YAML: rules + correlations
let mut engine = rsigma_eval::CorrelationEngine::new(rsigma_eval::CorrelationConfig::default());
engine.add_collection(&coll)?;
let res = engine.process_event_at(&rsigma_eval::event::JsonEvent::borrow(&json), ts_secs);
let n = res.iter().filter(|r| r.is_correlation()).count();
```

- Use `Engine` (detection only, with logsource routing) when no correlations are needed.
- `process_event_at` takes an explicit timestamp, which keeps proofs deterministic. Never use
  wall-clock time here.
- Verified: an `event_count` correlation (`gte: 3`, `group-by`, `timespan: 60s`) fires once on the
  third matching event.

## Behaviour that matters for Sluice

These were verified on 2026-10-09 against 0.24.0.

- **Keywords scan every string value** of the event (`Event::any_string_value`), not one message
  field. A keyword rule can therefore depend on any field: its requirements are
  `RequiredFields::Unknown`.
- **`generate` defaults to false.** Rules referenced by a correlation no longer alert on their
  own; only the correlation alerts. This follows the Sigma spec. The proof compares whatever the
  engine emits, so it stays correct, but don't expect base-rule alerts in tests.
- **Logsource pruning is opt-in and conflict-based** (`set_logsource_extractor`). Absent
  dimensions fail open, the same semantics as `LogSource::may_apply_to`. Sluice feeds the source's
  log source through reserved fields (`__sluice.logsource.*`) via a wrapper `Event`, so the
  engine scopes exactly like the guardrails.
- **Unparseable documents** do not fail `parse_sigma_yaml`. They land in
  `SigmaCollection::errors` and are silently absent from evaluation. Sluice turns each one into
  an opaque requirement.
- **Values:** `0x1010` unquoted in YAML is the integer 4112. Quote hex strings in rules.
- **API changes since the spike:** names are `&str` in quick-xml 0.42, which is not rsigma, but
  is noted here for the rules crate. The rsigma API itself was unchanged.

## AST (public, in `rsigma_parser::ast`)

- `SigmaCollection { rules: Vec<SigmaRule>, .. }`. Correlations and filters are separate document
  kinds (`SigmaDocument::{Rule, Correlation, Filter}`).
- `SigmaRule.detection: Detections { named: HashMap<String, Detection>, conditions:
  Vec<ConditionExpr>, condition_strings, timeframe }`.
- `Detection` is one of:
  - `AllOf(Vec<DetectionItem>)`
  - `AnyOf(Vec<Detection>)`
  - `Keywords(Vec<SigmaValue>)`
  - `ArrayMatch {..}`
  - `And(..)`
  - `Conditional {..}`
- `DetectionItem { field: FieldSpec { name: Option<String>, modifiers: Vec<Modifier> }, values }`.
- `ConditionExpr` is one of:
  - `And`
  - `Or`
  - `Not`
  - `Identifier`
  - `Selector { quantifier, pattern }` (for `1 of selection_*`, `all of them`)
- `CorrelationRule { correlation_type, rules, group_by, timespan, condition, aliases, .. }`.

All of this is enough to build the superset pre-filter and to collect the fields a rule needs,
including the fields inside `not filter` selections, which the safety contract requires us to keep.

## Licensing

rsigma is MIT. SigmaHQ rule content is DRL and must not be vendored.

## Differential test against pySigma

`scripts/sigma-differential.sh` compares the requirements Sluice derives (`sluice rules
requirements`) with pySigma 2.0.0 and fails only in the unsafe direction: a detection field
Sluice does not require, keywords not marked as raw-text matching, a correlation's base rule not
stateful or missing group-by fields, or a rule Sluice does not know at all. Alerts cannot be
compared, because pySigma converts rules to queries and does not evaluate them.

Result on 2026-10-09: the full SigmaHQ `rules/` tree (3152 rules, cloned at runtime because of
the DRL license) shows no unsafe difference; Sluice requires more fields than pySigma for 4
rules, which is the safe direction. A deliberately broken requirements file is caught.
Locally, without root: `uv venv ~/.cache/sluice-pysigma && uv pip install pysigma` and
`PYTHON=~/.cache/sluice-pysigma/bin/python`.
