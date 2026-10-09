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
