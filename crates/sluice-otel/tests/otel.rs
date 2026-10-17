//! Differential test against the real OTTL engine (the OpenTelemetry Collector, ADR 0028): on
//! the synthetic sample, every predicate's condition holds wherever its VRL matches.
//!
//! Runs only with `SLUICE_OTEL_COLLECTOR` set to a command that runs the collector
//! (`scripts/otel-check.sh` sets it), like the Kusto and Elasticsearch gates.

#![allow(
    clippy::print_stderr,
    reason = "the test reports when it is skipped and how precise the OTTL was"
)]

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};
use sluice_core::source::SourceFormat;
use sluice_otel::Collector;
use sluice_synth::{SynthConfig, generate};
use sluice_vector::PredicateProgram;

const ENV: &str = "SLUICE_OTEL_COLLECTOR";

#[test]
fn ottl_matches_whatever_vrl_matches() {
    let Ok(command) = std::env::var(ENV) else {
        eprintln!("skipped: set {ENV} (scripts/otel-check.sh)");
        return;
    };
    let events = sample();
    let predicates = predicates(&events);
    assert!(predicates.len() > 100, "{} predicates", predicates.len());
    let rows = run(&Collector::new(command), &events, &predicates);

    let mut vrl_true = 0usize;
    let mut ottl_only = 0usize;
    for (n, predicate) in predicates.iter().enumerate() {
        let program = PredicateProgram::compile(predicate).expect("VRL compiles");
        for (event, row) in events.iter().zip(&rows) {
            let vrl = program.matches(event).expect("VRL runs");
            let ottl = row.contains(&n);
            assert!(
                !vrl || ottl,
                "VRL matches but OTTL does not\npredicate {predicate:?}\nottl {}\nevent {}",
                sluice_otel::compile(predicate, sluice_otel::ROOT),
                Value::Object(event.clone())
            );
            vrl_true += usize::from(vrl);
            ottl_only += usize::from(ottl && !vrl);
        }
    }
    eprintln!(
        "{} predicates x {} events: VRL true {vrl_true}, OTTL true where VRL false {ottl_only}",
        predicates.len(),
        events.len()
    );
    assert!(vrl_true > 200, "too few positive cases to mean anything");
}

/// JSON events of every source, spread over the sample.
fn sample() -> Vec<Map<String, Value>> {
    let sample = generate(&SynthConfig {
        scale_percent: 1,
        ..SynthConfig::default()
    });
    let json_sources: BTreeSet<_> = sample
        .sources
        .iter()
        .filter(|s| s.format == SourceFormat::Json)
        .map(|s| s.id.clone())
        .collect();
    let json_events: Vec<_> = sample
        .events
        .iter()
        .filter(|e| json_sources.contains(&e.source))
        .collect();
    let stride = (json_events.len() / 60).max(1);
    json_events
        .iter()
        .step_by(stride)
        .map(|e| e.fields.clone())
        .collect()
}

/// Field tests built from real values (every operator, both cases, upper-cased and partial
/// values, nested paths), keyword tests, and the example Sigma rules' pre-filters.
fn predicates(events: &[Map<String, Value>]) -> Vec<Predicate> {
    let mut out = Vec::new();
    for (i, event) in events.iter().enumerate().step_by(3) {
        for (j, (key, value)) in leaves(event).iter().enumerate() {
            if (i + j) % 4 != 0 {
                continue;
            }
            let text = match value {
                Value::String(s) if !s.is_empty() => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => continue,
            };
            let chars: Vec<char> = text.chars().collect();
            let half = chars.len().div_ceil(2);
            let head: String = chars[..half].iter().collect();
            let tail: String = chars[chars.len() - half..].iter().collect();
            for case_sensitive in [false, true] {
                for (op, value) in [
                    (MatchOp::Equals, text.clone()),
                    (MatchOp::Equals, text.to_uppercase()),
                    (MatchOp::Contains, head.to_lowercase()),
                    (MatchOp::StartsWith, head.clone()),
                    (MatchOp::EndsWith, tail.to_uppercase()),
                ] {
                    out.push(Predicate::Field(FieldTest {
                        field: key.as_str().into(),
                        op,
                        values: vec![value, "no-such-value".into()],
                        case_sensitive,
                    }));
                }
            }
            out.push(Predicate::Keywords(KeywordTest {
                values: vec![head.to_uppercase()],
                case_sensitive: false,
            }));
            // `exists` on the path, on its parent, and on a path below it that is not there.
            let parent = key.rsplit_once('.').map(|(p, _)| p.to_owned());
            for path in [Some(key.clone()), parent, Some(format!("{key}.missing"))]
                .into_iter()
                .flatten()
            {
                out.push(Predicate::Field(FieldTest {
                    field: path.as_str().into(),
                    op: MatchOp::Exists,
                    values: Vec::new(),
                    case_sensitive: false,
                }));
            }
        }
    }
    let sigma = sluice_rules::SigmaRules::parse([include_str!(
        "../../../examples/rules/sigma/windows.yml"
    )])
    .expect("example rules parse");
    out.extend(sigma.requirements().iter().map(|r| r.prefilter.clone()));
    out
}

/// Every leaf of `event` with its dotted path.
fn leaves(event: &Map<String, Value>) -> Vec<(String, Value)> {
    fn walk(prefix: &str, value: &Value, out: &mut Vec<(String, Value)>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    walk(&format!("{prefix}.{k}"), v, out);
                }
            }
            other => out.push((prefix.to_owned(), other.clone())),
        }
    }
    let mut out = Vec::new();
    for (k, v) in event {
        walk(k, v, &mut out);
    }
    out
}

/// Evaluates `predicates` on every record in the collector: per record, the numbers of the
/// predicates that hold. The results go into the cache and reach the body last, so the
/// conditions see the record only.
fn run(
    collector: &Collector,
    events: &[Map<String, Value>],
    predicates: &[Predicate],
) -> Vec<BTreeSet<usize>> {
    let mut statements: Vec<String> = predicates
        .iter()
        .enumerate()
        .map(|(n, predicate)| {
            format!(
                "set(log.cache[\"{n}\"], true) where {}",
                sluice_otel::compile(predicate, sluice_otel::ROOT)
            )
        })
        .collect();
    statements.push("set(log.body[\"sluice_m\"], log.cache)".to_owned());
    let records: Vec<&Map<String, Value>> = events.iter().collect();
    collector
        .run(Some(&statements), &records)
        .unwrap_or_else(|e| panic!("{e}"))
        .iter()
        .map(|r| {
            r.get("sluice_m")
                .and_then(Value::as_object)
                .map(|m| m.keys().filter_map(|k| k.parse().ok()).collect())
                .unwrap_or_default()
        })
        .collect()
}
