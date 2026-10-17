//! Differential test against the real Lua engine (Fluent Bit, ADR 0027): on the synthetic
//! sample, every predicate's Lua matches whatever its VRL matches.
//!
//! Runs only with `SLUICE_FLUENT_BIT` set to a command that runs Fluent Bit
//! (`scripts/fluentbit-check.sh` sets it), like the Kusto and Elasticsearch gates.

#![allow(
    clippy::print_stderr,
    reason = "the test reports when it is skipped and how precise the Lua was"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::{Map, Value};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};
use sluice_core::source::SourceFormat;
use sluice_fluentbit::FluentBit;
use sluice_synth::{SynthConfig, generate};
use sluice_vector::PredicateProgram;

const ENV: &str = "SLUICE_FLUENT_BIT";

#[test]
fn lua_matches_whatever_vrl_matches() {
    let Ok(command) = std::env::var(ENV) else {
        eprintln!("skipped: set {ENV} (scripts/fluentbit-check.sh)");
        return;
    };
    let events = sample();
    let predicates = predicates(&events);
    assert!(predicates.len() > 100, "{} predicates", predicates.len());
    let rows = run(&FluentBit::new(command), &events, &predicates);

    let mut vrl_true = 0usize;
    let mut lua_only = 0usize;
    for (n, predicate) in predicates.iter().enumerate() {
        let program = PredicateProgram::compile(predicate).expect("VRL compiles");
        for (event, row) in events.iter().zip(&rows) {
            let vrl = program.matches(event).expect("VRL runs");
            let lua = row.as_bytes()[n] == b'1';
            assert!(
                !vrl || lua,
                "VRL matches but Lua does not\npredicate {predicate:?}\nlua {}\nevent {}",
                sluice_fluentbit::compile(predicate),
                Value::Object(event.clone())
            );
            vrl_true += usize::from(vrl);
            lua_only += usize::from(lua && !vrl);
        }
    }
    eprintln!(
        "{} predicates x {} events: VRL true {vrl_true}, Lua true where VRL false {lua_only}",
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

/// Evaluates `predicates` on every record in Fluent Bit; one string of `0` and `1` per record.
/// The results are stored after every test ran, so the tests see the record only.
fn run(
    fluent_bit: &FluentBit,
    events: &[Map<String, Value>],
    predicates: &[Predicate],
) -> Vec<String> {
    let mut script = sluice_fluentbit::functions().to_owned();
    script.push_str("local P = {}\n");
    for (n, predicate) in predicates.iter().enumerate() {
        let test = sluice_fluentbit::compile(predicate);
        writeln!(script, "P[{}] = function(r) return {test} end", n + 1)
            .expect("writes to a string");
    }
    script.push_str(
        "function sluice(tag, ts, r)\n  local m = {}\n  for i = 1, #P do m[i] = P[i](r) and \"1\" or \
         \"0\" end\n  r[\"sluice_m\"] = table.concat(m)\n  return 2, ts, r\nend\n",
    );
    let records: Vec<&Map<String, Value>> = events.iter().collect();
    fluent_bit
        .run(Some(&script), &records)
        .unwrap_or_else(|e| panic!("{e}"))
        .iter()
        .map(|r| r["sluice_m"].as_str().expect("results").to_owned())
        .collect()
}
