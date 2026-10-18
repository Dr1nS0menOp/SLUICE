//! Differential test against the real KQL engine (the Kusto emulator, docs/notes/sentinel-dcr.md):
//! on the synthetic sample, every predicate's KQL matches whatever its VRL matches.
//!
//! Runs only with `SLUICE_KUSTO_URL` set (`scripts/kql-check.sh` starts the emulator and sets
//! it), like the Vector gate: the emulator image is 4.5 GB.

#![allow(
    clippy::print_stderr,
    reason = "the test reports when it is skipped and how precise the KQL was"
)]

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};
use sluice_core::source::SourceFormat;
use sluice_synth::{SynthConfig, generate};
use sluice_vector::PredicateProgram;

const ENV: &str = "SLUICE_KUSTO_URL";

/// Predicates per emulator query.
const BATCH: usize = 25;

#[test]
fn kql_matches_whatever_vrl_matches() {
    let Ok(url) = std::env::var(ENV) else {
        eprintln!("skipped: set {ENV} (scripts/kql-check.sh)");
        return;
    };
    let events = sample();
    let columns: BTreeSet<String> = events.iter().flat_map(|e| e.keys().cloned()).collect();
    let column_names: Vec<&str> = columns.iter().map(String::as_str).collect();
    let predicates = predicates(&events);
    assert!(predicates.len() > 100, "{} predicates", predicates.len());

    let mut vrl_true = 0usize;
    let mut kql_only = 0usize;
    for batch in predicates.chunks(BATCH) {
        let kql: Vec<String> = batch
            .iter()
            .map(|p| sluice_kql::compile(p, &column_names))
            .collect();
        let rows = run(&url, &events, &columns, &kql);
        for (n, predicate) in batch.iter().enumerate() {
            let program = PredicateProgram::compile(predicate).expect("VRL compiles");
            for (event, row) in events.iter().zip(&rows) {
                let vrl = program.matches(event).expect("VRL runs");
                let kql = row[n].as_bool().unwrap_or_else(|| panic!("bool: {row:?}"));
                assert!(
                    !vrl || kql,
                    "VRL matches but KQL does not\npredicate {predicate:?}\nkql {}\nevent {}",
                    kql_text(batch, n, &column_names),
                    Value::Object(event.clone())
                );
                vrl_true += usize::from(vrl);
                kql_only += usize::from(kql && !vrl);
            }
        }
    }
    eprintln!(
        "{} predicates x {} events: VRL true {vrl_true}, KQL true where VRL false {kql_only}",
        predicates.len(),
        events.len()
    );
    assert!(vrl_true > 200, "too few positive cases to mean anything");
}

fn kql_text(batch: &[Predicate], n: usize, columns: &[&str]) -> String {
    sluice_kql::compile(&batch[n], columns)
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
/// values), keyword tests, and the example Sigma rules' pre-filters.
fn predicates(events: &[Map<String, Value>]) -> Vec<Predicate> {
    let mut out = Vec::new();
    for (i, event) in events.iter().enumerate().step_by(3) {
        for (j, (key, value)) in event.iter().enumerate() {
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
        }
    }
    let sigma = sluice_rules::SigmaRules::parse([include_str!(
        "../../../examples/rules/sigma/windows.yml"
    )])
    .expect("example rules parse");
    out.extend(sigma.requirements().iter().map(|r| r.prefilter.clone()));
    out
}

/// Evaluates `expressions` on every event in the column model; one row of booleans per event.
fn run(
    url: &str,
    events: &[Map<String, Value>],
    columns: &BTreeSet<String>,
    expressions: &[String],
) -> Vec<Vec<Value>> {
    let rows: Vec<String> = events
        .iter()
        .enumerate()
        .map(|(n, e)| {
            // A verbatim string has no escapes; JSON already escapes control characters.
            let json = Value::Object(e.clone()).to_string().replace('"', "\"\"");
            format!("{n}, @\"{json}\"")
        })
        .collect();
    let extend: Vec<String> = columns
        .iter()
        .map(|c| {
            let name = format!("['{}']", c.replace('\\', "\\\\").replace('\'', "\\'"));
            format!("{name} = ev{name}")
        })
        .collect();
    let project: Vec<String> = expressions
        .iter()
        .enumerate()
        .map(|(n, e)| format!("m{n} = {e}"))
        .collect();
    let query = format!(
        "datatable(n:long, raw:string)[{}]\n| extend ev = parse_json(raw)\n| extend {}\n\
         | order by n asc\n| project {}",
        rows.join(", "),
        extend.join(", "),
        project.join(", ")
    );
    let body = json!({ "db": "NetDefaultDB", "csl": query }).to_string();
    let answer = sluice_http::Client::new(std::time::Duration::from_secs(300))
        .send(
            "POST",
            &format!("{url}/v1/rest/query"),
            &[("content-type", "application/json".to_owned())],
            Some(&body),
        )
        .unwrap_or_else(|e| panic!("emulator unreachable: {e}"));
    let status = answer.status;
    let response = answer.body;
    if !(200..300).contains(&status) {
        let path = std::env::temp_dir().join("sluice-kql-failed-query.kql");
        let _ = std::fs::write(&path, &query);
        eprintln!("failed query written to {}", path.display());
    }
    assert!(
        (200..300).contains(&status),
        "emulator query failed ({status}): {}\nquery head: {}",
        &response[..response.len().min(1500)],
        &query[..query.len().min(300)]
    );
    let parsed: Value = serde_json::from_str(&response).expect("JSON response");
    parsed["Tables"][0]["Rows"]
        .as_array()
        .unwrap_or_else(|| panic!("no rows: {response}"))
        .iter()
        .map(|r| r.as_array().expect("row").clone())
        .collect()
}
