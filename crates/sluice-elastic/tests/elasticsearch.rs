//! Differential test against the real Painless engine (Elasticsearch, ADR 0024): on the
//! synthetic sample, every predicate's Painless matches whatever its VRL matches.
//!
//! Runs only with `SLUICE_ELASTIC_URL` set (`scripts/elastic-check.sh` starts Elasticsearch and
//! sets it), like the Kusto gate.

#![allow(
    clippy::print_stderr,
    reason = "the test reports when it is skipped and how precise the Painless was"
)]

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};
use sluice_core::source::SourceFormat;
use sluice_synth::{SynthConfig, generate};
use sluice_vector::PredicateProgram;

const ENV: &str = "SLUICE_ELASTIC_URL";

/// Most script text per simulation, well below what Elasticsearch compiles.
const SCRIPT_BUDGET: usize = 40_000;

#[test]
fn painless_matches_whatever_vrl_matches() {
    let Ok(url) = std::env::var(ENV) else {
        eprintln!("skipped: set {ENV} (scripts/elastic-check.sh)");
        return;
    };
    let events = sample();
    let predicates = predicates(&events);
    assert!(predicates.len() > 100, "{} predicates", predicates.len());

    let mut vrl_true = 0usize;
    let mut painless_only = 0usize;
    for batch in batches(&predicates) {
        let rows = run(&url, &events, batch);
        for (n, predicate) in batch.iter().enumerate() {
            let program = PredicateProgram::compile(predicate).expect("VRL compiles");
            for (event, row) in events.iter().zip(&rows) {
                let vrl = program.matches(event).expect("VRL runs");
                let painless = row[n].as_bool().unwrap_or_else(|| panic!("bool: {row:?}"));
                assert!(
                    !vrl || painless,
                    "VRL matches but Painless does not\npredicate {predicate:?}\npainless {}\n\
                     event {}",
                    sluice_elastic::compile(predicate),
                    Value::Object(event.clone())
                );
                vrl_true += usize::from(vrl);
                painless_only += usize::from(painless && !vrl);
            }
        }
    }
    eprintln!(
        "{} predicates x {} events: VRL true {vrl_true}, Painless true where VRL false \
         {painless_only}",
        predicates.len(),
        events.len()
    );
    assert!(vrl_true > 200, "too few positive cases to mean anything");
}

/// Predicates grouped so each group's script stays within [`SCRIPT_BUDGET`]; a predicate above
/// it alone would be too large for one script and is skipped (the generator refuses those).
fn batches(predicates: &[Predicate]) -> Vec<&[Predicate]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut size = 0;
    for (n, predicate) in predicates.iter().enumerate() {
        let len = sluice_elastic::compile(predicate).len();
        if size + len > SCRIPT_BUDGET && n > start {
            out.push(&predicates[start..n]);
            start = n;
            size = 0;
        }
        size += len;
    }
    if start < predicates.len() {
        out.push(&predicates[start..]);
    }
    out.retain(|b| {
        b.len() > 1 || sluice_elastic::compile(&b[0]).len() <= sluice_elastic::MAX_SCRIPT / 2
    });
    out
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

/// Evaluates `predicates` on every document in Elasticsearch; one row of booleans per document.
fn run(url: &str, events: &[Map<String, Value>], predicates: &[Predicate]) -> Vec<Vec<Value>> {
    let tests: Vec<String> = predicates.iter().map(sluice_elastic::compile).collect();
    // The result goes into a list built before it is stored, so the tests see the document only.
    let script = format!(
        "{}List m = [{}];\nctx.sluice_m = m;\n",
        functions(),
        tests.join(",\n")
    );
    let pipeline = json!({"processors": [{"script": {"source": script}}]});
    let documents: Vec<&Map<String, Value>> = events.iter().collect();
    let out = sluice_elastic::simulate(url, &pipeline, &documents)
        .unwrap_or_else(|e| panic!("{e}\n{}", &script[script.len().min(2000)..]));
    out.iter()
        .map(|d| d["sluice_m"].as_array().expect("results").clone())
        .collect()
}

/// The helper functions, as the generated pipeline carries them.
fn functions() -> String {
    let template = sluice_core::template::Template {
        id: "t".into(),
        source: "s".into(),
        logsource: sluice_core::logsource::LogSource::default(),
        schema: sluice_core::schema::Schema::default(),
        pattern: String::new(),
        shape: sluice_core::template::TemplateShape::Keyset {
            discriminators: Vec::new(),
            paths: ["a".into()].into(),
            variants: vec![["a".into()].into()],
        },
        fields: ["a".into()].into(),
        text_fields: BTreeSet::new(),
        stats: sluice_core::template::TemplateStats::default(),
    };
    let recipe = sluice_core::guard::EffectiveRecipe {
        drop_fields: ["a".into()].into(),
        ..sluice_core::guard::EffectiveRecipe::passthrough("t".into())
    };
    let pipeline = sluice_elastic::ingest_pipeline(
        "functions",
        &[sluice_elastic::PipelinePlan {
            template: &template,
            recipe: &recipe,
        }],
    );
    let script = pipeline.body["processors"][0]["script"]["source"]
        .as_str()
        .expect("a script")
        .to_owned();
    let end = script.find("Set keys =").expect("the functions come first");
    script[..end].to_owned()
}
