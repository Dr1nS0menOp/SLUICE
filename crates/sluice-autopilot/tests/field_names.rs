//! Field names are part of the safety contract (ADR 0018, contract rule 3).
//!
//! A Sigma rule names the fields it reads in Sigma's convention. Records that carry the same data
//! under other names (Elastic's ECS) look to a literal comparison as if the rule read nothing of
//! them: its fields were unprotected, a summarizing recipe took every event including the rule's
//! matches, and the proof compared two empty alert sets. Unless a source declares the convention
//! its records follow, nothing a Sigma rule could read is cut.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sluice_autopilot::{Analysis, Helpers, Input, Settings, analyze_proposals};
use sluice_core::event::{Event, Timestamp};
use sluice_core::guard::Reason;
use sluice_core::ids::{EventId, TemplateId};
use sluice_core::logsource::LogSource;
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::schema::Schema;
use sluice_core::source::{Source, SourceFormat};
use sluice_discover::{DiscoverConfig, discover};
use sluice_rules::{SigmaPipeline, SigmaRules};

const WHOAMI: &str = r"
title: Whoami execution
id: 00000000-0000-4000-8000-000000000301
logsource: { product: windows, category: process_creation }
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
";

/// Events at which the rule's matches sit, among 600 process creations.
const MATCHES: [u64; 3] = [100, 300, 500];

fn source(schema: Schema) -> Source {
    Source {
        id: "proc".into(),
        logsource: LogSource {
            product: Some("windows".into()),
            service: None,
            category: Some("process_creation".into()),
            complete: false,
        },
        format: SourceFormat::Json,
        schema,
        event_type: Vec::new(),
    }
}

fn image(n: u64) -> &'static str {
    if MATCHES.contains(&n) {
        r"C:\Windows\System32\whoami.exe"
    } else {
        ["svchost.exe", "app.exe", "explorer.exe"][usize::try_from(n % 3).unwrap_or(0)]
    }
}

/// A process creation as Sigma names it (Sysmon's `Image`).
fn sigma_named(n: u64) -> Value {
    json!({ "EventID": 1, "Computer": format!("pc{}", n % 4), "Image": image(n) })
}

/// The same process creation as Elastic stores it (ECS).
fn ecs_named(n: u64) -> Value {
    json!({
        "event": { "code": "1" },
        "host": { "name": format!("pc{}", n % 4) },
        "process": { "executable": image(n) },
    })
}

fn events(record: fn(u64) -> Value) -> Vec<Event> {
    (0..600)
        .map(|n| Event {
            id: EventId(n),
            timestamp: Timestamp(i64::try_from(n).unwrap_or(0)),
            source: "proc".into(),
            fields: record(n).as_object().expect("an object").clone(),
        })
        .collect()
}

/// The most aggressive proposal for every template: summarize by the host.
fn summarize_by(
    key: &str,
    templates: &[sluice_core::template::Template],
) -> BTreeMap<TemplateId, Recipe> {
    templates
        .iter()
        .map(|t| {
            let recipe = Recipe::new(
                t.id.clone(),
                vec![Reduction::Summarize {
                    summary_keys: vec![key.into()],
                }],
                Provenance::Operator,
                "summarize everything a rule does not read",
            )
            .expect("a valid recipe");
            (t.id.clone(), recipe)
        })
        .collect()
}

fn analyze(schema: Schema, record: fn(u64) -> Value, key: &str) -> Analysis {
    let rules = SigmaRules::parse([WHOAMI]).expect("the rule parses");
    analyze_with(&rules, schema, record, key)
}

fn analyze_with(
    rules: &SigmaRules,
    schema: Schema,
    record: fn(u64) -> Value,
    key: &str,
) -> Analysis {
    let sources = [source(schema)];
    let events = events(record);
    let discovery = discover(DiscoverConfig::default(), &sources, &events);
    let proposals = summarize_by(key, &discovery.templates);
    analyze_proposals(
        Input {
            sources: &sources,
            events: &events,
            sigma: rules,
            wazuh: None,
            sentinel: None,
            elastic: None,
        },
        discovery,
        proposals,
        &Settings::with_complete_rules(),
        Helpers::default(),
        Vec::new(),
    )
    .expect("the analysis runs")
}

fn differs(analysis: &Analysis) -> bool {
    analysis
        .selection
        .recipes
        .iter()
        .flat_map(|r| &r.adjustments)
        .any(|a| matches!(a.reason, Reason::FieldNamesDiffer { .. }))
}

#[test]
fn c3_a_sigma_rule_on_ecs_records_cuts_nothing_it_could_read() {
    let analysis = analyze(Schema::Ecs, ecs_named, "host.name");
    let proof = &analysis.selection.proof;
    assert_eq!(proof.total.summarized, 0, "no event was summarized");
    assert_eq!(proof.total.forwarded, 600);
    assert!(
        analysis
            .selection
            .recipes
            .iter()
            .all(sluice_core::guard::EffectiveRecipe::is_passthrough)
    );
    assert!(differs(&analysis), "the refusal says why");
    // The proof is blind here (the rule's names never occur in ECS records): the guardrails are
    // what keep the data, which is why they must not rely on the pre-filter finding a match.
    assert!(proof.full_alerts.is_empty());
}

/// With the pipeline Elastic's conversion uses (ADR 0020), the rule reads the ECS names: the
/// ECS records are cut like the Sigma-named ones, the proof runs the mapped rule on them, and its
/// matches are forwarded.
#[test]
fn c3_ecs_records_are_cut_through_the_ecs_pipeline_and_their_matches_kept() {
    let ecs = SigmaPipeline::builtin(Schema::Ecs, "ecs_windows").expect("built in");
    let rules = SigmaRules::parse_with([WHOAMI], &[ecs]).expect("the rule maps");
    let analysis = analyze_with(&rules, Schema::Ecs, ecs_named, "host.name");
    let proof = &analysis.selection.proof;
    assert_eq!(
        proof.full_alerts.len(),
        MATCHES.len(),
        "the mapped rule fires on ECS"
    );
    assert!(proof.holds(), "missing {:?}", proof.missing);
    assert_eq!(
        proof.total.summarized,
        600 - u64::try_from(MATCHES.len()).unwrap_or(0)
    );
    assert!(!differs(&analysis));
    // The original rule still serves Sigma-named records.
    let sigma = analyze_with(&rules, Schema::Sigma, sigma_named, "Computer");
    assert_eq!(sigma.selection.proof.full_alerts.len(), MATCHES.len());
    assert!(sigma.selection.proof.holds());
}

#[test]
fn c3_records_of_an_undeclared_source_are_treated_the_same_way() {
    let analysis = analyze(Schema::Undeclared, sigma_named, "Computer");
    assert_eq!(analysis.selection.proof.total.summarized, 0);
    assert!(differs(&analysis));
}

#[test]
fn c3_the_same_events_in_sigma_names_are_cut_and_their_matches_forwarded() {
    let analysis = analyze(Schema::Sigma, sigma_named, "Computer");
    let proof = &analysis.selection.proof;
    assert!(proof.holds(), "missing {:?}", proof.missing);
    assert_eq!(proof.full_alerts.len(), MATCHES.len());
    assert_eq!(proof.forwarded_alerts, proof.full_alerts);
    assert_eq!(
        proof.total.summarized,
        600 - u64::try_from(MATCHES.len()).unwrap_or(0),
        "everything but the rule's matches was summarized"
    );
    assert!(!differs(&analysis));
}
