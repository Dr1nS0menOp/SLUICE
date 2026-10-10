//! Hostile input: event field names and values chosen to break generated code (quotes, braces,
//! backslashes, template markers, dots, unicode, control characters, empty names). For any of
//! them the autopilot must produce a data plane that compiles, and whatever it enforces must keep
//! the alerts of the full data. Rules reference some of the odd names, so guardrails meet them too.

use std::collections::BTreeMap;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use serde_json::{Map, Value, json};
use sluice_autopilot::{Helpers, Input, Settings, analyze_proposals};
use sluice_core::event::{Event, Timestamp};
use sluice_core::guard::GuardrailConfig;
use sluice_core::ids::{EventId, TemplateId};
use sluice_core::logsource::LogSource;
use sluice_core::proof::prove;
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::source::{Source, SourceFormat};
use sluice_discover::{DiscoverConfig, discover};
use sluice_rules::SigmaRules;

/// Field names that have broken code generators before, or could.
const NAMES: [&str; 14] = [
    "plain",
    "with space",
    "quote\"d",
    "brace{{x}}",
    "back\\slash",
    "dot.ted",
    "ünïcödé",
    "emoji🔥",
    "tab\tname",
    "new\nline",
    "'single'",
    "%meta",
    "@timestamp",
    "$dollar",
];

/// Values with the same hazards, plus numbers, booleans, nulls, arrays and objects.
fn value(pick: u8) -> Value {
    match pick % 10 {
        0 => json!("plain value"),
        1 => json!("{{ template }}"),
        2 => json!("quote\" and \\ backslash"),
        3 => json!(""),
        4 => Value::Null,
        5 => json!(4624),
        6 => json!(true),
        7 => json!(["a", 1]),
        8 => json!({"nested \"key\"": "v"}),
        _ => json!("mimikatz sekurlsa::"),
    }
}

const RULES: &str = r#"
title: Odd field names
id: 00000000-0000-4000-8000-000000000201
logsource: { product: odd }
detection:
    selection:
        'quote"d|contains': 'plain'
        'dot.ted': 4624
    condition: selection
---
title: Odd keywords
id: 00000000-0000-4000-8000-000000000202
logsource: { product: odd }
detection:
    keywords: ['sekurlsa::', '{{ template }}']
    condition: keywords
"#;

fn source() -> Source {
    Source {
        id: "odd".into(),
        logsource: LogSource {
            product: Some("odd".into()),
            service: None,
            category: None,
            complete: true,
        },
        format: SourceFormat::Json,
    }
}

type Draw = Vec<(u8, u8)>;

fn event(n: u64, fields: &Draw) -> Event {
    let mut map = Map::new();
    map.insert(
        "kind".into(),
        json!(["a", "b"][usize::try_from(n % 2).unwrap_or(0)]),
    );
    for (name, pick) in fields {
        map.insert(
            NAMES[usize::from(*name) % NAMES.len()].to_owned(),
            value(*pick),
        );
    }
    Event {
        id: EventId(n),
        timestamp: Timestamp(i64::try_from(n).unwrap_or(0)),
        source: source().id,
        fields: map,
    }
}

/// Every template gets the most aggressive proposal: drop all its fields but one, drop empty
/// fields, summarize keyed by the first field.
fn proposal(template: &sluice_core::template::Template) -> Option<Recipe> {
    let fields: std::collections::BTreeSet<_> = template.fields.iter().skip(1).cloned().collect();
    let keys = template.fields.iter().take(1).cloned().collect();
    let mut reductions = vec![
        Reduction::DropEmptyFields,
        Reduction::Summarize { summary_keys: keys },
    ];
    if !fields.is_empty() {
        reductions.insert(0, Reduction::DropFields { fields });
    }
    Recipe::new(
        template.id.clone(),
        reductions,
        Provenance::Ai {
            model: "hostile".into(),
        },
        "drop nearly everything",
    )
    .ok()
}

#[test]
fn odd_names_and_values_compile_and_keep_every_alert() {
    let rules = SigmaRules::parse([RULES]).expect("rules parse");
    let sources = [source()];
    let engine = rules.engine(&sources).expect("rules compile");
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 6,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let reduced = std::cell::Cell::new(0usize);
    // Rarity off: every template is cut, so every odd name reaches generated code.
    let settings = Settings {
        guardrails: GuardrailConfig {
            rarity_min_events: 0,
            rarity_min_share_ppm: 0,
        },
        ..Settings::default()
    };
    runner
        .run(
            &vec(vec((any::<u8>(), any::<u8>()), 1..6), 20..50),
            |draws| {
                let events: Vec<Event> =
                    draws.iter().zip(0u64..).map(|(d, n)| event(n, d)).collect();
                let discovery = discover(DiscoverConfig::default(), &sources, &events);
                let proposals: BTreeMap<TemplateId, Recipe> = discovery
                    .templates
                    .iter()
                    .filter_map(|t| proposal(t).map(|r| (t.id.clone(), r)))
                    .collect();
                let input = Input {
                    sources: &sources,
                    events: &events,
                    sigma: &rules,
                    wazuh: None,
                };
                // Any error here (a generated program that does not compile) fails the property.
                let analysis = analyze_proposals(
                    input,
                    discovery,
                    proposals,
                    &settings,
                    Helpers::default(),
                    Vec::new(),
                )
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
                let proof = prove(&events, &engine, &analysis.data_plane)
                    .map_err(|e| TestCaseError::fail(e.to_string()))?;
                prop_assert!(
                    proof.holds(),
                    "missing {:?}, extra {:?}",
                    proof.missing,
                    proof.extra
                );
                let cut = analysis
                    .selection
                    .recipes
                    .iter()
                    .filter(|r| !r.is_passthrough());
                reduced.set(reduced.get() + cut.count());
                Ok(())
            },
        )
        .expect("hostile input is handled");
    assert!(reduced.get() > 0, "the odd names reached generated code");
}

/// Tokens for text lines that are hazards in regexes, VRL strings and templates.
const TOKENS: [&str; 16] = [
    "sshd", "Failed", "password", "(", "[x]", "a\\b", "$1", "*", "+?", "{{x}}", "\"q\"", "'s'",
    "ü", "🔥", "10.0.0.1", "|",
];

#[test]
fn odd_text_lines_compile_and_keep_every_alert() {
    let text_source = Source {
        id: "odd-text".into(),
        logsource: LogSource {
            product: Some("odd".into()),
            service: None,
            category: None,
            complete: true,
        },
        format: SourceFormat::Text {
            field: "message".into(),
        },
    };
    let rules = SigmaRules::parse([RULES]).expect("rules parse");
    let sources = [text_source];
    let engine = rules.engine(&sources).expect("rules compile");
    let settings = Settings {
        guardrails: GuardrailConfig {
            rarity_min_events: 0,
            rarity_min_share_ppm: 0,
        },
        ..Settings::default()
    };
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 6,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let reduced = std::cell::Cell::new(0usize);
    runner
        .run(&vec(vec(any::<u8>(), 2..8), 20..50), |lines| {
            let events: Vec<Event> = lines
                .iter()
                .zip(0u64..)
                .map(|(tokens, n)| {
                    let words: Vec<&str> = tokens
                        .iter()
                        .map(|t| TOKENS[usize::from(*t) % TOKENS.len()])
                        .collect();
                    let line = format!(
                        "Oct 10 08:00:0{} host sshd[42]: {}",
                        n % 10,
                        words.join(" ")
                    );
                    let mut fields = Map::new();
                    fields.insert("message".into(), json!(line));
                    Event {
                        id: EventId(n),
                        timestamp: Timestamp(i64::try_from(n).unwrap_or(0)),
                        source: sources[0].id.clone(),
                        fields,
                    }
                })
                .collect();
            let discovery = discover(DiscoverConfig::default(), &sources, &events);
            let proposals: BTreeMap<TemplateId, Recipe> = discovery
                .templates
                .iter()
                .filter_map(|t| proposal(t).map(|r| (t.id.clone(), r)))
                .collect();
            let input = Input {
                sources: &sources,
                events: &events,
                sigma: &rules,
                wazuh: None,
            };
            let analysis = analyze_proposals(
                input,
                discovery,
                proposals,
                &settings,
                Helpers::default(),
                Vec::new(),
            )
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let proof = prove(&events, &engine, &analysis.data_plane)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(
                proof.holds(),
                "missing {:?}, extra {:?}",
                proof.missing,
                proof.extra
            );
            let cut = analysis
                .selection
                .recipes
                .iter()
                .filter(|r| !r.is_passthrough());
            reduced.set(reduced.get() + cut.count());
            Ok(())
        })
        .expect("hostile text is handled");
    assert!(reduced.get() > 0, "the odd lines reached generated code");
}
