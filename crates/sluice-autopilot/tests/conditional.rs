//! Conditional protection (ADR 0009) without the proof's safety net: for any events, the data
//! plane the guardrails alone allow raises exactly the alerts of the full data.
//!
//! The rules are chosen for the cases where removing a field could change a verdict: keyword
//! searches over every value, `|all` lists, inner wildcards, `null` checks that match a missing
//! field, and `not` filters. Every template is offered the same aggressive recipe: drop the
//! fields those rules read, plus empty fields. Rarity is off, so every template is cut.

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use serde_json::{Map, Value, json};
use sluice_core::event::{Event, Timestamp};
use sluice_core::guard::{GuardContext, GuardrailConfig, guard};
use sluice_core::ids::{EventId, TemplateId};
use sluice_core::logsource::LogSource;
use sluice_core::proof::prove;
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::source::{Source, SourceFormat};
use sluice_discover::{DiscoverConfig, discover};
use sluice_rules::SigmaRules;
use sluice_vector::{Plan, compile_reducer};

const RULES: &str = r"
title: Credential tool keywords
id: 00000000-0000-4000-8000-000000000101
logsource: { product: windows, service: system }
detection:
    keywords: ['sekurlsa::', 'mimikatz']
    filter: { EventID: 15 }
    condition: keywords and not filter
---
title: Reverse shell keywords, all of them
id: 00000000-0000-4000-8000-000000000102
logsource: { product: windows, service: system }
detection:
    keywords:
        '|all': ['bash -c', '/dev/tcp/']
    condition: keywords
---
title: Download with output file
id: 00000000-0000-4000-8000-000000000103
logsource: { product: windows, service: system }
detection:
    selection:
        CommandLine|contains|all: ['curl', ' -o ']
    condition: selection
---
title: Service without user
id: 00000000-0000-4000-8000-000000000104
logsource: { product: windows, service: system }
detection:
    selection:
        EventID: 7036
        User: null
    condition: selection
---
title: Evil command line
id: 00000000-0000-4000-8000-000000000105
logsource: { product: windows, service: system }
detection:
    selection:
        CommandLine: 'cmd*evil.exe'
    condition: selection
---
title: Whoami not by SYSTEM
id: 00000000-0000-4000-8000-000000000106
logsource: { product: windows, service: system }
detection:
    selection:
        Image|endswith: '\whoami.exe'
    filter:
        User: SYSTEM
    condition: selection and not filter
";

fn source() -> Source {
    Source {
        id: "system".into(),
        logsource: LogSource {
            product: Some("windows".into()),
            service: Some("system".into()),
            category: None,
            complete: true,
        },
        format: SourceFormat::Json,
    }
}

/// One event's random parts.
type Draw = (u8, Vec<u8>, Vec<u8>, u8, u8, bool);

const WORDS: [&str; 8] = [
    "sekurlsa::logonpasswords",
    "mimikatz",
    "bash -c",
    "/dev/tcp/10.0.0.1/80",
    "curl",
    " -o ",
    "evil.exe",
    "service",
];

fn event(n: u64, (id, message, command, user, image, extra): &Draw) -> Event {
    let mut fields = Map::new();
    fields.insert(
        "EventID".into(),
        json!([1, 15, 7036, 4624][usize::from(*id % 4)]),
    );
    let words = |picks: &[u8]| -> String {
        picks
            .iter()
            .map(|p| WORDS[usize::from(*p) % WORDS.len()])
            .collect::<Vec<_>>()
            .join(" ")
    };
    if !message.is_empty() {
        fields.insert("Message".into(), json!(words(message)));
    }
    if !command.is_empty() {
        fields.insert(
            "CommandLine".into(),
            json!(format!("cmd {}", words(command))),
        );
    }
    match user % 5 {
        0 => {}
        1 => {
            fields.insert("User".into(), Value::Null);
        }
        2 => {
            fields.insert("User".into(), json!(""));
        }
        3 => {
            fields.insert("User".into(), json!("SYSTEM"));
        }
        _ => {
            fields.insert("User".into(), json!("alice"));
        }
    }
    match image % 3 {
        0 => {}
        1 => {
            fields.insert("Image".into(), json!(r"C:\Windows\System32\whoami.exe"));
        }
        _ => {
            fields.insert("Image".into(), json!(r"C:\a.exe"));
        }
    }
    if *extra {
        fields.insert("Extra".into(), json!(""));
    }
    Event {
        id: EventId(n),
        timestamp: Timestamp(i64::try_from(n).unwrap_or(0)),
        source: source().id,
        fields,
    }
}

fn recipe(template: TemplateId) -> Recipe {
    Recipe::new(
        template,
        vec![
            Reduction::DropFields {
                fields: ["Message", "CommandLine", "User", "Image", "Extra"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            },
            Reduction::DropEmptyFields,
        ],
        Provenance::Operator,
        "drop everything the rules read",
    )
    .expect("one routing reduction at most")
}

#[test]
fn the_guardrails_alone_preserve_every_alert() {
    let rules = SigmaRules::parse([RULES]).expect("rules parse");
    let sources = [source()];
    let engine = rules.engine(&sources).expect("rules compile");
    let draw = (
        any::<u8>(),
        vec(any::<u8>(), 0..4),
        vec(any::<u8>(), 0..4),
        any::<u8>(),
        any::<u8>(),
        any::<bool>(),
    );
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 12,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let conditional = std::cell::Cell::new(0usize);
    runner
        .run(&vec(draw, 20..60), |draws| {
            let events: Vec<Event> = draws.iter().zip(0u64..).map(|(d, n)| event(n, d)).collect();
            let discovery = discover(DiscoverConfig::default(), &sources, &events);
            let ctx = GuardContext {
                rules: rules.requirements(),
                config: GuardrailConfig {
                    rarity_min_events: 0,
                    rarity_min_share_ppm: 0,
                },
                archive_enabled: true,
            };
            let recipes: Vec<_> = discovery
                .templates
                .iter()
                .map(|t| guard(t, Some(&recipe(t.id.clone())), ctx))
                .collect();
            let plans = discovery
                .templates
                .iter()
                .zip(&recipes)
                .map(|(template, recipe)| Plan { template, recipe });
            let data_plane = compile_reducer(plans).expect("programs compile");
            let proof = prove(&events, &engine, &data_plane).expect("proof runs");
            prop_assert!(
                proof.holds(),
                "missing {:?}, extra {:?}",
                proof.missing,
                proof.extra
            );
            let kept_whole = recipes
                .iter()
                .filter(|r| r.keep_whole_when.is_some())
                .count();
            conditional.set(conditional.get() + kept_whole);
            Ok(())
        })
        .expect("conditional protection preserves alerts");
    assert!(
        conditional.get() > 0,
        "some fields were dropped only outside a rule's pre-filter"
    );
}
