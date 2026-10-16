//! Each event meets the rules in its source's field naming convention, in the engine as in the
//! requirements (ADR 0020).

use serde_json::{Value, json};
use sluice_core::alert::RuleEngine;
use sluice_core::event::{Event, Timestamp};
use sluice_core::ids::EventId;
use sluice_core::logsource::LogSource;
use sluice_core::schema::Schema;
use sluice_core::source::{Source, SourceFormat};
use sluice_rules::{SigmaPipeline, SigmaRules};

const FAILED_LOGON: &str = r"
title: Failed logon
id: 00000000-0000-4000-8000-000000000002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
";

const SNAKE_CASE: &str = "name: snake\ntransformations:\n  - type: field_name_mapping\n    \
                          mapping:\n      EventID: event_id\n";

fn source(id: &str, schema: Schema) -> Source {
    Source {
        id: id.into(),
        logsource: LogSource {
            product: Some("windows".into()),
            service: Some("security".into()),
            category: None,
            complete: false,
        },
        format: SourceFormat::Json,
        schema,
        event_type: Vec::new(),
    }
}

fn event(id: u64, source: &str, fields: &Value) -> Event {
    Event {
        id: EventId(id),
        timestamp: Timestamp(0),
        source: source.into(),
        fields: fields.as_object().expect("object").clone(),
    }
}

#[test]
fn each_event_meets_the_rules_of_its_own_convention() {
    let pipeline = SigmaPipeline::parse(Schema::Ecs, "snake", SNAKE_CASE).expect("pipeline");
    let rules = SigmaRules::parse_with([FAILED_LOGON], &[pipeline]).expect("rules");
    let sources = [source("sigma", Schema::Sigma), source("ecs", Schema::Ecs)];
    let engine = rules.engine(&sources).expect("engine");
    let alerts = engine
        .alerts(&[
            event(0, "sigma", &json!({"EventID": 4625})),
            event(1, "sigma", &json!({"event_id": 4625})),
            event(2, "ecs", &json!({"event_id": 4625})),
            event(3, "ecs", &json!({"EventID": 4625})),
        ])
        .expect("evaluates");
    let fired: Vec<u64> = alerts.iter().map(|a| a.event.0).collect();
    assert_eq!(fired, [0, 2]);
}
