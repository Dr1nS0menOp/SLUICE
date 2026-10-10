//! A complete log source keeps rules for other categories off its events, in the engine as in
//! the guardrails (`LogSource::may_apply_to`).

use serde_json::json;
use sluice_core::alert::RuleEngine;
use sluice_core::event::{Event, Timestamp};
use sluice_core::ids::EventId;
use sluice_core::logsource::LogSource;
use sluice_core::source::{Source, SourceFormat};
use sluice_rules::SigmaRules;

const DATABASE_KEYWORDS: &str = r"
title: Database keywords
id: 00000000-0000-4000-8000-000000000001
logsource:
    category: database
detection:
    keywords:
        - 'drop'
    condition: keywords
";

fn alerts(complete: bool) -> usize {
    let rules = SigmaRules::parse([DATABASE_KEYWORDS]).expect("rule parses");
    let source = Source {
        id: "system".into(),
        logsource: LogSource {
            product: Some("windows".into()),
            service: Some("system".into()),
            category: None,
            complete,
        },
        format: SourceFormat::Json,
    };
    let fields = json!({"EventID": 7036, "param1": "drop table service"});
    let event = Event {
        id: EventId(0),
        timestamp: Timestamp(0),
        source: source.id.clone(),
        fields: fields.as_object().expect("object").clone(),
    };
    let engine = rules.engine(std::slice::from_ref(&source)).expect("engine");
    let found = engine.alerts(&[event]).expect("evaluates").len();
    let applies = rules.requirements()[0]
        .logsource
        .may_apply_to(&source.logsource);
    assert_eq!(found > 0, applies, "engine and guardrails agree");
    found
}

#[test]
fn rules_for_a_missing_category_skip_a_complete_source_only() {
    assert_eq!(alerts(false), 1, "unknown category: the rule may apply");
    assert_eq!(alerts(true), 0);
}
