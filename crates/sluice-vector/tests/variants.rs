//! A template with several key sets (ADR 0019): the generated VRL recognises each of them, and
//! nothing else, so an event in a shape discovery never saw passes through unclassified.

use serde_json::json;
use sluice_core::event::{Event, Timestamp};
use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::EventId;
use sluice_core::logsource::LogSource;
use sluice_core::reduce::Reducer;
use sluice_core::schema::Schema;
use sluice_core::source::{Source, SourceFormat};
use sluice_core::template::TemplateShape;
use sluice_discover::{DiscoverConfig, discover};
use sluice_vector::{Plan, compile_reducer};

fn logon(n: u64, elevated: bool, extra: bool) -> Event {
    let mut record = json!({ "EventID": 4624, "TargetUserName": format!("u{n}") });
    if elevated {
        record["ElevatedToken"] = json!("%%1842");
    }
    if extra {
        record["Unseen"] = json!("x");
    }
    Event {
        id: EventId(n),
        timestamp: Timestamp(0),
        source: "sec".into(),
        fields: record.as_object().expect("an object").clone(),
    }
}

#[test]
fn every_key_set_of_a_kind_is_recognised_and_no_other() {
    let source = Source {
        id: "sec".into(),
        logsource: LogSource::default(),
        format: SourceFormat::Json,
        schema: Schema::Sigma,
        event_type: Vec::new(),
    };
    let sample: Vec<Event> = (0..400).map(|n| logon(n, n % 2 == 0, false)).collect();
    let discovery = discover(
        DiscoverConfig::default(),
        std::slice::from_ref(&source),
        &sample,
    );
    let [template] = discovery.templates.as_slice() else {
        panic!("one kind of event: {:#?}", discovery.templates);
    };
    assert!(
        matches!(&template.shape, TemplateShape::Keyset { variants, .. } if variants.len() == 2)
    );
    let recipe = EffectiveRecipe::passthrough(template.id.clone());
    let data_plane = compile_reducer([Plan {
        template,
        recipe: &recipe,
    }])
    .expect("the program compiles");

    for event in [logon(1, true, false), logon(2, false, false)] {
        let reduced = data_plane.reduce(&event).expect("runs");
        assert_eq!(reduced.template.as_ref(), Some(&template.id));
    }
    let drifted = data_plane.reduce(&logon(3, true, true)).expect("runs");
    assert_eq!(
        drifted.template, None,
        "an unseen key set belongs to no template"
    );
}
