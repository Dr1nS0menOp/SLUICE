//! The per-source program, run with the `vrl` crate: classification, routing and reductions.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use sluice_core::event::{Event, Timestamp};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::EventId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::schema::Schema;
use sluice_core::template::{LineHeader, Template, TemplateShape, TemplateStats};

use super::Plan;
use crate::compile_reducer;

fn paths(names: &[&str]) -> BTreeSet<FieldPath> {
    names.iter().map(|n| FieldPath::from(*n)).collect()
}

fn keyset(id: &str, event_id: &str, fields: &[&str]) -> Template {
    Template {
        id: id.into(),
        source: "s".into(),
        logsource: LogSource::default(),
        schema: Schema::Sigma,
        pattern: String::new(),
        shape: TemplateShape::Keyset {
            discriminators: vec![("EventID".into(), event_id.to_owned())],
            paths: paths(fields),
            variants: vec![paths(fields)],
        },
        fields: paths(fields),
        text_fields: BTreeSet::new(),
        stats: TemplateStats::default(),
    }
}

fn text(id: &str, tokens: &[&str]) -> Template {
    Template {
        shape: TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::None,
            tokens: tokens.iter().map(|t| (*t).to_owned()).collect(),
        },
        fields: paths(&["message"]),
        text_fields: paths(&["message"]),
        ..keyset(id, "0", &["message"])
    }
}

fn event(fields: Value) -> Event {
    let Value::Object(fields) = fields else {
        unreachable!()
    };
    Event {
        id: EventId(1),
        timestamp: Timestamp(0),
        source: "s".into(),
        fields,
    }
}

/// The template and outcome the program gives `body`, with these plans.
fn reduce(plans: &[(Template, EffectiveRecipe)], body: Value) -> (Option<String>, Outcome) {
    let plans: Vec<Plan<'_>> = plans
        .iter()
        .map(|(template, recipe)| Plan { template, recipe })
        .collect();
    let data_plane = compile_reducer(plans).expect("compiles without warnings");
    let result = data_plane.reduce(&event(body)).expect("runs");
    (result.template.map(|t| t.to_string()), result.outcome)
}

fn forwarded(outcome: Outcome) -> Map<String, Value> {
    match outcome {
        Outcome::Forwarded(body) => body,
        Outcome::Summarized => panic!("summarized"),
    }
}

fn eq(field: &str, value: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op: MatchOp::Equals,
        values: vec![value.into()],
        case_sensitive: false,
    })
}

fn logon() -> Template {
    keyset(
        "logon",
        "4624",
        &["EventID", "User", "Message", "Empty", "Gone"],
    )
}

fn logon_event(user: &str) -> Value {
    json!({"EventID": 4624, "User": user, "Message": "long text", "Empty": "", "Gone": null})
}

#[test]
fn an_unclassified_event_is_forwarded_unchanged_without_a_template() {
    let plans = [(logon(), EffectiveRecipe::passthrough("logon".into()))];
    let other = json!({"EventID": 9, "Other": 1});
    let (template, outcome) = reduce(&plans, other.clone());
    assert_eq!(template, None);
    assert_eq!(Value::Object(forwarded(outcome)), other);
}

#[test]
fn a_passthrough_recipe_classifies_but_changes_nothing() {
    let plans = [(logon(), EffectiveRecipe::passthrough("logon".into()))];
    let (template, outcome) = reduce(&plans, logon_event("a"));
    assert_eq!(template.as_deref(), Some("logon"));
    assert_eq!(Value::Object(forwarded(outcome)), logon_event("a"));
}

#[test]
fn c3_rule_guided_routing_forwards_matches_whole_and_summarizes_the_rest() {
    let recipe = EffectiveRecipe {
        drop_fields: paths(&["Message"]),
        route: Route::ForwardMatching {
            prefilter: eq("User", "admin"),
            summary_keys: vec!["User".into()],
        },
        ..EffectiveRecipe::passthrough("logon".into())
    };
    let plans = [(logon(), recipe)];
    let (_, matched) = reduce(&plans, logon_event("ADMIN"));
    assert!(
        !forwarded(matched).contains_key("Message"),
        "dropped on forwarded events"
    );
    let (_, other) = reduce(&plans, logon_event("bob"));
    assert_eq!(other, Outcome::Summarized);
}

#[test]
fn c3_events_a_protecting_rule_may_match_keep_every_field() {
    let recipe = EffectiveRecipe {
        drop_fields: paths(&["Message"]),
        keep_whole_when: Some(eq("User", "admin")),
        ..EffectiveRecipe::passthrough("logon".into())
    };
    let plans = [(logon(), recipe)];
    let (_, admin) = reduce(&plans, logon_event("admin"));
    assert_eq!(Value::Object(forwarded(admin)), logon_event("admin"));
    let (_, bob) = reduce(&plans, logon_event("bob"));
    assert!(!forwarded(bob).contains_key("Message"));
}

#[test]
fn empty_fields_go_except_those_rules_need() {
    let recipe = EffectiveRecipe {
        drop_empty_except: Some(paths(&["Empty"])),
        ..EffectiveRecipe::passthrough("logon".into())
    };
    let plans = [(logon(), recipe)];
    let body = forwarded(reduce(&plans, logon_event("a")).1);
    assert!(body.contains_key("Empty"), "kept for a rule");
    assert!(!body.contains_key("Gone"), "null removed");
    assert_eq!(body.get("User"), Some(&json!("a")), "values untouched");
}

#[test]
fn c3_a_field_a_rule_needs_keeps_what_lies_under_and_over_it() {
    let template = keyset("nested", "1", &["EventID", "Host.Name", "Data", "Other"]);
    let recipe = EffectiveRecipe {
        // A rule reads the object `Host`, and one reads `Data.Inner` (parsed from `Data`).
        drop_empty_except: Some(paths(&["Host", "Data.Inner"])),
        ..EffectiveRecipe::passthrough("nested".into())
    };
    let plans = [(template, recipe)];
    let body = forwarded(
        reduce(
            &plans,
            json!({"EventID": 1, "Host": {"Name": ""}, "Data": "", "Other": ""}),
        )
        .1,
    );
    assert_eq!(
        body.get("Host"),
        Some(&json!({"Name": ""})),
        "under a needed field"
    );
    assert_eq!(body.get("Data"), Some(&json!("")), "over a needed field");
    assert!(!body.contains_key("Other"));
}

#[test]
fn key_set_templates_are_tried_before_text_templates() {
    // A JSON event with a `message` that the text template would also take.
    let json_template = keyset("json", "0", &["EventID", "message"]);
    let text_template = text("text", &["<*>"]);
    let plans = [
        (text_template, EffectiveRecipe::passthrough("text".into())),
        (json_template, EffectiveRecipe::passthrough("json".into())),
    ];
    let (template, _) = reduce(&plans, json!({"EventID": 0, "message": "hello"}));
    assert_eq!(template.as_deref(), Some("json"));
}

#[test]
fn the_more_specific_text_template_wins() {
    let plans = [
        (
            text("any", &["<*>", "<*>"]),
            EffectiveRecipe::passthrough("any".into()),
        ),
        (
            text("failed", &["Failed", "<*>"]),
            EffectiveRecipe::passthrough("failed".into()),
        ),
    ];
    let (template, _) = reduce(&plans, json!({"message": "Failed password"}));
    assert_eq!(template.as_deref(), Some("failed"));
    let (template, _) = reduce(&plans, json!({"message": "Accepted password"}));
    assert_eq!(template.as_deref(), Some("any"));
}

#[test]
fn a_summarized_event_keeps_every_field_for_its_summary_keys() {
    let recipe = EffectiveRecipe {
        drop_fields: paths(&["User"]),
        route: Route::ForwardMatching {
            prefilter: Predicate::never(),
            summary_keys: vec!["User".into()],
        },
        ..EffectiveRecipe::passthrough("logon".into())
    };
    let plans = [(logon(), recipe)];
    let plans_ref: Vec<Plan<'_>> = plans
        .iter()
        .map(|(t, r)| Plan {
            template: t,
            recipe: r,
        })
        .collect();
    let reducer = compile_reducer(plans_ref).unwrap();
    let sample = event(logon_event("bob"));
    let program = reducer.program(&"s".into()).unwrap();
    let (body, _) = program.run(&sample.fields).unwrap();
    assert_eq!(serde_json::to_value(&body).unwrap()["User"], "bob");
}
