use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use sluice_core::event::{Event, Timestamp};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::{EventId, SourceId};
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::template::{LineHeader, Template, TemplateShape, TemplateStats};

use super::*;
use crate::FluentBit;

/// The command that runs Fluent Bit (`scripts/fluentbit-check.sh` sets it).
const ENV: &str = "SLUICE_FLUENT_BIT";

fn paths(names: &[&str]) -> BTreeSet<FieldPath> {
    names.iter().map(|n| FieldPath::from(*n)).collect()
}

fn template(id: &str, discriminators: &[(&str, &str)], variants: &[&[&str]]) -> Template {
    let variants: Vec<BTreeSet<FieldPath>> = variants.iter().map(|v| paths(v)).collect();
    let all: BTreeSet<FieldPath> = variants.iter().flatten().cloned().collect();
    Template {
        id: id.into(),
        source: "windows".into(),
        logsource: sluice_core::logsource::LogSource::default(),
        schema: sluice_core::schema::Schema::default(),
        pattern: String::new(),
        shape: TemplateShape::Keyset {
            discriminators: discriminators
                .iter()
                .map(|(f, v)| (FieldPath::from(*f), (*v).to_owned()))
                .collect(),
            paths: all.clone(),
            variants,
        },
        fields: all,
        text_fields: BTreeSet::new(),
        stats: TemplateStats::default(),
    }
}

fn removing(id: &str, fields: &[&str], keep: Option<Predicate>) -> EffectiveRecipe {
    EffectiveRecipe {
        drop_fields: paths(fields),
        keep_whole_when: keep,
        ..EffectiveRecipe::passthrough(id.into())
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

fn of(plans: &[(&Template, &EffectiveRecipe)]) -> LuaFilter {
    let plans: Vec<Plan<'_>> = plans
        .iter()
        .map(|(template, recipe)| Plan { template, recipe })
        .collect();
    lua_filter("test", &plans)
}

fn script(filter: &LuaFilter) -> &str {
    filter.script.as_deref().expect("a script")
}

fn logon() -> Template {
    template(
        "windows:4624:a",
        &[("EventID", "4624")],
        &[
            &["EventID", "Message", "User", "Host.name"],
            &["EventID", "Message", "User", "Host.name", "Ip"],
        ],
    )
}

#[test]
fn a_plan_that_removes_nothing_has_no_script() {
    let t = logon();
    let unchanged = of(&[(&t, &EffectiveRecipe::passthrough(t.id.clone()))]);
    assert_eq!(unchanged.script, None);
    assert!(unchanged.templates.is_empty() && unchanged.fields.is_empty());
    assert_eq!(of(&[]).script, None);
}

#[test]
fn a_removal_decides_everything_before_it_removes() {
    let t = logon();
    let recipe = removing(t.id.as_str(), &["Message"], Some(eq("User", "Admin")));
    let out = of(&[(&t, &recipe)]);
    assert_eq!(out.templates, [t.id.clone()].into());
    assert_eq!(out.fields, paths(&["Message"]));
    let script = script(&out);
    let classify = script.find("then t = 0").expect("classifies");
    let keep = script
        .find("if t == 0 and not (K[0](r)) then act = 0 end")
        .expect("tests keep-whole");
    let safe = script.find("not sluice_safe(r)").expect("checks numbers");
    let remove = script
        .find(r#"sluice_remove(r, {"Message"})"#)
        .expect("removes");
    assert!(classify < keep && keep < safe && safe < remove, "{script}");
    assert!(script.contains("K[0] = function(r)\n  return sluice_test("));
    assert!(script.contains(
        r#"{["EventID"] = true, ["Host.name"] = true, ["Message"] = true, ["User"] = true}"#
    ));
    assert!(script.contains(r#"sluice_disc(sluice_get(r, {"EventID"})) == "4624""#));
    assert!(
        script.contains("return 0, ts, r"),
        "unchanged records stay as they were"
    );
}

/// Takes the records with an IP of [`logon`] first: its id sorts before.
fn overlapping() -> Template {
    template(
        "windows:1:a",
        &[],
        &[&["EventID", "Message", "User", "Host.name", "Ip"]],
    )
}

#[test]
fn c1_a_template_that_changes_nothing_still_claims_what_vector_gives_it() {
    let counted = overlapping();
    let removed = logon();
    let unrelated = template("windows:0:a", &[], &[&["Other"]]);
    let counting = EffectiveRecipe {
        route: Route::ForwardMatching {
            prefilter: eq("User", "x"),
            summary_keys: vec!["User".into()],
        },
        ..removing(counted.id.as_str(), &["User"], None)
    };
    let recipe = removing(removed.id.as_str(), &["Message"], None);
    let out = of(&[
        (&removed, &recipe),
        (&counted, &counting),
        (
            &unrelated,
            &EffectiveRecipe::passthrough(unrelated.id.clone()),
        ),
    ]);
    let script = script(&out);
    assert!(
        script.contains("then t = 1"),
        "both overlapping templates classify"
    );
    assert!(
        !script.contains("then t = 2"),
        "the unrelated one is not needed"
    );
    assert!(script.contains("if act == 1 then") && !script.contains("if act == 0 then"));
    assert!(out.left_out.iter().any(|r| r.contains("counting")));
    assert_eq!(out.templates, [removed.id.clone()].into());
}

/// A template whose discriminator is a number Lua cannot render (`0.5`), and a later one of the
/// same key set that removes `Status`.
fn undecided_then_later() -> [(Template, EffectiveRecipe); 2] {
    let undecided = template(
        "windows:0:b",
        &[("EventID", "0.5")],
        &[&["EventID", "Status"]],
    );
    let later = template("windows:0:c", &[], &[&["EventID", "Status"]]);
    let unchanged = EffectiveRecipe::passthrough(undecided.id.clone());
    let recipe = removing(later.id.as_str(), &["Status"], None);
    [(undecided, unchanged), (later, recipe)]
}

#[test]
fn c1_a_record_an_earlier_template_cannot_decide_is_claimed_by_no_later_one() {
    let [(undecided, unchanged), (later, recipe)] = undecided_then_later();
    let out = of(&[(&undecided, &unchanged), (&later, &recipe)]);
    let text = script(&out);
    let claim = text
        .find("then t = 0")
        .expect("the undecided template claims");
    let stop = text
        .find(
            r#"elseif sluice_is(keys, n, S[1], 2) and sluice_may(sluice_get(r, {"EventID"}), "0.5") then t = -2"#,
        )
        .expect("the search stops where Lua cannot decide");
    let taken = text
        .find("then t = 1")
        .expect("the later template takes the rest");
    assert!(claim < stop && stop < taken, "{text}");
    assert!(text.contains("if act == 1 then") && !text.contains("if act == 0 then"));
    // Values Lua renders as VRL does need no stop.
    let t = logon();
    let plain = of(&[(&t, &removing(t.id.as_str(), &["Message"], None))]);
    assert!(!script(&plain).contains("t = -2"));
}

#[test]
fn c1_text_templates_are_left_to_a_pipeline_tool() {
    let text = Template {
        shape: TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::None,
            tokens: vec!["x".into()],
        },
        ..template("linux:a", &[], &[&["message"]])
    };
    let out = of(&[(&text, &removing(text.id.as_str(), &["message"], None))]);
    assert_eq!(out.script, None);
    assert_eq!(out.left_out.len(), 1, "{:?}", out.left_out);
}

#[test]
fn templates_share_the_functions_of_their_keep_whole_alternatives() {
    let a = logon();
    let b = template(
        "windows:4634:a",
        &[("EventID", "4634")],
        &[&["EventID", "Message", "User"]],
    );
    let both = Predicate::Any(vec![eq("User", "Admin"), eq("User", "root")]);
    let out = of(&[
        (&a, &removing(a.id.as_str(), &["Message"], Some(both))),
        (
            &b,
            &removing(b.id.as_str(), &["Message"], Some(eq("User", "root"))),
        ),
    ]);
    let script = script(&out);
    assert_eq!(script.matches("] = function(r)").count(), 2, "{script}");
    assert!(script.contains("not (K[0](r) or K[1](r))"));
    assert!(script.contains("not (K[1](r))"));
}

#[test]
fn empty_fields_are_removed_except_those_kept() {
    let t = logon();
    let recipe = EffectiveRecipe {
        drop_empty_except: Some(paths(&["User"])),
        ..EffectiveRecipe::passthrough(t.id.clone())
    };
    let out = of(&[(&t, &recipe)]);
    assert!(script(&out).contains(r#"sluice_remove_empty_except(r, keys, {"User"}, {})"#));
    assert!(out.empty_fields && out.fields.is_empty());
}

fn event(fields: &Value) -> Event {
    Event {
        id: EventId(0),
        timestamp: Timestamp(0),
        source: SourceId::new("windows"),
        fields: fields.as_object().expect("an object").clone(),
    }
}

/// What Vector's VRL forwards of each event, for the same templates and recipes.
fn vrl(plans: &[(&Template, &EffectiveRecipe)], events: &[Event]) -> Vec<Map<String, Value>> {
    let reducer = sluice_vector::compile_reducer(
        plans
            .iter()
            .map(|(template, recipe)| sluice_vector::Plan { template, recipe }),
    )
    .expect("VRL compiles");
    events
        .iter()
        .map(|e| match reducer.reduce(e).expect("VRL runs").outcome {
            Outcome::Forwarded(body) => body,
            Outcome::Summarized => panic!("nothing is counted here"),
        })
        .collect()
}

/// The leaf paths of a record, as VRL's `flatten` makes them.
fn leaves(record: &Map<String, Value>) -> BTreeSet<String> {
    fn walk(prefix: String, value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    walk(format!("{prefix}.{key}"), value, out);
                }
            }
            _ => {
                out.insert(prefix);
            }
        }
    }
    let mut out = BTreeSet::new();
    for (key, value) in record {
        walk(key.clone(), value, &mut out);
    }
    out
}

/// Whether Lua gave the value back: the same, or exactly the same number.
#[allow(clippy::float_cmp, reason = "the number must come back exactly")]
fn same(old: &Value, new: &Value) -> bool {
    old == new || old.as_f64().zip(new.as_f64()).is_some_and(|(a, b)| a == b)
}

/// Each leaf path with its value; an emptied object is a leaf of its own.
fn leaf_values(record: &Map<String, Value>) -> std::collections::BTreeMap<String, Value> {
    fn walk(prefix: String, value: &Value, out: &mut std::collections::BTreeMap<String, Value>) {
        match value {
            Value::Object(map) if !map.is_empty() => {
                for (key, value) in map {
                    walk(format!("{prefix}.{key}"), value, out);
                }
            }
            other => {
                out.insert(prefix, other.clone());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    for (key, value) in record {
        walk(key.clone(), value, &mut out);
    }
    out
}

/// Records across the edges of recognition, each with whether Lua cannot decide as VRL does
/// and keeps the record whole.
fn edge_cases() -> Vec<(Event, bool)> {
    let base = json!({"EventID": 4624, "Message": "An account logged on", "User": "bob",
                      "Host": {"name": "ws1"}});
    let with = |change: &dyn Fn(&mut Value)| {
        let mut fields = base.clone();
        change(&mut fields);
        event(&fields)
    };
    // `true`: Lua cannot decide as VRL does, and the record stays whole.
    vec![
        (with(&|_| {}), false),
        (with(&|f| f["Ip"] = json!("10.0.0.1")), false),
        (with(&|f| f["Extra"] = json!(1)), false),
        (with(&|f| f["User"] = json!("ADMIN")), false),
        (with(&|f| f["User"] = json!("admİn")), true),
        (with(&|f| f["EventID"] = json!("4624")), false),
        (with(&|f| f["EventID"] = json!(4624.0)), false),
        (with(&|f| f["EventID"] = json!(4625)), false),
        (with(&|f| f["Host"] = json!({"name": "", "os": {}})), true),
        (with(&|f| f["Host"] = json!({"name": null})), false),
        (with(&|f| f["Host"] = json!("flat")), false),
        (with(&|f| f["User"] = json!(["a", "b"])), false),
        (with(&|f| f["Message"] = json!({"nested": "x"})), false),
        (
            with(&|f| f["Host"]["name"] = json!(9_007_199_254_740_993_u64)),
            true,
        ),
        (with(&|f| f["Host"]["name"] = json!(-0.0)), true),
        (with(&|f| f["Host"]["name"] = json!(2.5)), false),
        (
            with(&|f| {
                f.as_object_mut().expect("an object").remove("User");
            }),
            false,
        ),
        (event(&json!({"EventID": 4634, "User": "carol"})), false),
        (
            event(&json!({"EventID": 4634, "User": "carol", "Message": "x"})),
            false,
        ),
        (event(&json!({"EventID": "4634", "User": null})), false),
    ]
}

/// In a real Fluent Bit (`SLUICE_FLUENT_BIT`, `scripts/fluentbit-check.sh`): every record loses
/// exactly what it loses in Vector's VRL, across the edges of recognition, and keeps the rest as
/// Fluent Bit gives it without the filter. Where Lua cannot decide, the record stays whole.
#[test]
fn c1_in_fluent_bit_records_lose_exactly_what_they_lose_in_vector() {
    let Ok(command) = std::env::var(ENV) else {
        return;
    };
    let t = logon();
    let other = template(
        "windows:4634:a",
        &[("EventID", "4634")],
        &[&["EventID", "User"]],
    );
    let recipe = EffectiveRecipe {
        drop_empty_except: Some(paths(&["User"])),
        ..removing(t.id.as_str(), &["Message"], Some(eq("User", "Admin")))
    };
    let other_recipe = removing(other.id.as_str(), &["User"], None);
    let claiming = overlapping();
    let unchanged = EffectiveRecipe::passthrough(claiming.id.clone());
    let plans = [
        (&t, &recipe),
        (&other, &other_recipe),
        (&claiming, &unchanged),
    ];
    let cases = edge_cases();
    let events: Vec<Event> = cases.iter().map(|(e, _)| e.clone()).collect();
    let expected = vrl(&plans, &events);
    let out = of(&plans);
    let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
    let fluent_bit = FluentBit::new(command);
    let baseline = fluent_bit.run(None, &records).expect("Fluent Bit runs");
    let actual = fluent_bit
        .run(out.script.as_deref(), &records)
        .unwrap_or_else(|e| panic!("{e}\n{}", script(&out)));
    for (((event, widened), vector), (before, after)) in cases
        .iter()
        .zip(&expected)
        .zip(baseline.iter().zip(&actual))
    {
        let shown = Value::Object(event.fields.clone());
        let lost_in_vector: BTreeSet<String> = leaves(&event.fields)
            .difference(&leaves(vector))
            .cloned()
            .collect();
        let lost_here: BTreeSet<String> =
            leaves(before).difference(&leaves(after)).cloned().collect();
        if *widened {
            assert_eq!(after, before, "kept whole: {shown}");
            assert!(!lost_in_vector.is_empty(), "Vector removes: {shown}");
        } else {
            assert_eq!(lost_here, lost_in_vector, "event {shown}");
        }
        let was = leaf_values(before);
        for (path, value) in leaf_values(after) {
            // An object whose last field went is a leaf of its own now, as in Vector.
            let Some(was) = was.get(&path) else {
                assert_eq!(value, json!({}), "{path} is new: {shown}");
                continue;
            };
            assert!(
                same(was, &value),
                "{path} changed from {was} to {value}: {shown}"
            );
        }
    }
    assert!(
        expected.iter().zip(&events).any(|(v, e)| v != &e.fields),
        "some event loses fields, or the test shows nothing"
    );
}

/// In a real Fluent Bit: a record whose discriminator Lua cannot render as VRL does stays
/// whole, never handed to a later template of the same key set; others lose what Vector removes.
#[test]
fn c1_in_fluent_bit_a_record_an_earlier_template_cannot_decide_stays_whole() {
    let Ok(command) = std::env::var(ENV) else {
        return;
    };
    let [(undecided, unchanged), (later, recipe)] = undecided_then_later();
    let plans = [(&undecided, &unchanged), (&later, &recipe)];
    // `true`: kept whole, where Vector removes `Status`.
    let cases = [
        (event(&json!({"EventID": 0.5, "Status": "ok"})), false),
        (event(&json!({"EventID": 0.25, "Status": "ok"})), true),
        (event(&json!({"EventID": 7, "Status": "ok"})), false),
    ];
    let events: Vec<Event> = cases.iter().map(|(e, _)| e.clone()).collect();
    let expected = vrl(&plans, &events);
    let out = of(&plans);
    let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
    let fluent_bit = FluentBit::new(command);
    let baseline = fluent_bit.run(None, &records).expect("Fluent Bit runs");
    let actual = fluent_bit
        .run(out.script.as_deref(), &records)
        .unwrap_or_else(|e| panic!("{e}\n{}", script(&out)));
    for (((event, widened), vector), (before, after)) in cases
        .iter()
        .zip(&expected)
        .zip(baseline.iter().zip(&actual))
    {
        let shown = Value::Object(event.fields.clone());
        let lost_in_vector: BTreeSet<String> = leaves(&event.fields)
            .difference(&leaves(vector))
            .cloned()
            .collect();
        let lost_here: BTreeSet<String> =
            leaves(before).difference(&leaves(after)).cloned().collect();
        if *widened {
            assert_eq!(after, before, "kept whole: {shown}");
            assert!(!lost_in_vector.is_empty(), "Vector removes: {shown}");
        } else {
            assert_eq!(lost_here, lost_in_vector, "event {shown}");
        }
    }
}

/// A script Fluent Bit cannot load is an error, not a filter that passes everything.
#[test]
fn a_script_that_does_not_load_is_refused() {
    let Ok(command) = std::env::var(ENV) else {
        return;
    };
    let record = Map::new();
    let result = FluentBit::new(command).run(Some("function sluice( broken"), &[&record]);
    assert!(result.is_err(), "{result:?}");
}
