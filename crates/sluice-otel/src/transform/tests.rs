use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sluice_core::event::{Event, Timestamp};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::{EventId, SourceId};
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::template::{LineHeader, Template, TemplateShape, TemplateStats};

use super::*;
use crate::Collector;

/// The command that runs the collector (`scripts/otel-check.sh` sets it).
const ENV: &str = "SLUICE_OTEL_COLLECTOR";

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

fn of(plans: &[(&Template, &EffectiveRecipe)]) -> Statements {
    let plans: Vec<TransformPlan<'_>> = plans
        .iter()
        .map(|(template, recipe)| TransformPlan { template, recipe })
        .collect();
    transform(&plans)
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

/// Takes the records with an IP of [`logon`] first: its id sorts before.
fn overlapping() -> Template {
    template(
        "windows:1:a",
        &[],
        &[&["EventID", "Message", "User", "Host.name", "Ip"]],
    )
}

#[test]
fn a_plan_that_removes_nothing_has_no_statements() {
    let t = logon();
    let unchanged = of(&[(&t, &EffectiveRecipe::passthrough(t.id.clone()))]);
    assert!(unchanged.statements.is_empty() && unchanged.templates.is_empty());
    assert_eq!(of(&[]).statements, Vec::<String>::new());
}

#[test]
fn a_removal_decides_everything_before_it_removes() {
    let t = logon();
    let recipe = removing(t.id.as_str(), &["Message"], Some(eq("User", "Admin")));
    let out = of(&[(&t, &recipe)]);
    assert_eq!(out.templates, [t.id.clone()].into());
    assert_eq!(out.fields, paths(&["Message"]));
    let at = |prefix: &str| {
        out.statements
            .iter()
            .position(|s| s.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix}: {:#?}", out.statements))
    };
    let prepare = at("set(log.cache[\"sluice_p0\"], log.body)");
    let classify = at("set(log.cache[\"sluice_t\"], 0)");
    let keep = at("set(log.cache[\"sluice_k0\"], true)");
    let decide = at("set(log.cache[\"sluice_a\"], 0)");
    let remove = at("delete_key(log.body, \"Message\")");
    assert!(prepare < classify && classify < keep && keep < decide && decide < remove);
    assert!(
        out.statements[keep + 1].starts_with("set(log.cache[\"sluice_k0\"], false) where"),
        "kept unless its test is false: {:#?}",
        out.statements
    );
    let recognition = &out.statements[classify];
    assert!(recognition.contains("Len(log.body) == 4"), "{recognition}");
    assert!(
        recognition.contains("Len(log.body[\"Host\"]) == 1"),
        "{recognition}"
    );
    assert!(
        recognition.contains("Len(log.cache[\"sluice_p0\"]) == 0"),
        "{recognition}"
    );
    assert!(
        out.statements.iter().any(|s| s.starts_with(
            r#"delete_matching_keys(log.cache["sluice_p0"], "^(?:EventID|Host|Message|User)$")"#
        )),
        "{:#?}",
        out.statements
    );
    assert!(
        recognition.contains(r#"(log.body["EventID"] == "4624" or log.body["EventID"] == 4624)"#),
        "{recognition}"
    );
    assert!(out.statements[decide].contains("not (log.cache[\"sluice_k0\"] == true)"));
    assert!(out.statements[remove].ends_with("log.cache[\"sluice_a\"] == 0"));
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
    let joined = out.statements.join("\n");
    assert!(
        joined.contains("set(log.cache[\"sluice_t\"], 1)"),
        "{joined}"
    );
    assert!(
        !joined.contains("set(log.cache[\"sluice_t\"], 2)"),
        "{joined}"
    );
    assert!(out.left_out.iter().any(|r| r.contains("counting")));
    assert_eq!(out.templates, [removed.id.clone()].into());
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
    assert_eq!(out.statements, Vec::<String>::new());
    assert_eq!(out.left_out.len(), 1, "{:?}", out.left_out);
}

#[test]
fn the_processor_quotes_every_statement_for_yaml() {
    let yaml = processor("sluice_windows", &["set(x, \"it's\")".to_owned()]);
    assert!(yaml.contains("transform/sluice_windows:\n    error_mode: ignore"));
    assert!(yaml.contains("- 'set(x, \"it''s\")'"), "{yaml}");
}

#[test]
fn discriminators_match_the_text_or_the_value_it_spells() {
    assert_eq!(discriminator("x", "abc"), r#"x == "abc""#);
    assert_eq!(discriminator("x", "-12"), r#"(x == "-12" or x == -12)"#);
    assert_eq!(discriminator("x", "true"), r#"(x == "true" or x == true)"#);
    assert_eq!(discriminator("x", "012"), r#"x == "012""#);
    assert_eq!(discriminator("x", "1.5"), r#"x == "1.5""#);
    // `== 0` would also take `-0.0`, which VRL renders as `-0`.
    assert_eq!(discriminator("x", "0"), r#"x == "0""#);
}

/// A template whose discriminator is a number OTTL does not compare (`0.5`), and a later one of
/// the same key set that removes `Status`.
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
    let position = |prefix: &str| {
        out.statements
            .iter()
            .position(|s| s.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix}: {:#?}", out.statements))
    };
    let claim = position(r#"set(log.cache["sluice_t"], 0)"#);
    let stop = position(r#"set(log.cache["sluice_t"], -1) where log.cache["sluice_t"] == nil and"#);
    let taken = position(r#"set(log.cache["sluice_t"], 1)"#);
    assert!(claim < stop && stop < taken, "{:#?}", out.statements);
    assert!(
        out.statements[stop].ends_with(
            r#"(log.body["EventID"] == "0.5" or (IsInt(log.body["EventID"]) or IsDouble(log.body["EventID"])))"#
        ),
        "{}",
        out.statements[stop]
    );
    // Values OTTL compares as VRL renders them need no stop.
    let t = logon();
    let plain = of(&[(&t, &removing(t.id.as_str(), &["Message"], None))]);
    assert!(!plain.statements.iter().any(|s| s.contains(", -1)")));
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

/// Each leaf path with its value; an emptied object is a leaf of its own.
fn leaf_values(record: &Map<String, Value>) -> BTreeMap<String, Value> {
    fn walk(prefix: String, value: &Value, out: &mut BTreeMap<String, Value>) {
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
    let mut out = BTreeMap::new();
    for (key, value) in record {
        walk(key.clone(), value, &mut out);
    }
    out
}

/// The leaf paths of a record, as VRL's `flatten` makes them.
fn leaves(record: &Map<String, Value>) -> BTreeSet<String> {
    leaf_values(record)
        .into_iter()
        .filter(|(_, v)| *v != json!({}))
        .map(|(k, _)| k)
        .collect()
}

/// Records across the edges of recognition, each with whether OTTL cannot decide as VRL does
/// and keeps the record whole.
fn edge_cases() -> Vec<(Event, bool)> {
    let base = json!({"EventID": 4624, "Message": "An account logged on", "User": "bob",
                      "Host": {"name": "ws1"}});
    let with = |change: &dyn Fn(&mut Value)| {
        let mut fields = base.clone();
        change(&mut fields);
        event(&fields)
    };
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
        (
            with(&|f| f["Host"] = json!({"name": null, "x": null})),
            false,
        ),
        (with(&|f| f["Host"] = json!({"name": ""})), false),
        (with(&|f| f["Host"] = json!("flat")), false),
        (with(&|f| f["User"] = json!(["a", "b"])), true),
        (with(&|f| f["Message"] = json!({"nested": "x"})), false),
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
        (event(&json!({"EventID": 4634, "Other": null})), false),
    ]
}

/// Whether the collector gave the value back: the same, or exactly the same number.
#[allow(clippy::float_cmp, reason = "the number must come back exactly")]
fn same(old: &Value, new: &Value) -> bool {
    old == new || old.as_f64().zip(new.as_f64()).is_some_and(|(a, b)| a == b)
}

/// In a real collector (`SLUICE_OTEL_COLLECTOR`, `scripts/otel-check.sh`): every record loses
/// exactly what it loses in Vector's VRL, across the edges of recognition, and keeps the rest as
/// the collector gives it without the statements. Where OTTL cannot decide, it stays whole.
#[test]
fn c1_in_the_collector_records_lose_exactly_what_they_lose_in_vector() {
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
    let collector = Collector::new(command);
    let baseline = collector.run(None, &records).expect("the collector runs");
    let actual = collector
        .run(Some(&out.statements), &records)
        .unwrap_or_else(|e| panic!("{e}\n{:#?}", out.statements));
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
}

/// In a real collector: a record whose discriminator OTTL does not compare as VRL renders it
/// stays whole, never handed to a later template of the same key set. OTTL cannot render a
/// number, so the stop takes any number there.
#[test]
fn c1_in_the_collector_a_record_an_earlier_template_cannot_decide_stays_whole() {
    let Ok(command) = std::env::var(ENV) else {
        return;
    };
    let [(undecided, unchanged), (later, recipe)] = undecided_then_later();
    let plans = [(&undecided, &unchanged), (&later, &recipe)];
    // `true`: kept whole, where Vector removes `Status`.
    let cases = [
        (event(&json!({"EventID": 0.5, "Status": "ok"})), false),
        (event(&json!({"EventID": 0.25, "Status": "ok"})), true),
        (event(&json!({"EventID": 7, "Status": "ok"})), true),
        (event(&json!({"EventID": "7", "Status": "ok"})), false),
    ];
    let events: Vec<Event> = cases.iter().map(|(e, _)| e.clone()).collect();
    let expected = vrl(&plans, &events);
    let out = of(&plans);
    let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
    let collector = Collector::new(command);
    let baseline = collector.run(None, &records).expect("the collector runs");
    let actual = collector
        .run(Some(&out.statements), &records)
        .unwrap_or_else(|e| panic!("{e}\n{:#?}", out.statements));
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

/// A statement the collector refuses is an error, not statements that pass everything.
#[test]
fn statements_that_do_not_parse_are_refused() {
    let Ok(command) = std::env::var(ENV) else {
        return;
    };
    let record = Map::new();
    let result = Collector::new(command).run(Some(&["set(".to_owned()]), &[&record]);
    assert!(result.is_err(), "{result:?}");
}
