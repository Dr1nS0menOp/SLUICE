use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::template::{Template, TemplateShape, TemplateStats};

use super::*;

fn paths(names: &[&str]) -> BTreeSet<FieldPath> {
    names.iter().map(|n| FieldPath::from(*n)).collect()
}

fn template(id: &str, discriminators: &[(&str, &str)], variants: &[&[&str]]) -> Template {
    let variants: Vec<BTreeSet<FieldPath>> = variants.iter().map(|v| paths(v)).collect();
    let all: BTreeSet<FieldPath> = variants.iter().flatten().cloned().collect();
    Template {
        id: id.into(),
        source: "SecurityEvent".into(),
        logsource: sluice_core::logsource::LogSource::default(),
        schema: sluice_core::schema::Schema::Sentinel,
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

fn privileges() -> Template {
    template(
        "SecurityEvent:4672:a",
        &[("EventID", "4672")],
        &[&[
            "EventID",
            "Computer",
            "EventData",
            "PrivilegeList",
            "TenantId",
            "TimeGenerated",
        ]],
    )
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

fn of(plans: &[(&Template, &EffectiveRecipe)]) -> Transformation {
    let plans: Vec<TransformPlan<'_>> = plans
        .iter()
        .map(|(template, recipe)| TransformPlan { template, recipe })
        .collect();
    transformation(Table::SecurityEvent, &plans)
}

#[test]
fn a_plan_that_removes_nothing_leaves_the_records_as_they_come() {
    let t = privileges();
    let unchanged = of(&[(&t, &EffectiveRecipe::passthrough(t.id.clone()))]);
    assert_eq!(unchanged.kql, "source");
    assert!(unchanged.columns.is_empty() && unchanged.templates.is_empty());
    assert_eq!(of(&[]).kql, "source");
}

#[test]
fn a_column_is_emptied_only_on_records_of_its_template_outside_keep_whole() {
    let t = privileges();
    let recipe = removing(t.id.as_str(), &["EventData"], Some(eq("Computer", "dc01")));
    let out = of(&[(&t, &recipe)]);
    assert_eq!(out.columns, ["EventData".to_owned()].into());
    assert_eq!(out.templates, [t.id.clone()].into());
    // Every column of the one key set is in the signature, in the order of the schema.
    assert!(
        out.kql.contains(
            r#"tostring(['EventID']) == "4672" and __sluice_s == "1111" and __sluice_r, "g0""#
        ),
        "{}",
        out.kql
    );
    assert!(
        out.kql
            .contains(r#"| extend ['EventData'] = iff((__sluice_t == "g0" and not("#)
    );
    assert!(
        out.kql.contains(r#"=~ "dc01""#),
        "the keep-whole test: {}",
        out.kql
    );
    assert!(
        out.kql
            .ends_with("| project-away __sluice_s, __sluice_r, __sluice_t")
    );
    assert!(out.left_out.is_empty(), "{:?}", out.left_out);
}

#[test]
fn service_columns_are_not_part_of_the_signature() {
    let with = privileges();
    let without = template(
        "SecurityEvent:4672:a",
        &[("EventID", "4672")],
        &[&["EventID", "Computer", "EventData", "PrivilegeList"]],
    );
    let recipe = removing(with.id.as_str(), &["EventData"], None);
    assert_eq!(of(&[(&with, &recipe)]).kql, of(&[(&without, &recipe)]).kql);
}

#[test]
fn what_a_transformation_cannot_do_is_left_to_a_pipeline_tool() {
    let t = privileges();
    let recipe = EffectiveRecipe {
        route: Route::ForwardMatching {
            prefilter: Predicate::Always,
            summary_keys: vec!["Computer".into()],
        },
        ..removing(
            t.id.as_str(),
            &["EventData", "Nested.Field", "NoSuchColumn", "EventID"],
            None,
        )
    };
    let out = of(&[(&t, &recipe)]);
    assert_eq!(
        out.columns,
        ["EventData".to_owned()].into(),
        "the whole column still goes"
    );
    for reason in ["counting", "`EventID`"] {
        assert!(
            out.left_out.iter().any(|r| r.contains(reason)),
            "{reason}: {:?}",
            out.left_out
        );
    }
    // Fields no record of the template has are nothing to remove, and nothing to report.
    assert_eq!(out.left_out.len(), 2, "{:?}", out.left_out);
}

#[test]
fn templates_that_cannot_be_recognised_by_their_columns_keep_every_column() {
    let text = Template {
        shape: TemplateShape::Text {
            field: "EventData".into(),
            header: sluice_core::template::LineHeader::None,
            tokens: vec!["x".into()],
        },
        ..privileges()
    };
    let by_time = template("t2", &[("TimeCreated", "x")], &[&["EventID"]]);
    let unknown = template("t3", &[("EventID", "1")], &[&["EventID", "Nested.Field"]]);
    let control = template("t4", &[("EventID", "\u{1}")], &[&["EventID"]]);
    for t in [&text, &by_time, &unknown, &control] {
        let recipe = removing(t.id.as_str(), &["EventData"], None);
        let out = of(&[(t, &recipe)]);
        assert_eq!(out.kql, "source", "{}", t.id);
        assert_eq!(out.left_out.len(), 1, "{}: {:?}", t.id, out.left_out);
    }
}

#[test]
fn templates_with_the_same_columns_remove_only_what_all_remove_and_keep_where_any_keeps() {
    let a = privileges();
    let b = template(
        "SecurityEvent:4672:b",
        &[("EventID", "4672")],
        &[&["EventID", "Computer", "EventData", "PrivilegeList"]],
    );
    let ra = removing(
        a.id.as_str(),
        &["EventData", "PrivilegeList"],
        Some(eq("Computer", "one")),
    );
    let rb = removing(b.id.as_str(), &["EventData"], Some(eq("Computer", "two")));
    let out = of(&[(&a, &ra), (&b, &rb)]);
    assert_eq!(out.columns, ["EventData".to_owned()].into());
    assert!(
        out.kql.contains(r#""one""#) && out.kql.contains(r#""two""#),
        "{}",
        out.kql
    );
    assert_eq!(
        out.kql.matches("__sluice_s ==").count(),
        1,
        "one group: {}",
        out.kql
    );
}

#[test]
fn templates_told_apart_by_columns_or_values_each_keep_their_own_removals() {
    let a = privileges();
    let other_columns = template(
        "SecurityEvent:4672:c",
        &[("EventID", "4672")],
        &[&["EventID", "Computer", "EventData"]],
    );
    let other_value = template(
        "SecurityEvent:4798:a",
        &[("EventID", "4798")],
        &[&["EventID", "Computer", "EventData", "PrivilegeList"]],
    );
    let ra = removing(a.id.as_str(), &["PrivilegeList"], None);
    let rc = removing(other_columns.id.as_str(), &["EventData"], None);
    let rv = removing(other_value.id.as_str(), &["EventData"], None);
    let out = of(&[(&a, &ra), (&other_columns, &rc), (&other_value, &rv)]);
    assert_eq!(
        out.columns,
        ["EventData".to_owned(), "PrivilegeList".to_owned()].into()
    );
    assert_eq!(out.kql.matches("__sluice_s ==").count(), 3, "{}", out.kql);
}

#[test]
fn a_record_that_could_fit_two_templates_is_left_alone() {
    let by_id = privileges();
    let by_channel = template(
        "SecurityEvent:x",
        &[("Channel", "Security")],
        &[&[
            "EventID",
            "Computer",
            "EventData",
            "PrivilegeList",
            "TenantId",
        ]],
    );
    let ra = removing(by_id.id.as_str(), &["EventData"], None);
    let rb = removing(by_channel.id.as_str(), &["PrivilegeList"], None);
    let out = of(&[(&by_id, &ra), (&by_channel, &rb)]);
    assert_eq!(out.kql, "source");
    assert!(
        out.left_out
            .iter()
            .any(|r| r.contains("cannot be told apart"))
    );
}

#[test]
fn typed_columns_are_emptied_with_a_null_of_their_type() {
    let t = template(
        "SecurityEvent:4624:a",
        &[("EventID", "4624")],
        &[&["EventID", "LogonType", "LogonGuid"]],
    );
    let recipe = removing(t.id.as_str(), &["LogonType", "LogonGuid"], None);
    let out = of(&[(&t, &recipe)]);
    assert!(out.kql.contains("int(null), ['LogonType'])"), "{}", out.kql);
    assert!(
        out.kql.contains("guid(null), ['LogonGuid'])"),
        "{}",
        out.kql
    );
}

#[test]
fn every_function_a_transformation_calls_is_one_dcrs_accept() {
    let t = privileges();
    let keywords = Predicate::Keywords(sluice_core::predicate::KeywordTest {
        values: vec!["mimikatz".into()],
        case_sensitive: false,
    });
    let recipe = removing(
        t.id.as_str(),
        &["EventData"],
        Some(Predicate::any([eq("Computer", "dc01"), keywords])),
    );
    let out = of(&[(&t, &recipe)]);
    assert!(
        disallowed_functions(&out.kql).is_empty(),
        "{:?}",
        disallowed_functions(&out.kql)
    );
    assert_eq!(
        disallowed_functions(
            r#"source | extend x = bag_remove_keys(y, "a(") | extend z = pack_all()"#
        ),
        ["bag_remove_keys".to_owned(), "pack_all".to_owned()].into()
    );
}

/// In the Kusto emulator (`SLUICE_KUSTO_URL`, as `tests/emulator.rs`): a column is emptied on
/// exactly the records of its template outside keep-whole, and every other record keeps it.
#[test]
fn c1_in_the_kql_engine_only_records_of_the_template_lose_the_column() {
    use serde_json::{Value, json};
    use sluice_core::event::{Event, Timestamp};
    use sluice_core::ids::{EventId, SourceId};

    let Ok(url) = std::env::var("SLUICE_KUSTO_URL") else {
        return;
    };
    let t = template(
        "SecurityEvent:4672:a",
        &[("EventID", "4672")],
        &[&[
            "EventID",
            "Activity",
            "Computer",
            "EventData",
            "PrivilegeList",
        ]],
    );
    let recipe = removing(t.id.as_str(), &["EventData"], Some(eq("Computer", "dc01")));
    let out = of(&[(&t, &recipe)]);
    let base =
        json!({"EventID": 4672, "Computer": "ws1", "EventData": "<xml/>", "PrivilegeList": "SeX"});
    let record = |label: &str, change: &dyn Fn(&mut Value)| {
        let mut fields = base.clone();
        fields["Activity"] = json!(label);
        change(&mut fields);
        Event {
            id: EventId(0),
            timestamp: Timestamp(0),
            source: SourceId::new("SecurityEvent"),
            fields: fields.as_object().expect("an object").clone(),
        }
    };
    let events = [
        record("template", &|_| {}),
        record("extra column", &|f| f["SubjectUserName"] = json!("ward")),
        record("keep whole", &|f| f["Computer"] = json!("DC01")),
        record("other event", &|f| f["EventID"] = json!(4798)),
        record("missing column", &|f| {
            f.as_object_mut()
                .expect("an object")
                .remove("PrivilegeList");
        }),
    ];
    let client = crate::engine::Client::new(&url);
    let database = crate::engine::Database::create(&client).expect("a database");
    database
        .load(Table::SecurityEvent, &events.iter().collect::<Vec<_>>())
        .expect("loads");
    let query = out.kql.replacen("source", "SecurityEvent", 1) + "\n| project Activity, EventData";
    let rows = database.query(&query).expect("the transformation runs");
    let mut seen: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let row: Value = serde_json::from_str(row).expect("a row");
            (
                row[1][0].as_str().unwrap().to_owned(),
                row[1][1].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    seen.sort();
    let expected: Vec<(String, String)> = [
        ("extra column", "<xml/>"),
        ("keep whole", "<xml/>"),
        ("missing column", "<xml/>"),
        ("other event", "<xml/>"),
        ("template", ""),
    ]
    .iter()
    .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
    .collect();
    assert_eq!(seen, expected, "{}", out.kql);
}
