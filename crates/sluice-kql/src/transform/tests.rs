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
    let plans: Vec<Plan<'_>> = plans
        .iter()
        .map(|(template, recipe)| Plan { template, recipe })
        .collect();
    transformation(
        &Table::SecurityEvent,
        &Table::SecurityEvent.column_names(),
        &plans,
    )
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
    // Every column of the one key set is in the signature, in the order of the schema, and a
    // record the keep-whole test matches gets no label.
    assert!(
        out.kql.contains(
            r#"tostring(['EventID']) == "4672" and __sluice_s == "1111" and __sluice_r and not("#
        ),
        "{}",
        out.kql
    );
    assert!(
        out.kql
            .contains(r#"| extend ['EventData'] = iff(__sluice_t == "g0", "", ['EventData'])"#),
        "{}",
        out.kql
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
    assert!(
        out.kql.starts_with(&format!("source\n{SLUICE_PART} = ")),
        "where a later run finds Sluice's part: {}",
        out.kql
    );
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
fn c1_a_record_an_earlier_template_cannot_decide_is_claimed_by_no_later_one() {
    // `LogonGuid` is no text or whole-number column, so the transformation cannot tell this
    // template's records from the later one's, which has the same columns.
    let columns: &[&str] = &["EventID", "Computer", "EventData", "LogonGuid"];
    let undecided = template("SecurityEvent:4624:a", &[("LogonGuid", "x")], &[columns]);
    let later = template("SecurityEvent:4624:b", &[], &[columns]);
    let recipe = removing(later.id.as_str(), &["EventData"], None);
    assert_ne!(
        of(&[(&later, &recipe)]).kql,
        "source",
        "on its own the later template removes EventData"
    );
    let unchanged = EffectiveRecipe::passthrough(undecided.id.clone());
    let both = of(&[(&undecided, &unchanged), (&later, &recipe)]);
    assert_eq!(both.kql, "source");
    assert!(
        both.left_out
            .iter()
            .any(|r| r.contains("not a text or whole-number column")),
        "{:?}",
        both.left_out
    );
    assert!(
        both.left_out
            .iter()
            .any(|r| r.contains("cannot be told apart")),
        "{:?}",
        both.left_out
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
fn a_boolean_column_is_emptied_with_a_bool_null_and_a_type_without_one_is_left_out() {
    let t = template(
        "Custom:1:a",
        &[("EventID", "1")],
        &[&["EventID", "Flag", "Span"]],
    );
    let recipe = removing(t.id.as_str(), &["Flag", "Span"], None);
    let plans = [Plan {
        template: &t,
        recipe: &recipe,
    }];
    let out = transformation_on(
        "Custom_CL",
        &[
            ("EventID", "int"),
            ("Flag", "boolean"),
            ("Span", "timespan"),
        ],
        &["EventID", "Flag", "Span"],
        &plans,
    );
    assert!(out.kql.contains("bool(null), ['Flag'])"), "{}", out.kql);
    assert_eq!(
        disallowed_functions(&out.kql),
        BTreeSet::new(),
        "{}",
        out.kql
    );
    assert_eq!(out.columns, ["Flag".to_owned()].into());
    assert!(
        out.left_out
            .iter()
            .any(|r| r.contains("`Span` is a timespan column")),
        "{:?}",
        out.left_out
    );
}

#[test]
fn no_panic_on_input_a_column_kql_cannot_name_leaves_the_records_as_they_come() {
    let t = template(
        "Custom:1:a",
        &[("EventID", "1")],
        &[&["EventID", "Bad\u{1}Name"]],
    );
    let recipe = removing(t.id.as_str(), &["Bad\u{1}Name"], None);
    let plans = [Plan {
        template: &t,
        recipe: &recipe,
    }];
    let out = transformation_on(
        "Custom_CL",
        &[("EventID", "int"), ("Bad\u{1}Name", "string")],
        &["EventID", "Bad\u{1}Name"],
        &plans,
    );
    assert_eq!(out.kql, "source");
    assert!(out.columns.is_empty() && out.templates.is_empty());
    assert!(
        out.left_out[0].contains("cannot name"),
        "{:?}",
        out.left_out
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
        record("extra column", &|f| f["SubjectUserName"] = json!("alice")),
        record("keep whole", &|f| f["Computer"] = json!("DC01")),
        record("other event", &|f| f["EventID"] = json!(4798)),
        record("missing column", &|f| {
            f.as_object_mut()
                .expect("an object")
                .remove("PrivilegeList");
        }),
    ];
    let client = crate::engine::Client::new(&url);
    let database = crate::engine::Database::create(&client, &[]).expect("a database");
    database
        .load(&Table::SecurityEvent, &events.iter().collect::<Vec<_>>())
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

#[test]
fn only_columns_of_the_stream_are_named_and_a_template_needing_another_is_left_alone() {
    let t = privileges();
    let recipe = removing(
        t.id.as_str(),
        &["EventData"],
        Some(eq("SubjectUserName", "x")),
    );
    let plans = [Plan {
        template: &t,
        recipe: &recipe,
    }];
    let without = |left: &str| -> Vec<&str> {
        Table::SecurityEvent
            .column_names()
            .into_iter()
            .filter(|c| *c != left)
            .collect()
    };
    let out = transformation(&Table::SecurityEvent, &without("SubjectUserName"), &plans);
    assert_ne!(out.kql, "source");
    assert!(
        !out.kql.contains("['SubjectUserName']"),
        "a column the stream lacks: {}",
        out.kql
    );
    assert!(
        !out.kql.contains("columnifexists"),
        "every column read is in the stream"
    );

    let out = transformation(&Table::SecurityEvent, &without("PrivilegeList"), &plans);
    assert_eq!(out.kql, "source", "its records cannot arrive whole");
    assert!(
        out.left_out.iter().any(|r| r.contains("PrivilegeList")),
        "{:?}",
        out.left_out
    );
}

#[test]
fn a_transformation_longer_than_a_rule_takes_removes_nothing() {
    let templates: Vec<Template> = (0..400)
        .map(|n| {
            template(
                &format!("SecurityEvent:{n}:a"),
                &[("EventID", &n.to_string())],
                &[&["EventID", "Computer", "EventData"]],
            )
        })
        .collect();
    let recipes: Vec<EffectiveRecipe> = templates
        .iter()
        .map(|t| removing(t.id.as_str(), &["EventData"], None))
        .collect();
    let plans: Vec<(&Template, &EffectiveRecipe)> = templates.iter().zip(&recipes).collect();
    let out = of(&plans);
    assert_eq!(out.kql, "source");
    assert!(out.columns.is_empty() && out.templates.is_empty());
    assert!(
        out.left_out
            .iter()
            .any(|r| r.contains(&MAX_TRANSFORM_KQL.to_string())),
        "{:?}",
        out.left_out.last()
    );
}

/// A 4624 template whose columns hold `values` as constants (the kind of event implies them
/// alone), and one more implied by `LogonType`.
fn implying(
    values: &[(&str, &str)],
    conditional: Option<(&str, &str)>,
) -> (Template, EffectiveRecipe) {
    use sluice_core::recipe::{ImpliedValue, Literal};
    // The same columns whichever values are implied, so only the values make a difference.
    let columns = [
        "EventID",
        "LogonType",
        "EventSourceName",
        "Activity",
        "Keywords",
        "Channel",
        "RestrictedAdminMode",
    ];
    let t = template("SecurityEvent:4624:i", &[("EventID", "4624")], &[&columns]);
    let mut implied: Vec<ImpliedValue> = values
        .iter()
        .map(|(column, value)| ImpliedValue {
            field: (*column).into(),
            value: Literal::Text((*value).into()),
            when: None,
        })
        .collect();
    implied.extend(conditional.map(|(column, value)| ImpliedValue {
        field: column.into(),
        value: Literal::Text(value.into()),
        when: Some(("LogonType".into(), Literal::Integer(3))),
    }));
    let recipe = EffectiveRecipe {
        drop_implied: implied,
        ..EffectiveRecipe::passthrough(t.id.clone())
    };
    (t, recipe)
}

fn within(plan: &(Template, EffectiveRecipe), budget: usize) -> Transformation {
    let plans = [Plan {
        template: &plan.0,
        recipe: &plan.1,
    }];
    transformation_within(
        &Table::SecurityEvent,
        &Table::SecurityEvent.column_names(),
        &plans,
        budget,
    )
}

#[test]
fn as_many_implied_values_as_fit_go_in_the_most_worthwhile_first() {
    // Longest first; the conditional one, though the longest, comes last.
    let constants = [
        ("EventSourceName", "Microsoft-Windows-Security-Auditing"),
        ("Activity", "4624 - An account was successfully logged on."),
        ("Keywords", "0x8020000000000000"),
        ("Channel", "Security"),
    ];
    let conditional = Some((
        "RestrictedAdminMode",
        "a placeholder longer than every constant value above, by far",
    ));
    let all = implying(&constants, conditional);
    // Ranked: Activity, EventSourceName, Keywords, Channel, then RestrictedAdminMode.
    let ranked = ["Activity", "EventSourceName", "Keywords", "Channel"];
    let length = |k: usize| {
        let first: Vec<(&str, &str)> = ranked[..k]
            .iter()
            .map(|c| {
                *constants
                    .iter()
                    .find(|(name, _)| name == c)
                    .expect("a constant")
            })
            .collect();
        within(&implying(&first, None), MAX_TRANSFORM_KQL).kql.len()
    };
    for k in 1..=ranked.len() {
        let exact = within(&all, length(k));
        let columns: BTreeSet<&str> = exact.implied.iter().map(|v| v.column.as_str()).collect();
        assert_eq!(
            columns,
            ranked[..k].iter().copied().collect(),
            "{k} fit exactly"
        );
        assert!(
            exact
                .left_out
                .iter()
                .any(|l| l.starts_with(&format!("{} of 5 implied values did not fit", 5 - k))),
            "{k}: {:?}",
            exact.left_out
        );
        let short = within(&all, length(k) - 1);
        assert_eq!(short.implied.len(), k - 1, "one character short of {k}");
    }
    let everything = within(&all, MAX_TRANSFORM_KQL);
    assert_eq!(everything.implied.len(), 5);
    assert!(
        everything
            .left_out
            .iter()
            .all(|l| !l.contains("did not fit"))
    );
    // Exactly as long as the budget is still within it.
    let exact = within(&all, everything.kql.len());
    assert_eq!(exact.kql, everything.kql);
}

#[test]
fn a_budget_too_small_for_anything_removes_nothing_and_says_so() {
    let plan = implying(&[("Channel", "Security")], None);
    let out = within(&plan, 3);
    assert_eq!(out.kql, "source");
    assert!(out.templates.is_empty() && out.columns.is_empty());
    assert!(
        out.left_out
            .iter()
            .any(|l| l.contains("more than the 3 left")),
        "{:?}",
        out.left_out
    );
}

#[test]
fn an_empty_dynamic_column_is_also_an_empty_object() {
    assert_eq!(empty("['C']", "string"), "isempty(tostring(['C']))");
    assert_eq!(
        empty("['C']", "dynamic"),
        r#"(isempty(tostring(['C'])) or tostring(['C']) == "{}")"#
    );
}

#[test]
fn many_parts_are_concatenated_in_nested_calls_kusto_takes() {
    let parts = |n: usize| (0..n).map(|i| format!("p{i}")).collect::<Vec<_>>();
    assert_eq!(strcat(&[]), r#""""#);
    assert_eq!(strcat(&parts(1)), "p0");
    assert_eq!(strcat(&parts(3)), "strcat(p0, p1, p2)");
    assert_eq!(
        strcat(&parts(STRCAT_MAX)),
        format!("strcat({})", parts(STRCAT_MAX).join(", "))
    );
    assert_eq!(
        strcat(&parts(STRCAT_MAX + 1)),
        format!(
            "strcat(strcat({}), p{STRCAT_MAX})",
            parts(STRCAT_MAX).join(", ")
        )
    );
}
#[test]
fn a_function_after_a_closed_string_is_still_found() {
    assert_eq!(
        disallowed_functions(r#"source | extend x = "a\"(" | extend y = bag_keys(z)"#),
        ["bag_keys".to_owned()].into()
    );
    assert_eq!(
        disallowed_functions(r#"source | extend x = "bag_keys(y)", z = 'pack_all()'"#),
        BTreeSet::new(),
        "a call inside a string is text"
    );
}
