use sluice_core::field::FieldPath;
use sluice_core::guard::EffectiveRecipe;
use sluice_core::recipe::ImpliedValue;
use sluice_core::template::Template;

use super::*;

fn template(id: &str, columns: &[&str]) -> Template {
    serde_json::from_value(serde_json::json!({
        "id": id, "source": "s", "logsource": {}, "pattern": "p",
        "shape": {"kind": "keyset", "discriminators": [["EventID", "4624"]],
                  "paths": columns, "variants": [columns]},
        "fields": columns, "text_fields": [],
        "stats": {"events": 1000, "bytes": 1, "source_events": 1000}
    }))
    .expect("a template")
}

fn recipe(id: &str, values: Vec<ImpliedValue>) -> EffectiveRecipe {
    EffectiveRecipe {
        drop_implied: values,
        ..EffectiveRecipe::passthrough(id.into())
    }
}

fn value_of(field: &str, value: Literal, when: Option<(&str, Literal)>) -> ImpliedValue {
    ImpliedValue {
        field: FieldPath::new(field),
        value,
        when: when.map(|(on, v)| (FieldPath::new(on), v)),
    }
}

const COLUMNS: [&str; 4] = ["EventID", "Keywords", "LogonType", "RestrictedAdminMode"];

fn types() -> BTreeMap<&'static str, &'static str> {
    [
        ("EventID", "int"),
        ("Keywords", "string"),
        ("LogonType", "int"),
        ("RestrictedAdminMode", "string"),
    ]
    .into()
}

fn discriminators() -> BTreeMap<String, String> {
    [("EventID".to_owned(), "4624".to_owned())].into()
}

fn values() -> Vec<ImpliedValue> {
    vec![
        value_of("Keywords", Literal::Text("0x8020000000000000".into()), None),
        value_of(
            "RestrictedAdminMode",
            Literal::Text("-".into()),
            Some(("LogonType", Literal::Integer(3))),
        ),
        value_of("EventID", Literal::Integer(4624), None),
        value_of("Keywords", Literal::Text(String::new()), None),
    ]
}

#[test]
fn whole_columns_with_a_value_and_no_discriminator_are_emptied() {
    let t = template("t", &COLUMNS);
    let r = recipe("t", values());
    let plans = [Plan {
        template: &t,
        recipe: &r,
    }];
    let mut left_out = Vec::new();
    let kept = implied(
        &plans[0],
        &discriminators(),
        &types(),
        &plans,
        &mut left_out,
    );
    let columns: Vec<&str> = kept.iter().map(|v| v.column.as_str()).collect();
    assert_eq!(columns, ["Keywords", "RestrictedAdminMode"]);
    assert_eq!(
        left_out.len(),
        2,
        "the discriminator and the empty value: {left_out:?}"
    );
}

#[test]
fn a_kind_of_event_without_the_column_keeps_it_on_every_kind_with_its_event_id() {
    // Another template of 4624 lacks `RestrictedAdminMode`: once emptied, the function could
    // not tell its records from those where it was emptied.
    let t = template("t", &COLUMNS);
    let other = template("u", &["EventID", "Keywords", "LogonType"]);
    let r = recipe("t", values());
    let none = EffectiveRecipe::passthrough("u".into());
    let plans = [
        Plan {
            template: &t,
            recipe: &r,
        },
        Plan {
            template: &other,
            recipe: &none,
        },
    ];
    let mut left_out = Vec::new();
    let kept = implied(
        &plans[0],
        &discriminators(),
        &types(),
        &plans,
        &mut left_out,
    );
    assert!(kept.iter().all(|v| v.column != "RestrictedAdminMode"));
    assert!(left_out.iter().any(|l| l.contains("RestrictedAdminMode")));
}

#[test]
fn the_test_compares_the_column_and_its_condition_as_text() {
    let value = Rebuilt {
        column: "RestrictedAdminMode".into(),
        kind: "string".into(),
        value: "-".into(),
        discriminators: discriminators(),
        when: Some(("LogonType".into(), "3".into())),
    };
    assert_eq!(
        holds(&value),
        r#"tostring(['RestrictedAdminMode']) == "-" and tostring(['LogonType']) == "3""#
    );
}

#[test]
fn the_function_puts_each_implied_value_back_where_its_column_is_empty() {
    let rebuilt = [
        Rebuilt {
            column: "Keywords".into(),
            kind: "string".into(),
            value: "0x8020000000000000".into(),
            discriminators: discriminators(),
            when: None,
        },
        Rebuilt {
            column: "LogonType".into(),
            kind: "int".into(),
            value: "3".into(),
            discriminators: discriminators(),
            when: None,
        },
    ];
    let kql = function(&Table::SecurityEvent, &rebuilt).expect("a function");
    assert!(kql.contains("named SecurityEventFull"));
    assert!(kql.contains("\nSecurityEvent\n"));
    assert!(kql.contains(
        r#"| extend ['Keywords'] = case(isempty(tostring(['Keywords'])) and tostring(['EventID']) == "4624", "0x8020000000000000", ['Keywords'])"#
    ));
    assert!(kql.contains(r#", toint("3"), ['LogonType'])"#));
    assert_eq!(function(&Table::SecurityEvent, &[]), None);
}

#[test]
fn a_guid_column_and_its_value_are_read_as_text_which_holds_for_either_type() {
    // Found in a workspace: the tables API lists `LogonGuid` as `guid`, a query reads it as a
    // `string`, and `case` refused a `toguid(…)` value for it ("return types are not
    // compatible"). Text on both sides runs on a `string` column and on a `guid` one.
    let rebuilt = [Rebuilt {
        column: "LogonGuid".into(),
        kind: "guid".into(),
        value: "00000000-0000-0000-0000-000000000000".into(),
        discriminators: discriminators(),
        when: None,
    }];
    let kql = function(&Table::SecurityEvent, &rebuilt).expect("a function");
    assert!(
        kql.contains(r#", "00000000-0000-0000-0000-000000000000", tostring(['LogonGuid']))"#),
        "{kql}"
    );
}

/// In the Kusto emulator (`SLUICE_KUSTO_URL`), on a table with the types the tables API lists
/// (`LogonGuid` a `guid`; a workspace reads it as a `string`, which `try-dcr-implied.sh`
/// covers): the function runs, and puts the value back where it was emptied, and only there.
#[test]
fn c1_in_the_kql_engine_the_function_runs_on_the_table_and_puts_a_guid_back() {
    use serde_json::{Value, json};
    use sluice_core::event::{Event, Timestamp};
    use sluice_core::ids::{EventId, SourceId};

    let Ok(url) = std::env::var("SLUICE_KUSTO_URL") else {
        return;
    };
    let zero = "00000000-0000-0000-0000-000000000000";
    let rebuilt = [Rebuilt {
        column: "LogonGuid".into(),
        kind: "string".into(),
        value: zero.into(),
        discriminators: discriminators(),
        when: None,
    }];
    let record = |event_id: i64, guid: Option<&str>, label: &str| {
        let mut fields = json!({"EventID": event_id, "Activity": label});
        if let Some(guid) = guid {
            fields["LogonGuid"] = json!(guid);
        }
        Event {
            id: EventId(0),
            timestamp: Timestamp(0),
            source: SourceId::new("SecurityEvent"),
            fields: fields.as_object().expect("an object").clone(),
        }
    };
    let events = [
        record(4624, None, "emptied"),
        record(4624, Some("11111111-2222-3333-4444-555555555555"), "kept"),
        record(4625, None, "other event"),
    ];
    let client = crate::engine::Client::new(&url);
    let database = crate::engine::Database::create(&client, &[]).expect("a database");
    database
        .load(&Table::SecurityEvent, &events.iter().collect::<Vec<_>>())
        .expect("loads");
    let kql = function(&Table::SecurityEvent, &rebuilt).expect("a function");
    let query = kql + "| project Activity, LogonGuid = tostring(LogonGuid)";
    let rows = database
        .query(&query)
        .expect("the function runs on the table");
    let mut seen: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let row: Value = serde_json::from_str(row).expect("a row");
            (
                row[1][0].as_str().unwrap_or_default().to_owned(),
                row[1][1].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        [
            ("emptied".to_owned(), zero.to_owned()),
            (
                "kept".to_owned(),
                "11111111-2222-3333-4444-555555555555".to_owned()
            ),
            ("other event".to_owned(), String::new()),
        ]
    );
}

#[test]
fn a_value_is_written_as_a_literal_of_its_columns_type() {
    assert_eq!(typed("string", "-"), r#""-""#);
    assert_eq!(typed("bool", "true"), r#"tobool("true")"#);
    assert_eq!(typed("boolean", "true"), r#"tobool("true")"#);
    assert_eq!(typed("int", "3"), r#"toint("3")"#);
    assert_eq!(typed("long", "3"), r#"tolong("3")"#);
    assert_eq!(typed("real", "0.5"), r#"toreal("0.5")"#);
    assert_eq!(
        typed("datetime", "2026-10-24T00:00:00Z"),
        r#"todatetime("2026-10-24T00:00:00Z")"#
    );
    assert_eq!(typed("dynamic", "[]"), r#"todynamic("[]")"#);
}

#[test]
fn a_column_is_read_as_text_when_the_table_or_the_stream_calls_it_a_guid() {
    let zero = "00000000-0000-0000-0000-000000000000";
    let rebuilt = |column: &str, kind: &str| Rebuilt {
        column: column.into(),
        kind: kind.into(),
        value: zero.into(),
        discriminators: discriminators(),
        when: None,
    };
    let text = format!(r#", "{zero}", tostring(['LogonGuid']))"#);
    // The table says `guid`, the stream `string`.
    let kql = function(&Table::SecurityEvent, &[rebuilt("LogonGuid", "string")]).expect("one");
    assert!(kql.contains(&text), "{kql}");
    // The table does not know the column; the stream says `guid`.
    let kql = function(&Table::SecurityEvent, &[rebuilt("Unlisted", "guid")]).expect("one");
    assert!(
        kql.contains(&format!(r#", "{zero}", tostring(['Unlisted']))"#)),
        "{kql}"
    );
    // A string column stays a string column.
    let kql = function(&Table::SecurityEvent, &[rebuilt("Keywords", "string")]).expect("one");
    assert!(
        kql.contains(&format!(r#", "{zero}", ['Keywords'])"#)),
        "{kql}"
    );
}

#[test]
fn a_value_implied_by_a_field_that_is_not_a_whole_column_is_left_in_place() {
    let t = template("t", &COLUMNS);
    let mut types = types();
    types.insert("event.code", "string");
    for (on, value) in [
        // Not a column of the stream.
        ("Missing", Literal::Integer(3)),
        // A path into a column, not a column.
        ("event.code", Literal::Text("x".into())),
        // A value no KQL literal Sluice writes can carry.
        ("LogonType", Literal::Text("\u{1}".into())),
    ] {
        let r = recipe(
            "t",
            vec![value_of(
                "RestrictedAdminMode",
                Literal::Text("-".into()),
                Some((on, value)),
            )],
        );
        let plans = [Plan {
            template: &t,
            recipe: &r,
        }];
        let mut left_out = Vec::new();
        let kept = implied(&plans[0], &discriminators(), &types, &plans, &mut left_out);
        assert!(kept.is_empty(), "implied by {on}: {kept:?}");
        assert!(
            left_out
                .iter()
                .any(|l| l.contains("is implied by a field that is not a whole column")),
            "{on}: {left_out:?}"
        );
    }
}
