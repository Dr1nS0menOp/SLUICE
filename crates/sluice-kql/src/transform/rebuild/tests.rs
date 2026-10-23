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
    let kql = function("SecurityEvent", &rebuilt).expect("a function");
    assert!(kql.contains("named SecurityEventFull"));
    assert!(kql.contains("\nSecurityEvent\n"));
    assert!(kql.contains(
        r#"| extend ['Keywords'] = case(isempty(tostring(['Keywords'])) and tostring(['EventID']) == "4624", "0x8020000000000000", ['Keywords'])"#
    ));
    assert!(kql.contains(r#", toint("3"), ['LogonType'])"#));
    assert_eq!(function("SecurityEvent", &[]), None);
}
