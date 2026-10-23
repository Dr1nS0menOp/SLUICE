use serde_json::json;

use super::*;

fn field(name: &str) -> FieldPath {
    FieldPath::new(name)
}

fn variant(names: &[&str]) -> BTreeSet<FieldPath> {
    names.iter().map(|n| field(n)).collect()
}

/// `n` logons of each type, as 4624 records them: `RestrictedAdminMode` is `-` except on type 10.
fn logons(n: usize) -> Vec<Map<String, Value>> {
    let mut events = Vec::new();
    for (i, logon_type) in [2, 3, 10].iter().cycle().take(3 * n).enumerate() {
        let admin = if *logon_type == 10 {
            if i % 2 == 0 { "Yes" } else { "No" }
        } else {
            "-"
        };
        let json = json!({
            "EventID": 4624, "Keywords": "0x8020000000000000", "LogonType": logon_type,
            "RestrictedAdminMode": admin, "TargetUserName": format!("user{i}"),
        });
        if let Value::Object(map) = json {
            events.push(map);
        }
    }
    events
}

fn learned(events: &[Map<String, Value>]) -> Vec<ImpliedValue> {
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&[
        "EventID",
        "Keywords",
        "LogonType",
        "RestrictedAdminMode",
        "TargetUserName",
    ]);
    let event_id = field("EventID");
    learn_template(&[&event_id].into(), std::slice::from_ref(&fields), &refs)
}

fn text(value: &str) -> Literal {
    Literal::Text(value.into())
}

#[test]
fn a_value_every_event_of_the_kind_holds_is_implied_by_the_kind() {
    let values = learned(&logons(30));
    assert!(values.contains(&ImpliedValue {
        field: field("Keywords"),
        value: text("0x8020000000000000"),
        when: None,
    }));
}

#[test]
fn a_placeholder_another_field_implies_is_learned_with_that_field() {
    let values = learned(&logons(30));
    let admin: Vec<&ImpliedValue> = values
        .iter()
        .filter(|v| v.field == field("RestrictedAdminMode"))
        .collect();
    assert_eq!(
        admin.len(),
        2,
        "types 2 and 3 imply `-`; type 10 varies: {admin:?}"
    );
    for implied in admin {
        assert_eq!(implied.value, text("-"));
        let (on, value) = implied.when.as_ref().expect("a condition");
        assert_eq!(on, &field("LogonType"));
        assert!(matches!(value, Literal::Integer(2 | 3)));
    }
}

#[test]
fn the_field_that_names_the_kind_of_event_is_never_implied() {
    let values = learned(&logons(30));
    assert!(values.iter().all(|v| v.field != field("EventID")));
}

#[test]
fn a_field_that_implies_another_is_never_removed() {
    let values = learned(&logons(30));
    let implying: BTreeSet<&FieldPath> = values
        .iter()
        .filter_map(|v| v.when.as_ref().map(|(on, _)| on))
        .collect();
    assert!(values.iter().all(|v| !implying.contains(&v.field)));
}

#[test]
fn too_few_events_per_value_imply_nothing() {
    let values = learned(&logons(MIN_SUPPORT - 1));
    assert!(
        values.iter().all(|v| v.when.is_none()),
        "constants need no support; implications do: {values:?}"
    );
}

#[test]
fn a_field_some_variant_lacks_is_never_implied() {
    let events = logons(30);
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let with = variant(&[
        "Keywords",
        "LogonType",
        "RestrictedAdminMode",
        "TargetUserName",
    ]);
    let without = variant(&["LogonType", "RestrictedAdminMode", "TargetUserName"]);
    let values = learn_template(&BTreeSet::new(), &[with, without], &refs);
    assert!(values.iter().all(|v| v.field != field("Keywords")));
}

#[test]
fn values_that_are_not_a_bool_an_integer_or_a_string_are_never_implied() {
    let events: Vec<Map<String, Value>> = (0..40)
        .filter_map(
            |_| match json!({"Ratio": 0.5, "List": [1], "Obj": {"a": 1}, "Null": null}) {
                Value::Object(map) => Some(map),
                _ => None,
            },
        )
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&["Ratio", "List", "Obj", "Null"]);
    assert_eq!(
        learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs),
        []
    );
}

#[test]
fn an_integer_and_the_string_of_it_are_different_values() {
    assert_ne!(Literal::of(&json!(0)), Literal::of(&json!("0")));
    assert_eq!(Literal::of(&json!(0)), Some(Literal::Integer(0)));
    assert_eq!(Literal::of(&json!(0.5)), None);
}

#[test]
fn nested_fields_are_found_by_their_path() {
    let event = json!({"event_data": {"LogonType": 3}});
    let Value::Object(map) = event else {
        unreachable!("an object")
    };
    assert_eq!(
        lookup(&map, &field("event_data.LogonType")),
        Some(&json!(3))
    );
    assert_eq!(lookup(&map, &field("event_data.Missing")), None);
}

#[test]
fn an_identifier_that_keeps_bringing_new_values_implies_nothing() {
    // `ThreadId` has few values, each with enough events, and `ObjectType` follows it on this
    // sample; but the later half brings threads the earlier half never saw.
    let events: Vec<Map<String, Value>> = (0..120)
        .filter_map(|i| {
            let thread = if i < 60 { i % 2 } else { 2 + i % 2 };
            match json!({"ThreadId": thread, "ObjectType": format!("type{thread}")}) {
                Value::Object(map) => Some(map),
                _ => None,
            }
        })
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&["ThreadId", "ObjectType"]);
    assert_eq!(
        learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs),
        []
    );
}

#[test]
fn a_category_repeats_its_values_and_an_identifier_does_not() {
    let values = |v: &[i64]| v.iter().map(|i| Literal::Integer(*i)).collect::<Vec<_>>();
    assert!(closed(&values(&[2, 3, 2, 3, 3, 2])));
    assert!(!closed(&values(&[1, 2, 3, 4, 5, 6])));
}

#[test]
fn columns_the_workspace_adds_itself_are_never_learned() {
    for column in ["Type", "TenantId", "_ResourceId", "_ItemId"] {
        assert!(workspace_column(&field(column)), "{column}");
    }
    for column in ["Keywords", "EventSourceName", "Computer"] {
        assert!(!workspace_column(&field(column)), "{column}");
    }
}

#[test]
fn a_field_named_as_an_identifier_never_implies_another() {
    for name in [
        "SystemThreadId",
        "SubjectLogonId",
        "LogonGuid",
        "event_data.process_id",
    ] {
        assert!(identifier(&field(name)), "{name}");
    }
    for name in ["LogonType", "Account", "AuthenticationPackageName", "Valid"] {
        assert!(!identifier(&field(name)), "{name}");
    }
}
