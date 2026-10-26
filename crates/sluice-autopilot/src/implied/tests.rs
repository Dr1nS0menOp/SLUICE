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

#[test]
fn a_field_counts_its_name_four_bytes_of_punctuation_and_its_value_in_json() {
    // `"Keywords":"0x80",`: 8 + 4 + 6.
    assert_eq!(size(&field("Keywords"), &text("0x80")), 18);
    // The last segment only, a number and a boolean as JSON writes them.
    assert_eq!(
        size(&field("event.code"), &Literal::Integer(4624)),
        4 + 4 + 4
    );
    assert_eq!(size(&field("Ok"), &Literal::Bool(false)), 2 + 4 + 5);
    // An escaped quote counts as JSON writes it.
    assert_eq!(size(&field("Q"), &text("a\"b")), 1 + 4 + 6);
}

#[test]
fn an_implication_is_worth_its_events_times_the_bytes_of_the_value() {
    // `Mode` is `-` on 30 events of type 2 and `x` on 25 of type 3; 5 of type 4 are too few.
    let types: Vec<Literal> = [(2, 30), (3, 25), (4, 5)]
        .iter()
        .flat_map(|(t, n)| std::iter::repeat_n(Literal::Integer(*t), *n))
        .collect();
    let modes: Vec<Literal> = [("-", 30), ("x", 25), ("y", 5)]
        .iter()
        .flat_map(|(m, n)| std::iter::repeat_n(text(m), *n))
        .collect();
    // Interleaved, so the later half repeats the earlier half's types.
    let order: Vec<usize> = (0..60).map(|i| (i * 7) % 60).collect();
    let types: Vec<Literal> = order.iter().map(|&i| types[i].clone()).collect();
    let modes: Vec<Literal> = order.iter().map(|&i| modes[i].clone()).collect();
    let (mode, logon_type) = (field("Mode"), field("LogonType"));
    let found = implied_by(&mode, &modes, &logon_type, &types).expect("an implication");
    assert_eq!(
        found.bytes,
        30 * size(&mode, &text("-")) + 25 * size(&mode, &text("x"))
    );
    assert_eq!(found.values.len(), 2, "type 4 has too few events");
}

#[test]
fn a_field_implies_another_only_with_two_to_thirty_two_values() {
    let (mode, on) = (field("Mode"), field("LogonType"));
    let modes = vec![text("-"); 40 * 33];
    // One value is the kind of event's to imply, 33 are no category; both repeat in the later
    // half, so neither is refused for a value that came late.
    let one = vec![Literal::Integer(2); 40 * 33];
    let many: Vec<Literal> = (0..40 * 33).map(|i| Literal::Integer(i % 33)).collect();
    let fewer: Vec<Literal> = (0..40 * 33).map(|i| Literal::Integer(i % 32)).collect();
    assert!(implied_by(&mode, &modes, &on, &one).is_none());
    assert!(implied_by(&mode, &modes, &on, &many).is_none());
    assert!(implied_by(&mode, &modes, &on, &fewer).is_some());
}

#[test]
fn at_most_sixty_four_values_are_learned_per_kind_of_event() {
    let names: Vec<String> = (0..70).map(|i| format!("F{i:02}")).collect();
    let events: Vec<Map<String, Value>> = (0..30)
        .map(|_| names.iter().map(|n| (n.clone(), json!("v"))).collect())
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let values = learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs);
    assert_eq!(values.len(), MAX_PER_TEMPLATE);
}

#[test]
fn of_fields_that_imply_each_other_none_removed_implies_a_removed_one() {
    // `A`, `B` and `C` determine each other; each could be learned as implied by another, but
    // a value is only rebuilt while what implies it is still there.
    let events: Vec<Map<String, Value>> = (0..80)
        .filter_map(|i| {
            let (a, b, c) = if i % 2 == 0 {
                ("a0", "b-zero-long-value", "c0-mid")
            } else {
                ("a1", "b-one-long-value-", "c1-mid")
            };
            match json!({"A": a, "B": b, "C": c}) {
                Value::Object(map) => Some(map),
                _ => None,
            }
        })
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&["A", "B", "C"]);
    let values = learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs);
    assert!(!values.is_empty(), "the longest one is learned");
    let removed: BTreeSet<&FieldPath> = values.iter().map(|v| &v.field).collect();
    for value in &values {
        let (on, _) = value.when.as_ref().expect("implied by another field");
        assert!(
            !removed.contains(on),
            "{value:?} is implied by a removed field"
        );
    }
}

mod learn {
    use sluice_core::event::Timestamp;
    use sluice_core::ids::{EventId, SourceId};
    use sluice_core::template::{Template, TemplateStats};

    use super::*;

    fn template(id: &str, schema: Schema, fields: &[&str], events: u64) -> Template {
        let variant = variant(fields);
        Template {
            id: id.into(),
            source: "s".into(),
            logsource: sluice_core::logsource::LogSource::default(),
            schema,
            pattern: String::new(),
            shape: TemplateShape::Keyset {
                discriminators: vec![(field("EventID"), "1".to_owned())],
                paths: variant.clone(),
                variants: vec![variant.clone()],
            },
            fields: variant,
            text_fields: BTreeSet::new(),
            stats: TemplateStats {
                events,
                bytes: 0,
                source_events: 1_000,
            },
        }
    }

    /// `n` events of `template`, each `{"EventID": 1, "Channel": "Security", "TenantId": "t"}`.
    fn discovery(templates: Vec<Template>, n: u64) -> (Discovery, Vec<Event>) {
        let mut assignments = BTreeMap::new();
        let mut events = Vec::new();
        for template in &templates {
            for _ in 0..n {
                let id = EventId(events.len() as u64);
                assignments.insert(id, template.id.clone());
                let Value::Object(fields) =
                    json!({"EventID": 1, "Channel": "Security", "TenantId": "t"})
                else {
                    unreachable!("an object")
                };
                events.push(Event {
                    id,
                    timestamp: Timestamp(0),
                    source: SourceId::new("s"),
                    fields,
                });
            }
        }
        (
            Discovery {
                templates,
                assignments,
            },
            events,
        )
    }

    const FIELDS: [&str; 3] = ["EventID", "Channel", "TenantId"];

    #[test]
    fn a_frequent_kind_of_event_gets_its_constants_but_never_its_discriminator() {
        let (discovery, events) = discovery(vec![template("t", Schema::Sigma, &FIELDS, 500)], 30);
        let learned = learn(&discovery, &events, GuardrailConfig::default());
        let fields: Vec<&str> = learned[&TemplateId::from("t")]
            .iter()
            .map(|v| v.field.as_str())
            .collect();
        assert_eq!(fields, ["Channel", "TenantId"]);
    }

    #[test]
    fn a_rare_kind_of_event_gets_nothing() {
        let (discovery, events) = discovery(vec![template("t", Schema::Sigma, &FIELDS, 5)], 30);
        assert!(learn(&discovery, &events, GuardrailConfig::default()).is_empty());
    }

    #[test]
    fn read_from_sentinel_the_columns_the_workspace_adds_are_left_alone() {
        let (discovery, events) =
            discovery(vec![template("t", Schema::Sentinel, &FIELDS, 500)], 30);
        let learned = learn(&discovery, &events, GuardrailConfig::default());
        let fields: Vec<&str> = learned[&TemplateId::from("t")]
            .iter()
            .map(|v| v.field.as_str())
            .collect();
        assert_eq!(fields, ["Channel"]);
    }

    #[test]
    fn a_kind_of_event_with_nothing_implied_is_not_listed() {
        // Only the discriminator: nothing to learn.
        let (discovery, events) =
            discovery(vec![template("t", Schema::Sigma, &["EventID"], 500)], 30);
        assert!(learn(&discovery, &events, GuardrailConfig::default()).is_empty());
    }
}

#[test]
fn a_field_another_removed_one_is_implied_by_stays_even_if_what_implies_it_stays_too() {
    // `ObjectName` (largest) is implied by `B` (or `C`; ties go to the first name), so `B` must
    // stay, though `C`, which implies `B`, stays too.
    let events: Vec<Map<String, Value>> = (0..80)
        .filter_map(|i| {
            let (object, b, c) = if i % 2 == 0 {
                ("object-zero-with-a-long-value", "b0-mid", "c0")
            } else {
                ("object-one-with-a-long-value-", "b1-mid", "c1")
            };
            match json!({"ObjectName": object, "B": b, "C": c}) {
                Value::Object(map) => Some(map),
                _ => None,
            }
        })
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&["ObjectName", "B", "C"]);
    let values = learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs);
    let removed: BTreeSet<&str> = values.iter().map(|v| v.field.as_str()).collect();
    assert!(removed.contains("ObjectName"), "{values:?}");
    assert!(
        !removed.contains("B"),
        "`ObjectName` is put back from it: {values:?}"
    );
    assert!(
        values
            .iter()
            .filter(|v| v.field.as_str() == "ObjectName")
            .all(|v| v.when.as_ref().is_some_and(|(on, _)| on.as_str() == "B"))
    );
}

#[test]
fn an_identifier_is_implied_by_the_kind_of_event_but_never_by_another_field() {
    // Per machine, one logging thread through the sample, and a logon ID that is always `0x0`.
    let events: Vec<Map<String, Value>> = (0..80)
        .filter_map(|i| {
            let (computer, thread) = if i % 2 == 0 {
                ("dc01.corp.example", "3063")
            } else {
                ("ws01.corp.example", "1197")
            };
            match json!({"Computer": computer, "ExecutionThreadID": thread,
                         "agent": {"ephemeral_id": format!("{computer}-run-7")},
                         "SubjectLogonId": "0x0"})
            {
                Value::Object(map) => Some(map),
                _ => None,
            }
        })
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&[
        "Computer",
        "ExecutionThreadID",
        "agent.ephemeral_id",
        "SubjectLogonId",
    ]);
    let values = learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs);
    let removed: BTreeSet<&str> = values.iter().map(|v| v.field.as_str()).collect();
    assert_eq!(removed, ["SubjectLogonId"].into(), "{values:?}");
    assert!(values.iter().all(|v| v.when.is_none()));
}

#[test]
fn an_address_or_a_port_is_never_implied_nor_implies_another() {
    // The log collector's address and port, the same on every event, and a host's address per
    // machine: a lab's, not the kind of event's. `Transport` only ends in "port".
    let events: Vec<Map<String, Value>> = (0..80)
        .filter_map(|i| {
            let (host, address) = if i % 2 == 0 {
                ("dc01", "10.0.1.4")
            } else {
                ("ws01", "fe80::1")
            };
            match json!({"Computer": host, "SourceAddress": address, "collector": "10.0.0.9",
                         "port": 60737, "DestinationPort": "445", "Transport": "tcp",
                         "Workstation": format!("{host}-ws")})
            {
                Value::Object(map) => Some(map),
                _ => None,
            }
        })
        .collect();
    let refs: Vec<&Map<String, Value>> = events.iter().collect();
    let fields = variant(&[
        "Computer",
        "SourceAddress",
        "collector",
        "port",
        "DestinationPort",
        "Transport",
        "Workstation",
    ]);
    let values = learn_template(&BTreeSet::new(), std::slice::from_ref(&fields), &refs);
    let removed: BTreeSet<&str> = values.iter().map(|v| v.field.as_str()).collect();
    assert_eq!(removed, ["Transport", "Workstation"].into(), "{values:?}");
    assert!(
        values
            .iter()
            .filter(|v| v.field.as_str() == "Workstation")
            .all(|v| v
                .when
                .as_ref()
                .is_some_and(|(on, _)| on.as_str() == "Computer")),
        "implied by the host's name, never by its address: {values:?}"
    );
    assert!(network(&field("IpPort"), &[]));
    assert!(network(&field("src_port"), &[]));
    assert!(!network(&field("Transport"), &[]));
    assert!(
        !network(&field("Name"), &[text("10.0.0.1"), text("host")]),
        "not every value"
    );
}
