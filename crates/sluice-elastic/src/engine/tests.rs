use serde_json::json;
use sluice_core::event::Timestamp;
use sluice_core::ids::SourceId;

use super::*;

const ENV: &str = "SLUICE_ELASTIC_URL";

#[test]
fn esql_runs_on_the_proof_index_with_its_metadata() {
    assert_eq!(
        from_index(
            "from logs-aws.*, logs-gcp* metadata _id | where a == 1",
            "p"
        ),
        "FROM p metadata _id | where a == 1"
    );
    assert_eq!(from_index("FROM logs-*|WHERE a", "p"), "FROM p|WHERE a");
    assert_eq!(from_index("row a = 1", "p"), "row a = 1");
}

#[test]
fn the_mapping_names_every_leaf_a_rule_reads_as_keyword() {
    let fields: BTreeSet<FieldPath> = [
        "process",
        "process.name",
        "process.name.caseless",
        "source.ip",
        "user.name",
        "a*",
        "b..c",
        "d.",
        "_id",
    ]
    .into_iter()
    .map(FieldPath::from)
    .collect();
    let properties = &mapping(&fields)["properties"];
    assert_eq!(properties["process.name"]["type"], "keyword");
    assert_eq!(
        properties["process.name"]["fields"]["caseless"]["normalizer"],
        "sluice_lowercase"
    );
    assert_eq!(properties["user.name"]["type"], "keyword");
    assert!(properties.get("process").is_none(), "a parent is an object");
    assert_eq!(properties["source.ip"]["type"], "ip");
    for unmappable in ["a*", "b..c", "d.", "_id", "process.name.caseless"] {
        assert!(properties.get(unmappable).is_none(), "{unmappable}");
    }
    assert_eq!(properties["@timestamp"]["type"], "date");
}

#[test]
fn eql_alerts_are_hits_and_the_last_event_of_sequences() {
    let rule = RuleId::new("r");
    let answer = json!({"hits": {
        "events": [{"_id": "3"}],
        "sequences": [{"events": [{"_id": "1"}, {"_id": "2"}]}],
    }});
    let alerts = eql_alerts(&rule, &answer).unwrap();
    let ids: Vec<u64> = alerts.iter().map(|a| a.event.0).collect();
    assert_eq!(ids, [3, 2]);
    assert!(eql_alerts(&rule, &json!({"hits": {"events": [{"_id": "x"}]}})).is_err());
}

#[test]
fn esql_alerts_are_rows_by_content() {
    let rule = RuleId::new("r");
    let answer = json!({"columns": [{"name": "n"}], "values": [[2], [2], [3]]});
    let alerts = esql_alerts(&rule, &answer);
    assert_eq!(alerts.len(), 3, "identical rows stay distinct");
    let again = esql_alerts(
        &rule,
        &json!({"columns": [{"name": "n"}], "values": [[3], [2], [2]]}),
    );
    assert_eq!(
        alerts.iter().collect::<BTreeSet<_>>(),
        again.iter().collect::<BTreeSet<_>>(),
        "order does not matter"
    );
}

#[test]
fn an_event_without_a_timestamp_gets_its_own() {
    let event = Event {
        id: EventId(1),
        timestamp: Timestamp(10),
        source: SourceId::new("s"),
        fields: json!({"a": 1}).as_object().unwrap().clone(),
    };
    assert_eq!(document(&event)["@timestamp"], 10_000);
}

fn event(id: u64, fields: &Value) -> Event {
    Event {
        id: EventId(id),
        timestamp: Timestamp(1_791_622_800 + i64::try_from(id).unwrap()),
        source: SourceId::new("windows"),
        fields: fields.as_object().expect("an object").clone(),
    }
}

/// In a real Elasticsearch: the rules raise the same alerts on the same documents, others when
/// a field they read is gone, and a rule Elasticsearch refuses is set aside.
#[test]
fn c5_in_elasticsearch_a_removed_field_a_rule_reads_changes_its_alerts() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let rules = [
        (
            RuleId::new("elastic:eql"),
            RuleQuery::Eql(
                r#"process where process.name == "cmd.exe" and user.name != null"#.into(),
            ),
        ),
        (
            RuleId::new("elastic:seq"),
            RuleQuery::Eql(
                "sequence by host.id [process where process.name == \"cmd.exe\"] \
                 [network where true]"
                    .into(),
            ),
        ),
        (
            RuleId::new("elastic:esql"),
            RuleQuery::Esql(
                "from logs-endpoint.events.* | where process.name == \"cmd.exe\" \
                 | stats n = count(*) by host.id"
                    .into(),
            ),
        ),
        (
            RuleId::new("elastic:broken"),
            RuleQuery::Eql("process where length(process.name, 1, 2) == 3".into()),
        ),
    ];
    let fields: BTreeSet<FieldPath> = ["process.name", "user.name", "host.id"]
        .into_iter()
        .map(FieldPath::from)
        .collect();
    let engine = ElasticEngine::connect(&url, &rules, &fields).expect("connects");
    assert_eq!(engine.rules().count(), 3, "{:?}", engine.skipped());
    assert_eq!(engine.skipped().len(), 1, "{:?}", engine.skipped());

    let full = [
        event(
            1,
            &json!({"event": {"category": ["process"]}, "process": {"name": "cmd.exe"},
                         "user": {"name": "bob"}, "host": {"id": "h1"}, "message": "long text"}),
        ),
        event(
            2,
            &json!({"event": {"category": ["network"]}, "host": {"id": "h1"}}),
        ),
    ];
    let full_alerts = engine.alerts(&full).expect("runs");
    let rules_fired: BTreeSet<&str> = full_alerts.iter().map(|a| a.rule.as_str()).collect();
    assert_eq!(
        rules_fired,
        ["elastic:eql", "elastic:esql", "elastic:seq"].into()
    );

    // Without a field no rule reads, the alerts are the same.
    let mut kept = full.clone();
    kept[0].fields.remove("message");
    assert_eq!(engine.alerts(&kept).expect("runs"), full_alerts);

    // Without one the EQL rule reads, they are not.
    let mut lost = full.clone();
    lost[0].fields.remove("user");
    let lost_alerts = engine.alerts(&lost).expect("runs");
    assert_ne!(lost_alerts, full_alerts);
    assert!(!lost_alerts.iter().any(|a| a.rule.as_str() == "elastic:eql"));
}
