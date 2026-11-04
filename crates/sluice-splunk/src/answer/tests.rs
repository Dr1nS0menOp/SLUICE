use std::collections::BTreeSet;

use serde_json::json;

use super::*;

fn rows(value: &Value) -> Vec<Map<String, Value>> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|r| r.as_object().expect("an object").clone())
        .collect()
}

#[test]
fn a_search_splunk_refuses_says_why_whichever_way_it_refuses() {
    // An unknown command: `400`.
    let unknown = r#"{"messages":[{"type":"FATAL","text":"Unknown search command 'x'."}]}"#;
    assert_eq!(
        outcome(400, unknown, 10).unwrap(),
        Outcome::Refused("Unknown search command 'x'.".to_owned())
    );
    // A lookup the proof's Splunk does not have: `200`, with only a message.
    let lookup = r#"{"messages":[{"type":"FATAL","text":"Error in 'lookup' command"}]}"#;
    assert_eq!(
        outcome(200, lookup, 10).unwrap(),
        Outcome::Refused("Error in 'lookup' command".to_owned())
    );
    assert_eq!(
        outcome(400, "not json", 10).unwrap(),
        Outcome::Refused("not json".to_owned())
    );
}

#[test]
fn an_answer_that_is_neither_rows_nor_a_refusal_is_an_error() {
    assert!(matches!(
        outcome(401, "denied", 10),
        Err(SplunkError::Rejected { status: 401, .. })
    ));
    assert!(matches!(
        outcome(200, "", 10),
        Err(SplunkError::Response(_))
    ));
    assert!(matches!(
        outcome(200, r#"{"messages":[]}"#, 10),
        Err(SplunkError::Response(_))
    ));
}

#[test]
fn warnings_do_not_refuse_a_search_but_its_rows_are_kept() {
    let answer = r#"{"messages":[{"type":"WARN","text":"w"}],"results":[{"count":"0"}]}"#;
    assert_eq!(
        outcome(200, answer, 10).unwrap(),
        Outcome::Rows(rows(&json!([{ "count": "0" }])))
    );
    assert_eq!(
        outcome(200, r#"{"results":[]}"#, 10).unwrap(),
        Outcome::Rows(Vec::new())
    );
}

#[test]
fn c5_reaching_splunks_row_limit_is_not_proof() {
    // Splunk caps the rows silently: as many as the cap may mean more were left out.
    let answer = r#"{"results":[{"a":"1"},{"a":"2"}]}"#;
    assert!(matches!(outcome(200, answer, 3), Ok(Outcome::Rows(_))));
    let error = outcome(200, answer, 2).unwrap_err().to_string();
    assert!(error.contains("too many to compare"), "{error}");
}

#[test]
fn a_row_that_is_an_event_alerts_on_that_event() {
    let rule = RuleId::new("splunk:s");
    let alerts = alerts(
        &rule,
        &rows(&json!([
            { EVENT_FIELD: "7", "_raw": "{…}", "_cd": "0:1", "User": "a" },
            { EVENT_FIELD: "9", "_raw": "{…}", "_cd": "0:2" },
        ])),
        "p1",
    );
    assert_eq!(
        alerts.iter().map(|a| a.event).collect::<Vec<_>>(),
        [EventId(7), EventId(9)]
    );
}

#[test]
fn any_other_row_alerts_by_its_content_whatever_splunk_adds() {
    let rule = RuleId::new("splunk:s");
    let first = rows(&json!([
        { "User": "a", "count": "2", "index": "p1", "_bkt": "p1~0~x", "_time": "1" },
        { "User": "a", "count": "2", "index": "p1", "_bkt": "p1~0~x", "_time": "1" },
        { "User": "b", "count": "1", "index": "p1" },
    ]));
    // Another evaluation: another index, other bucket ids, the rows in another order.
    let second = rows(&json!([
        { "User": "b", "count": "1", "index": "p2" },
        { "User": "a", "count": "2", "index": "p2", "_bkt": "p2~3~y", "_time": "1" },
        { "User": "a", "count": "2", "index": "p2", "_bkt": "p2~3~y", "_time": "1" },
    ]));
    let set = |r: &[Map<String, Value>], index| -> BTreeSet<Alert> {
        alerts(&rule, r, index).into_iter().collect()
    };
    // Identical rows stay distinct, and the sets are equal.
    assert_eq!(set(&first, "p1").len(), 3);
    assert_eq!(set(&first, "p1"), set(&second, "p2"));
    // A changed value, or a row more or less, is a different set.
    let changed = rows(&json!([
        { "User": "b", "count": "1", "index": "p2" },
        { "User": "a", "count": "3", "index": "p2", "_time": "1" },
        { "User": "a", "count": "2", "index": "p2", "_time": "1" },
    ]));
    assert_ne!(set(&first, "p1"), set(&changed, "p2"));
    assert_ne!(set(&first, "p1"), set(&second[..2], "p2"));
    // The time is part of a row.
    let later = rows(&json!([{ "User": "b", "count": "1", "index": "p2", "_time": "2" }]));
    assert_ne!(set(&first[2..], "p1"), set(&later, "p2"));
}

#[test]
fn the_evaluation_a_row_comes_from_is_not_part_of_it() {
    // `table *` and `values(*)` show the run's number, which differs between evaluations.
    let rule = RuleId::new("splunk:s");
    let row = |run: &str| rows(&json!([{ "User": "a", RUN_FIELD: run }]));
    assert_eq!(alerts(&rule, &row("1"), "p"), alerts(&rule, &row("2"), "p"));
}

#[test]
fn a_row_with_several_event_ids_alerts_by_its_content() {
    let rule = RuleId::new("splunk:s");
    let row = rows(&json!([{ EVENT_FIELD: ["1", "2"], "User": "a" }]));
    let alert = &alerts(&rule, &row, "p")[0];
    assert_ne!(alert.event, EventId(1));
    assert_ne!(alert.event, EventId(2));
}

#[test]
fn the_parts_of_a_hash_are_kept_apart() {
    assert_ne!(fnv1a(&["ab", "c"]), fnv1a(&["a", "bc"]));
    assert_eq!(fnv1a(&["a"]), fnv1a(&["a"]));
}
