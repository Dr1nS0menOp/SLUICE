//! The engine against a fake emulator that answers by command and records what it was sent.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use super::*;
use crate::table::CustomColumn;

fn ids(rule: &str, rows: &[&str]) -> Vec<u64> {
    alerts_from_rows(
        &RuleId::new(rule),
        rows.iter().map(|r| (*r).to_owned()).collect(),
    )
    .map(|a| a.event.0)
    .collect()
}

#[test]
fn identical_rows_are_distinct_alerts() {
    let alerts = ids("r", &["a", "a", "b"]);
    assert_eq!(alerts.iter().collect::<BTreeSet<_>>().len(), 3);
}

#[test]
fn row_order_does_not_change_alerts() {
    let mut one = ids("r", &["a", "b", "a"]);
    let mut two = ids("r", &["b", "a", "a"]);
    one.sort_unstable();
    two.sort_unstable();
    assert_eq!(one, two);
}

#[test]
fn a_changed_column_is_a_different_alert() {
    assert_ne!(
        ids("r", &["[[\"User\"],[\"alice\"]]"]),
        ids("r", &["[[\"User\"],[\"\"]]"])
    );
    assert_ne!(ids("r", &["a"]), ids("s", &["a"]));
    assert_ne!(fnv1a(&["ab", "c"]), fnv1a(&["a", "bc"]));
}

fn event(id: u64, source: &str, fields: &Value) -> Event {
    Event {
        id: EventId(id),
        timestamp: sluice_core::event::Timestamp(0),
        source: SourceId::new(source),
        fields: fields.as_object().expect("object").clone(),
    }
}

#[test]
fn records_hold_columns_and_the_table_type() {
    let event = event(1, "win", &json!({"EventID": 4625, "NotAColumn": 1}));
    assert_eq!(
        record(&Table::SecurityEvent, &event),
        json!({ "EventID": 4625, "Type": "SecurityEvent" })
    );
}

#[test]
fn every_table_is_found_by_its_name_and_only_by_it() {
    for table in Table::STANDARD {
        assert_eq!(Table::from_name(table.name()), Some(table.clone()));
        assert!(table.columns().any(|(c, _)| c == "_ResourceId"));
    }
    assert_eq!(Table::from_name("securityevent"), None);
    assert_eq!(Table::from_name(""), None);
}

#[test]
fn the_reason_a_rule_is_set_aside_is_its_first_line() {
    assert_eq!(
        first_line("\n  'Missing' not found \n details"),
        "'Missing' not found"
    );
    assert_eq!(first_line(" \n"), "rejected");
}

/// One request the emulator got: the endpoint (`mgmt` or `query`), the database and the text.
type Sent = Arc<Mutex<Vec<(String, String, String)>>>;

/// An emulator that answers each request with `answer(endpoint, csl)` (status and body).
fn emulator(answer: fn(&str, &str) -> (u16, String)) -> (String, Sent) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let url = format!("http://{}", listener.local_addr().expect("bound"));
    let sent: Sent = Arc::default();
    let seen = Arc::clone(&sent);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(stream);
            while let Some((path, body)) = request(&mut reader) {
                let endpoint = path.rsplit('/').next().unwrap_or_default().to_owned();
                let body: Value = serde_json::from_str(&body).expect("a JSON body");
                let (db, csl) = (body["db"].as_str().unwrap(), body["csl"].as_str().unwrap());
                let (status, text) = answer(&endpoint, csl);
                seen.lock()
                    .expect("not poisoned")
                    .push((endpoint, db.to_owned(), csl.to_owned()));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{text}",
                    text.len()
                );
                if reader.get_mut().write_all(response.as_bytes()).is_err() {
                    break;
                }
            }
        }
    });
    (url, sent)
}

/// Reads one request: its path and body; `None` when the connection is closed.
fn request(reader: &mut impl BufRead) -> Option<(String, String)> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let path = line.split_whitespace().nth(1)?.to_owned();
    let mut length = 0;
    loop {
        line.clear();
        reader.read_line(&mut line).ok()?;
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some((path, String::from_utf8(body).ok()?))
}

/// A result with one column and `rows` rows, each holding `alice`.
fn result(rows: usize) -> String {
    json!({"Tables": [{"Columns": [{"ColumnName": "User"}], "Rows": vec![json!(["alice"]); rows]}]})
        .to_string()
}

/// Commands succeed; a query naming `Missing` is refused; others return two equal rows.
fn usual(endpoint: &str, csl: &str) -> (u16, String) {
    match endpoint {
        "mgmt" => (200, "{}".to_owned()),
        _ if csl.contains("Missing") => (400, "'Missing' not found\ndetails".to_owned()),
        _ => (200, result(2)),
    }
}

fn rules(names: &[&str]) -> Vec<(RuleId, String)> {
    names
        .iter()
        .map(|q| {
            (
                RuleId::new(format!("sentinel:{q}")),
                format!("{q} | take 1"),
            )
        })
        .collect()
}

#[test]
fn rules_that_cannot_run_on_empty_tables_are_set_aside_with_the_reason() {
    let (url, sent) = emulator(usual);
    let engine = KustoEngine::connect(
        &format!("{url}/"),
        &rules(&["SecurityEvent", "Missing"]),
        BTreeMap::new(),
    )
    .expect("connects");
    let kept: Vec<&str> = engine.rules().map(RuleId::as_str).collect();
    assert_eq!(kept, ["sentinel:SecurityEvent"]);
    assert_eq!(
        engine.skipped(),
        [(
            RuleId::new("sentinel:Missing"),
            "'Missing' not found".to_owned()
        )]
    );

    // A fresh volatile database with every table, dropped when done.
    let sent = sent.lock().unwrap().clone();
    let (endpoint, db, create) = &sent[0];
    assert_eq!((endpoint.as_str(), db.as_str()), ("mgmt", DEFAULT_DB));
    let name = create
        .strip_prefix(".create database ")
        .and_then(|rest| rest.strip_suffix(" volatile"))
        .expect("a volatile database");
    let tables = sent
        .iter()
        .filter(|(_, d, c)| d == name && c.starts_with(".create table "))
        .count();
    assert_eq!(tables, Table::STANDARD.len());
    assert_eq!(
        sent.last().unwrap().2,
        format!(".drop database {name} ifexists")
    );
}

#[test]
fn events_load_into_their_sources_table_in_batches_and_each_row_is_an_alert() {
    let (url, sent) = emulator(usual);
    let tables = BTreeMap::from([(SourceId::new("win"), Table::SecurityEvent)]);
    let engine = KustoEngine::connect(&url, &rules(&["SecurityEvent"]), tables).expect("connects");
    let mut events: Vec<Event> = (0..501)
        .map(|i| event(i, "win", &json!({"EventID": 4624, "Account": "a"})))
        .collect();
    events.push(event(
        999,
        "elsewhere",
        &json!({"EventID": 4624, "Account": "marker"}),
    ));
    let alerts = engine.alerts(&events).expect("evaluates");
    assert_eq!(alerts.len(), 2, "two equal rows, two alerts");

    let sent = sent.lock().unwrap().clone();
    let ingests: Vec<&String> = sent
        .iter()
        .map(|(_, _, c)| c)
        .filter(|c| c.starts_with(".ingest inline into table SecurityEvent"))
        .collect();
    let lines: Vec<usize> = ingests.iter().map(|c| c.lines().count() - 1).collect();
    assert_eq!(lines, [INGEST_BATCH, 1]);
    assert!(
        !ingests.iter().any(|c| c.contains("marker")),
        "a source without a table loads nothing"
    );
}

#[test]
fn an_emulator_that_is_down_or_answers_nonsense_is_an_error() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    assert!(matches!(
        KustoEngine::connect(&closed, &[], BTreeMap::new()),
        Err(KustoError::Unreachable { .. })
    ));

    let (url, _) = emulator(|_, _| (200, "not json".to_owned()));
    assert!(matches!(
        KustoEngine::connect(&url, &[], BTreeMap::new()),
        Err(KustoError::Response(_))
    ));

    let (url, _) = emulator(|_, _| (500, "busy".to_owned()));
    assert_eq!(
        KustoEngine::connect(&url, &[], BTreeMap::new()).unwrap_err(),
        KustoError::Rejected {
            status: 500,
            message: "busy".to_owned()
        }
    );
}

fn no_table(endpoint: &str, _: &str) -> (u16, String) {
    match endpoint {
        "mgmt" => (200, "{}".to_owned()),
        _ => (200, json!({"Tables": []}).to_string()),
    }
}

fn no_rows(endpoint: &str, _: &str) -> (u16, String) {
    match endpoint {
        "mgmt" => (200, "{}".to_owned()),
        _ => (200, json!({"Tables": [{"Columns": []}]}).to_string()),
    }
}

#[test]
fn a_malformed_query_result_is_an_error_not_a_rule_set_aside() {
    for answer in [no_table, no_rows] {
        let (url, _) = emulator(answer);
        let engine = KustoEngine::connect(
            &url,
            &[(RuleId::new("r"), "SecurityEvent | take 1".into())],
            BTreeMap::new(),
        );
        assert!(matches!(engine, Err(KustoError::Response(_))), "{engine:?}");
    }
}

fn custom() -> Table {
    let column = |name: &str, kind: &str, field: &str| CustomColumn {
        name: name.to_owned(),
        kind: kind.to_owned(),
        field: field.to_owned(),
    };
    Table::custom(
        "MyApp_CL",
        vec![
            column("TimeGenerated", "datetime", "TimeGenerated"),
            column("action", "string", "action"),
            column("user_agent", "string", "user-agent"),
        ],
    )
    .expect("a valid custom table")
}

#[test]
fn a_custom_table_needs_a_valid_name_columns_and_types() {
    let column = |name: &str, kind: &str| CustomColumn {
        name: name.to_owned(),
        kind: kind.to_owned(),
        field: name.to_owned(),
    };
    assert!(Table::custom("MyApp", vec![column("a", "string")]).is_none());
    assert!(Table::custom("My App_CL", vec![column("a", "string")]).is_none());
    assert!(Table::custom("_CL", Vec::new()).is_none());
    assert!(Table::custom("MyApp_CL", vec![column("a", "text")]).is_none());
    assert!(Table::custom("MyApp_CL", vec![column("a']\n.drop", "string")]).is_none());
    let table = custom();
    assert_eq!(table.name(), "MyApp_CL");
    assert_eq!(table.output_stream(), "Custom-MyApp_CL");
    assert_eq!(
        Table::SecurityEvent.output_stream(),
        "Microsoft-SecurityEvent"
    );
    assert_eq!(
        table.stream_columns(),
        [
            ("TimeGenerated", "datetime"),
            ("action", "string"),
            ("user-agent", "string")
        ]
    );
    assert_eq!(
        Table::from_name("MyApp_CL"),
        None,
        "only standard tables by name"
    );
}

#[test]
fn a_custom_table_holds_a_renamed_field_under_its_column() {
    let event = event(
        1,
        "app",
        &json!({"action": "deny", "user-agent": "curl", "extra": 1}),
    );
    assert_eq!(
        record(&custom(), &event),
        json!({"action": "deny", "user_agent": "curl", "Type": "MyApp_CL"})
    );
}

#[test]
fn custom_tables_are_created_in_every_database() {
    let (url, sent) = emulator(usual);
    let tables = BTreeMap::from([
        (SourceId::new("app"), custom()),
        (SourceId::new("app2"), custom()),
    ]);
    let engine = KustoEngine::connect(&url, &rules(&["MyApp_CL"]), tables).expect("connects");
    let events = vec![event(1, "app", &json!({"action": "deny"}))];
    engine.alerts(&events).expect("evaluates");
    let sent = sent.lock().unwrap().clone();
    let created = sent
        .iter()
        .filter(|(_, _, c)| c.starts_with(".create table MyApp_CL "))
        .count();
    assert_eq!(
        created, 2,
        "once when the rules are checked, once per evaluation"
    );
    assert!(
        sent.iter()
            .any(|(_, _, c)| c.starts_with(".ingest inline into table MyApp_CL"))
    );
}

/// In the Kusto emulator (`SLUICE_KUSTO_URL`): the `SluiceCounts` function reads the summary
/// table as `sluice connect sentinel --summary-table` defines it.
#[test]
fn the_counts_function_reads_the_summary_table() {
    use sluice_vector::summary_table::{SUMMARY_COUNTS, SUMMARY_TABLE, summary_table};
    let Ok(url) = std::env::var("SLUICE_KUSTO_URL") else {
        return;
    };
    let table = summary_table();
    let columns: Vec<(String, String)> = table["properties"]["schema"]["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .map(|c| {
            (
                c["name"].as_str().expect("a name").to_owned(),
                c["type"].as_str().expect("a type").to_owned(),
            )
        })
        .collect();
    let columns: Vec<(&str, &str)> = columns
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    let rows = [
        json!({"TimeGenerated": "2026-10-17T10:00:00Z", "sluice_source": "win",
               "sluice_template": "win:5156:a", "sluice_keys": {"Application": "svchost.exe"},
               "sluice_count": 40}),
        json!({"TimeGenerated": "2026-10-17T10:01:00Z", "sluice_source": "win",
               "sluice_template": "win:5156:a", "sluice_keys": {"Application": "svchost.exe"},
               "sluice_count": 2}),
    ];
    let client = Client::new(&url);
    let database = Database::create(&client, &[]).expect("a database");
    database
        .load_table(SUMMARY_TABLE, &columns, &rows)
        .expect("loads");
    let query = format!(
        "{SUMMARY_COUNTS}| summarize Count = sum(Count) by Source, Template, App = \
         tostring(Keys.Application)"
    );
    let result = database.query(&query).expect("the function runs");
    assert_eq!(result.len(), 1, "{result:?}");
    assert!(
        result[0].contains("svchost.exe") && result[0].contains("42"),
        "{result:?}"
    );
}
