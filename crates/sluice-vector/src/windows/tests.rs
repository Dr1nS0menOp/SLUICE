use serde_json::{Map, Value, json};

use super::*;
use crate::runtime::CompiledProgram;

/// A failed logon as Vector's `windows_event_log` source emits it (the shape verified in
/// docs/notes/vector-windows.md; values made up).
fn failed_logon() -> Map<String, Value> {
    let event = json!({
        "channel": "Security",
        "computer": "ws01.corp.example",
        "event_id": 4625,
        "event_data": {
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "LogonType": "3",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a",
            "IpAddress": "203.0.113.7",
            "ErrorCode": "0x0",
            "KeyLength": "0",
            "ProcessName": "C:\\Windows\\System32\\svchost.exe",
            "NotAColumn": "kept <in> \"EventData\" & nowhere else"
        },
        "host": "ws01",
        "keywords": "0x8010000000000000",
        "level": "Information",
        "level_value": 0,
        "message": "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0",
        "opcode": 0,
        "process_id": 812,
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "record_id": 1_234_567,
        "source_type": "windows_event_log",
        "task": 12544,
        "thread_id": 4321,
        "timestamp": "2026-10-11T05:49:33.501855300Z",
        "version": 0
    });
    match event {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

fn shaped(event: &Map<String, Value>) -> Map<String, Value> {
    let program = CompiledProgram::compile("security_event", security_event_program())
        .expect("compiles without warnings in Vector's environment");
    let (value, _) = program.run(event).expect("runs");
    match serde_json::to_value(&value).expect("serializes") {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

#[test]
fn system_fields_become_security_event_columns() {
    let out = shaped(&failed_logon());
    assert_eq!(out["EventID"], 4625);
    assert_eq!(out["Computer"], "ws01.corp.example");
    assert_eq!(
        out["EventSourceName"],
        "Microsoft-Windows-Security-Auditing"
    );
    assert_eq!(out["Channel"], "Security");
    assert_eq!(out["EventRecordId"], "1234567");
    assert_eq!(out["Task"], 12544);
    assert_eq!(out["Activity"], "4625 - An account failed to log on.");
    assert_eq!(out["TimeGenerated"], "2026-10-11T05:49:33.501855300Z");
    for gone in ["event_data", "message", "source_type", "host"] {
        assert!(!out.contains_key(gone), "{gone}");
    }
}

#[test]
fn data_values_become_typed_columns_and_all_stay_in_event_data() {
    let out = shaped(&failed_logon());
    assert_eq!(out["TargetUserName"], "admin");
    assert_eq!(out["LogonType"], 3, "an int column");
    assert_eq!(out["ErrorCode"], 0, "hexadecimal parsed");
    assert_eq!(
        out["Status"], "0xc000006d",
        "a string column keeps its text"
    );
    assert!(!out.contains_key("NotAColumn"));
    let xml = out["EventData"].as_str().expect("a string");
    assert!(xml.starts_with(
        r#"<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event">"#
    ));
    assert!(xml.contains(r#"<Data Name="TargetUserName">admin</Data>"#));
    assert!(xml.contains(
        r#"<Data Name="NotAColumn">kept &lt;in&gt; &quot;EventData&quot; &amp; nowhere else</Data>"#
    ));
    assert!(xml.ends_with("</EventData>"));
}

#[test]
fn every_output_column_is_a_security_event_column() {
    let out = shaped(&failed_logon());
    let known = |name: &str| {
        SECURITY_EVENT_SYSTEM_COLUMNS
            .iter()
            .any(|(n, _)| *n == name)
            || SECURITY_EVENT_DATA_COLUMNS.iter().any(|(n, _)| *n == name)
    };
    for name in out.keys() {
        assert!(known(name), "{name} is not a SecurityEvent column");
    }
}

fn run(program: String, event: &Map<String, Value>) -> Map<String, Value> {
    let program = CompiledProgram::compile("windows", program)
        .expect("compiles without warnings in Vector's environment");
    let (value, _) = program.run(event).expect("runs");
    match serde_json::to_value(&value).expect("serializes") {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// A System channel event (the shape verified in docs/notes/vector-windows.md; values made up).
fn service_event() -> Map<String, Value> {
    let event = json!({
        "channel": "System",
        "computer": "ws01.corp.example",
        "event_id": 7036,
        "event_data": { "param1": "Print Spooler", "param2": "running", "Empty": "" },
        "level": "Information",
        "level_value": 4,
        "message": "The Print Spooler service entered the running state.",
        "provider_name": "Service Control Manager",
        "record_id": 42,
        "source_type": "windows_event_log",
        "timestamp": "2026-10-11T05:49:33.501855300Z",
        "version": 0
    });
    match event {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

#[test]
fn empty_strings_are_kept_as_the_agent_keeps_them() {
    let mut event = failed_logon();
    event["event_data"]["SubjectUserName"] = json!("");
    let out = shaped(&event);
    assert_eq!(out["SubjectUserName"], "");
}

#[test]
fn other_channels_become_windows_event_records() {
    let out = run(windows_event_program(), &service_event());
    assert_eq!(out["EventID"], 7036);
    assert_eq!(out["Provider"], "Service Control Manager");
    assert_eq!(out["EventLevel"], 4);
    assert_eq!(out["EventRecordId"], "42");
    assert_eq!(
        out["EventData"],
        json!({ "param1": "Print Spooler", "param2": "running", "Empty": "" })
    );
    for name in out.keys() {
        assert!(
            WINDOWS_EVENT_COLUMNS.iter().any(|(n, _)| n == name),
            "{name} is not a WindowsEvent column"
        );
    }
    let mut classic = service_event();
    classic.remove("event_data");
    classic.insert("string_inserts".into(), json!(["a", "b"]));
    assert_eq!(
        run(windows_event_program(), &classic)["EventData"],
        json!({ "Data": ["a", "b"] })
    );
}

#[test]
fn classic_security_events_without_named_data_still_shape() {
    let mut event = failed_logon();
    event.remove("event_data");
    event.insert("string_inserts".into(), json!(["a", "b"]));
    let out = shaped(&event);
    assert_eq!(out["EventID"], 4625);
    assert_eq!(
        out["EventData"],
        r#"<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event"></EventData>"#
    );
}

#[test]
fn the_dcr_declares_every_column_the_programs_write() {
    let dcr = windows_dcr("westeurope", "/subscriptions/x/workspaces/w");
    let declared = |stream: &str| -> Vec<String> {
        dcr["properties"]["streamDeclarations"][stream]["columns"]
            .as_array()
            .expect("columns")
            .iter()
            .map(|c| c["name"].as_str().expect("a name").to_owned())
            .collect()
    };
    let security = declared(SECURITY_EVENT_STREAM);
    for name in shaped(&failed_logon()).keys() {
        assert!(security.contains(name), "{name} not declared");
    }
    let windows = declared(WINDOWS_EVENT_STREAM);
    for name in run(windows_event_program(), &service_event()).keys() {
        assert!(windows.contains(name), "{name} not declared");
    }
    let flows = dcr["properties"]["dataFlows"].as_array().expect("flows");
    assert_eq!(flows[0]["outputStream"], "Microsoft-SecurityEvent");
    assert_eq!(flows[1]["outputStream"], "Microsoft-WindowsEvent");
    assert!(flows.iter().all(|f| f["transformKql"] == "source"));
    // Column names must start with a letter and hold at most 45 letters, digits or `_`.
    for name in security.iter().chain(&windows) {
        assert!(name.len() <= 45 && name.starts_with(|c: char| c.is_ascii_alphabetic()));
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "{name}"
        );
    }
}

#[test]
fn the_agent_splits_by_channel_and_never_drops_on_errors() {
    let central = Central {
        security: "http://sluice:9110",
        events: Some("http://sluice:9111"),
    };
    let channels = ["Security".to_owned(), "System".to_owned()];
    let yaml = agent_config(&channels, central, "C:/ProgramData/Vector/data").expect("YAML");
    let config: Value = serde_yaml_ng::from_str(&yaml).expect("YAML");
    assert_eq!(config["sources"]["windows"]["type"], "windows_event_log");
    assert_eq!(
        config["transforms"]["channel"]["route"]["security"],
        r#".channel == "Security""#
    );
    // Events leave the host as Vector read them: shaping happens after the central archive.
    assert_eq!(
        config["transforms"].as_object().map(serde_json::Map::len),
        Some(1)
    );
    assert_eq!(
        config["sinks"]["security"]["inputs"],
        json!(["channel.security"])
    );
    assert_eq!(
        config["sinks"]["events"]["inputs"],
        json!(["channel._unmatched"])
    );
    assert_eq!(config["sinks"]["security"]["uri"], "http://sluice:9110");
    assert_eq!(config["sinks"]["events"]["uri"], "http://sluice:9111");
    assert_eq!(config["sinks"]["events"]["buffer"]["type"], "disk");

    let security_only = Central {
        security: "http://sluice:9110",
        events: None,
    };
    let yaml = agent_config(&channels[..1], security_only, "C:/data").expect("YAML");
    let config: Value = serde_yaml_ng::from_str(&yaml).expect("YAML");
    assert!(config["sinks"].get("events").is_none());
    assert!(
        agent_config(&channels, security_only, "C:/data").is_err(),
        "System needs a WindowsEvent destination"
    );
}
