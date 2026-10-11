//! Linux and network syslog as Microsoft Sentinel's `Syslog` table, so the analytics rules on
//! that table see Sluice's records as they see the Azure Monitor Agent's.
//!
//! A `sluice up` source with `shape: sentinel_syslog` runs [`syslog_program`] after its archive.
//! It takes the record as Vector's `syslog` source produces it (`appname`, `facility`,
//! `hostname`, `procid`, `severity`, `message`, `timestamp`), or a raw syslog line in `message`
//! or `event.original` (as Filebeat sends it), parsed with VRL's `parse_syslog`. A line that is
//! not syslog keeps its text in `SyslogMessage`.

use serde_json::{Value, json};

/// The DCR stream Sluice sends `Syslog` records to.
pub const SYSLOG_STREAM: &str = "Custom-SluiceSyslog";

/// The `Syslog` columns Sluice fills, with their types (from the Log Analytics tables API).
pub const SYSLOG_COLUMNS: [(&str, &str); 9] = [
    ("TimeGenerated", "datetime"),
    ("EventTime", "datetime"),
    ("Computer", "string"),
    ("HostName", "string"),
    ("Facility", "string"),
    ("SeverityLevel", "string"),
    ("ProcessName", "string"),
    ("ProcessID", "int"),
    ("SyslogMessage", "string"),
];

/// VRL that turns a syslog record into a `Syslog` record.
#[must_use]
pub fn syslog_program() -> String {
    r#"_line = if is_string(.message) { string!(.message) } else if is_string(.event.original) { string!(.event.original) } else { "" }
_s = if exists(.appname) || exists(.facility) { . } else { parse_syslog(_line) ?? {} }
_out = {}
_time = if exists(_s.timestamp) { _s.timestamp } else if exists(.timestamp) { .timestamp } else { ."@timestamp" }
_out.TimeGenerated = _time
_out.EventTime = _time
_host = if exists(_s.hostname) { _s.hostname } else if exists(.host.hostname) { .host.hostname } else { .host }
_out.Computer = _host
_out.HostName = _host
_out.Facility = _s.facility
_out.SeverityLevel = _s.severity
_out.ProcessName = _s.appname
_out.ProcessID = if _s.procid == null { null } else { to_int(_s.procid) ?? null }
_out.SyslogMessage = if exists(_s.message) { _s.message } else { _line }
. = compact(_out, recursive: false, string: false, object: false, array: false)
"#
    .to_owned()
}

/// A data collection rule that stores the records in `Syslog` unchanged.
#[must_use]
pub fn syslog_dcr(location: &str, workspace_resource_id: &str) -> Value {
    let columns: Vec<Value> = SYSLOG_COLUMNS
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": { SYSLOG_STREAM: { "columns": columns } },
            "destinations": {
                "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
            },
            "dataFlows": [{
                "streams": [SYSLOG_STREAM],
                "destinations": ["sentinel"],
                "transformKql": "source",
                "outputStream": "Microsoft-Syslog",
            }],
        },
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;
    use crate::CompiledProgram;

    fn shaped(event: &Value) -> Map<String, Value> {
        let program = CompiledProgram::compile("syslog", syslog_program())
            .expect("compiles without warnings in Vector's environment");
        let Value::Object(event) = event else {
            panic!("object")
        };
        let (value, _) = program.run(event).expect("runs");
        match serde_json::to_value(&value).expect("serializes") {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    #[test]
    fn a_raw_line_is_parsed_into_syslog_columns() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:55.000Z",
            "host": { "hostname": "bastion01" },
            "message": "<86>Oct 10 08:00:55 bastion01 sshd[4242]: Failed password for root from 203.0.113.9 port 50022 ssh2",
        }));
        assert_eq!(out["Facility"], "authpriv");
        assert_eq!(out["SeverityLevel"], "info");
        assert_eq!(out["ProcessName"], "sshd");
        assert_eq!(out["ProcessID"], 4242);
        assert_eq!(out["HostName"], "bastion01");
        assert_eq!(out["Computer"], "bastion01");
        assert_eq!(
            out["SyslogMessage"],
            "Failed password for root from 203.0.113.9 port 50022 ssh2"
        );
        assert!(out["TimeGenerated"].is_string());
    }

    #[test]
    fn vectors_syslog_source_fields_are_used_as_they_are() {
        let out = shaped(&json!({
            "appname": "CRON", "facility": "cron", "hostname": "web01", "procid": 7,
            "severity": "notice", "message": "session opened", "timestamp": "2026-10-10T08:00:00Z",
        }));
        assert_eq!(out["Facility"], "cron");
        assert_eq!(out["ProcessName"], "CRON");
        assert_eq!(out["ProcessID"], 7);
        assert_eq!(out["SyslogMessage"], "session opened");
    }

    #[test]
    fn a_line_that_is_not_syslog_keeps_its_text() {
        let out = shaped(&json!({ "message": "plain text", "@timestamp": "2026-10-10T08:00:00Z" }));
        assert_eq!(out["SyslogMessage"], "plain text");
        assert!(out.get("Facility").is_none());
        assert!(out.get("ProcessID").is_none(), "no process id, not 0");
    }

    #[test]
    fn the_dcr_stores_records_in_syslog_unchanged() {
        let dcr = syslog_dcr("westeurope", "/ws");
        let flow = &dcr["properties"]["dataFlows"][0];
        assert_eq!(flow["outputStream"], "Microsoft-Syslog");
        assert_eq!(flow["transformKql"], "source");
        assert_eq!(
            dcr["properties"]["streamDeclarations"][SYSLOG_STREAM]["columns"]
                .as_array()
                .map(Vec::len),
            Some(SYSLOG_COLUMNS.len())
        );
    }
}
