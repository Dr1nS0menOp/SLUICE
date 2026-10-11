//! Windows events from Vector's `windows_event_log` source, shaped as Microsoft Sentinel's
//! `SecurityEvent` and `WindowsEvent` tables (PLAN.md, M7; ADR 0014).
//!
//! Vector puts a provider's named data under `event_data`, all values as strings, and the system
//! fields in snake case (docs/notes/vector-windows.md). Sentinel's analytics rules and Sigma both
//! read the data names at the top level (`TargetUserName`, `LogonType`). The programs here map
//! one onto the other, so the event Sluice proves its reductions on is the record Sentinel
//! stores:
//!
//! - the Security channel becomes `SecurityEvent`: system fields become its system columns, every
//!   data value whose name is a column becomes that column, typed as the table types it, and
//!   every data value is also kept in the `EventData` column as the `<EventData>` XML the Azure
//!   Monitor Agent writes;
//! - every other channel becomes `WindowsEvent`, whose `EventData` is the data as an object.
//!
//! The account columns the agent derives (`SubjectAccount`, `TargetAccount`, `Account`,
//! `AccountType`) follow Microsoft's column reference; see `ACCOUNTS`. Empty strings are kept, as
//! the agent keeps them; only absent values are left out.

pub use columns::{
    SECURITY_EVENT_DATA_COLUMNS, SECURITY_EVENT_GUID_COLUMNS, SECURITY_EVENT_SYSTEM_COLUMNS,
    WINDOWS_EVENT_COLUMNS,
};

mod columns;

/// The DCR input stream for `SecurityEvent` records.
pub const SECURITY_EVENT_STREAM: &str = "Custom-SluiceSecurityEvent";

/// The DCR input stream for `WindowsEvent` records.
pub const WINDOWS_EVENT_STREAM: &str = "Custom-SluiceWindowsEvent";

/// The channel that goes to `SecurityEvent`; every other channel goes to `WindowsEvent`.
pub const SECURITY_CHANNEL: &str = "Security";

/// Leaves out absent values only; an empty string stays, as the agent stores it.
const COMPACT: &str = "compact(_out, recursive: false, string: false, object: false, array: false)";

/// System fields both tables share, in the agent's names.
const COMMON: &str = r"_out = {}
_out.TimeGenerated = .timestamp
_out.Computer = .computer
_out.EventID = .event_id
_out.Channel = .channel
_out.Task = .task
_out.EventLevelName = .level
_out.Keywords = .keywords
_out.Opcode = if is_integer(.opcode) { to_string!(.opcode) } else { null }
_out.EventRecordId = if is_integer(.record_id) { to_string!(.record_id) } else { null }
_out.Version = .version
_out.SystemProcessId = .process_id
_out.SystemThreadId = .thread_id
_out.SystemUserId = .user_id
";

/// The VRL that shapes a Security channel event as a `SecurityEvent` record.
#[must_use]
pub fn security_event_program() -> String {
    let quoted = |names: &mut dyn Iterator<Item = &str>| {
        names
            .map(crate::syntax::string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let columns = quoted(&mut SECURITY_EVENT_DATA_COLUMNS.iter().map(|(n, _)| *n));
    let integers = quoted(
        &mut SECURITY_EVENT_DATA_COLUMNS
            .iter()
            .filter(|(_, int)| *int)
            .map(|(n, _)| *n),
    );
    let name = xml_escape("_name");
    let value = xml_escape("_value");
    format!(
        r#"{COMMON}_data = object(.event_data) ?? {{}}
_columns = [{columns}]
_integers = [{integers}]
_out.EventSourceName = .provider_name
_out.Level = if is_integer(.level_value) {{ to_string!(.level_value) }} else {{ null }}
_message = if is_string(.message) {{ string!(.message) }} else {{ "" }}
_title = strip_whitespace(string(split(_message, "\n", limit: 2)[0]) ?? "")
_out.Activity = if is_integer(.event_id) {{ to_string!(.event_id) + " - " + _title }} else {{ _title }}
_xml = "<EventData xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
for_each(_data) -> |_name, _raw| {{
  _value = if is_string(_raw) {{ string!(_raw) }} else {{ encode_json(_raw) }}
  _xml = _xml + "<Data Name=\"" + {name} + "\">" + {value} + "</Data>"
  if includes(_columns, _name) {{
    if includes(_integers, _name) {{
      _out = set!(_out, [_name], parse_int(_value) ?? null)
    }} else {{
      _out = set!(_out, [_name], _value)
    }}
  }}
}}
_out.EventData = _xml + "</EventData>"
{ACCOUNTS}. = {COMPACT}
"#
    )
}

/// The account columns the agent derives from the event's data, as Microsoft's column reference
/// describes them: `SubjectAccount` and `TargetAccount` as `DOMAIN\name`, `Account` as the target
/// account when the event has one and the subject otherwise, and `AccountType` as `Machine` for a
/// name ending in `$`. Anything else is `User`, which the rules that filter on it
/// (`AccountType == "User"`) keep seeing: when in doubt, a rule sees more, never less.
const ACCOUNTS: &str = r#"_su = string(_out.SubjectUserName) ?? ""
_sd = string(_out.SubjectDomainName) ?? ""
_tu = string(_out.TargetUserName) ?? ""
_td = string(_out.TargetDomainName) ?? ""
if _out.SubjectAccount == null && _su != "" && _su != "-" {
  _out.SubjectAccount = if _sd == "" || _sd == "-" { _su } else { _sd + "\\" + _su }
}
if _out.TargetAccount == null && _tu != "" && _tu != "-" {
  _out.TargetAccount = if _td == "" || _td == "-" { _tu } else { _td + "\\" + _tu }
}
_acct = if _out.TargetAccount != null { _out.TargetAccount } else { _out.SubjectAccount }
if is_string(_acct) {
  _out.Account = _acct
  _out.AccountType = if ends_with(string!(_acct), "$") { "Machine" } else { "User" }
}
"#;

/// The VRL that shapes an event of any other channel as a `WindowsEvent` record. Classic
/// events with unnamed data keep it as `EventData.Data`, a list.
#[must_use]
pub fn windows_event_program() -> String {
    format!(
        r#"{COMMON}_out.Provider = .provider_name
_out.EventLevel = .level_value
_out.EventData = if is_object(.event_data) {{ .event_data }} else if is_array(.string_inserts) {{ {{"Data": .string_inserts}} }} else {{ null }}
. = {COMPACT}
"#
    )
}

/// Where a Windows host sends its two kinds of records: URLs of `http_server` sources of
/// `sluice up`.
#[derive(Debug, Clone, Copy)]
pub struct Central<'a> {
    /// Receives `SecurityEvent` records (the Security channel).
    pub security: &'a str,
    /// Receives `WindowsEvent` records (every other channel), if any other channel is read.
    pub events: Option<&'a str>,
}

/// The Vector configuration for a Windows host: read `channels` and send each event, as Vector
/// read it, to its `central` source: the Security channel to one, every other channel to the
/// other. The host keeps no state but Vector's read checkpoints and a disk send buffer. Shaping
/// happens centrally, after the archive keeps the original (contract rule 2): give the central
/// sources `shape: sentinel_security_event` and `shape: sentinel_windows_event`.
///
/// # Errors
///
/// Returns [`VectorError::Config`](crate::VectorError::Config) if a channel other than Security
/// is read without `central.events`, or if the configuration cannot be serialized.
pub fn agent_config(
    channels: &[String],
    central: Central<'_>,
    data_dir: &str,
) -> Result<String, crate::VectorError> {
    let others = channels.iter().any(|c| c != SECURITY_CHANNEL);
    let transforms = serde_json::json!({
        "channel": {
            "type": "route",
            "inputs": ["windows"],
            "route": { "security": format!(".channel == {}", crate::syntax::string(SECURITY_CHANNEL)) },
        },
    });
    let mut sinks = serde_json::json!({ "security": send("channel.security", central.security) });
    if others {
        let url = central.events.ok_or_else(|| {
            crate::VectorError::Config(
                "channels other than Security become WindowsEvent records: give their URL".into(),
            )
        })?;
        sinks["events"] = send("channel._unmatched", url);
    }
    let config = serde_json::json!({
        "data_dir": data_dir,
        "sources": {
            "windows": {
                "type": "windows_event_log",
                "channels": channels,
                "render_message": true,
            },
        },
        "transforms": transforms,
        "sinks": sinks,
    });
    serde_yaml_ng::to_string(&config).map_err(|e| crate::VectorError::Config(e.to_string()))
}

fn send(input: &str, url: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "http",
        "inputs": [input],
        "uri": url,
        "method": "post",
        "encoding": { "codec": "json" },
        "framing": { "method": "newline_delimited" },
        "batch": { "max_events": 500, "timeout_secs": 1 },
        "buffer": { "type": "disk", "max_size": 268_435_488, "when_full": "block" },
    })
}

/// A data collection rule (ARM resource body) with two input streams, [`SECURITY_EVENT_STREAM`]
/// into `SecurityEvent` and [`WINDOWS_EVENT_STREAM`] into `WindowsEvent`. Sluice already sent
/// exactly the tables' columns, proven and reduced, so the only transformation types the
/// `SecurityEvent` GUID columns ([`SECURITY_EVENT_GUID_COLUMNS`]); `WindowsEvent` is stored as
/// sent (`source`). `kind: Direct` gives the rule its own ingestion endpoint.
#[must_use]
pub fn windows_dcr(location: &str, workspace_resource_id: &str) -> serde_json::Value {
    let column = |name: &str, kind: &str| serde_json::json!({ "name": name, "type": kind });
    let mut security: Vec<serde_json::Value> = SECURITY_EVENT_SYSTEM_COLUMNS
        .iter()
        .map(|(name, kind)| column(name, kind))
        .collect();
    security.extend(
        SECURITY_EVENT_DATA_COLUMNS
            .iter()
            .map(|(name, int)| column(name, if *int { "int" } else { "string" })),
    );
    let windows: Vec<serde_json::Value> = WINDOWS_EVENT_COLUMNS
        .iter()
        .map(|(name, kind)| column(name, kind))
        .collect();
    let flow = |stream: &str, table: &str, transform: &str| {
        serde_json::json!({
            "streams": [stream],
            "destinations": ["sentinel"],
            "transformKql": transform,
            "outputStream": table,
        })
    };
    let guids: Vec<String> = SECURITY_EVENT_GUID_COLUMNS
        .iter()
        .map(|c| format!("{c} = toguid({c})"))
        .collect();
    let security_transform = format!("source | extend {}", guids.join(", "));
    serde_json::json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": {
                SECURITY_EVENT_STREAM: { "columns": security },
                WINDOWS_EVENT_STREAM: { "columns": windows },
            },
            "destinations": {
                "logAnalytics": [
                    { "workspaceResourceId": workspace_resource_id, "name": "sentinel" }
                ]
            },
            "dataFlows": [
                flow(SECURITY_EVENT_STREAM, "Microsoft-SecurityEvent", &security_transform),
                flow(WINDOWS_EVENT_STREAM, "Microsoft-WindowsEvent", "source"),
            ],
        },
    })
}

/// VRL that escapes `text` (a string variable) for an XML attribute or element.
fn xml_escape(text: &str) -> String {
    format!(
        r#"replace(replace(replace(replace({text}, "&", "&amp;"), "<", "&lt;"), ">", "&gt;"), "\"", "&quot;")"#
    )
}

#[cfg(test)]
mod tests;
