//! Firewall and network device events as Microsoft Sentinel's `CommonSecurityLog` table (the CEF
//! table), so the analytics rules on it, such as the threat-intelligence IP matches, see them.
//!
//! A `sluice up` source with `shape: sentinel_common_security_log` runs
//! [`common_security_log_program`] after its archive. It reads raw `filterlog` lines (from
//! firewalls built on `pf`) and parsed firewall records in two namings: flat (`src_ip`, `dst_port`, `proto`, `action`, `direction`, as the
//! `opnsense/filterlog` recipes expect) and ECS (`source.ip`, `destination.port`,
//! `network.transport`, `event.action`, `network.direction`). `DeviceVendor` is always set, if
//! only to `""`: rules on the table are bounded to records that have it.

use serde_json::{Value, json};

/// The DCR stream Sluice sends `CommonSecurityLog` records to.
pub const COMMON_SECURITY_LOG_STREAM: &str = "Custom-SluiceCommonSecurityLog";

/// The `CommonSecurityLog` columns Sluice fills, with their types (from the tables API).
pub const COMMON_SECURITY_LOG_COLUMNS: [(&str, &str); 18] = [
    ("TimeGenerated", "datetime"),
    ("DeviceVendor", "string"),
    ("DeviceProduct", "string"),
    ("DeviceVersion", "string"),
    ("DeviceName", "string"),
    ("Computer", "string"),
    ("DeviceAction", "string"),
    ("Activity", "string"),
    ("DeviceEventClassID", "string"),
    ("CommunicationDirection", "string"),
    ("SourceIP", "string"),
    ("SourcePort", "int"),
    ("DestinationIP", "string"),
    ("DestinationPort", "int"),
    ("Protocol", "string"),
    ("DeviceInboundInterface", "string"),
    ("DeviceOutboundInterface", "string"),
    ("Message", "string"),
];

/// VRL that turns a firewall record into a `CommonSecurityLog` record.
#[must_use]
pub fn common_security_log_program() -> String {
    format!("{FILTERLOG}{CEF}")
}

/// VRL that reads a raw `filterlog` line (firewalls built on `pf`) (CSV, usually inside a syslog line)
/// into the flat fields, unless the record already has them. Positions follow the documented
/// format: rule, sub-rule, anchor, tracker, interface, reason, action, direction, IP version,
/// then for IPv4 `tos, ecn, ttl, id, offset, flags, protocol id, protocol, length, src, dst` and
/// for IPv6 `class, flow label, hop limit, protocol, protocol id, length, src, dst`, then the
/// ports for TCP and UDP.
pub(crate) const FILTERLOG: &str = r#"_line = if is_string(.message) { string!(.message) } else { "" }
_inner = _line
_app = .appname
if !exists(.appname) && starts_with(_line, "<") {
  _sys = parse_syslog(_line) ?? {}
  if is_string(_sys.message) { _inner = string!(_sys.message) }
  _app = _sys.appname
  if !exists(.hostname) { .hostname = _sys.hostname }
  if !exists(.timestamp) { .timestamp = _sys.timestamp }
}
_csv = _app == "filterlog" || match(_inner, r'^\d+,[^,]*,[^,]*,[^,]*,[^,]+,[a-z-]+,(pass|block|reject),(in|out),[46],')
if _csv && !exists(.src_ip) && !exists(.source.ip) {
  _f = split(_inner, ",")
  .rule_number = _f[0]
  .interface = _f[4]
  .reason = _f[5]
  .action = _f[6]
  .direction = _f[7]
  .ip_version = _f[8]
  _ports = 0
  if _f[8] == "4" {
    .proto = _f[16]
    .src_ip = _f[18]
    .dst_ip = _f[19]
    _ports = 20
  } else if _f[8] == "6" {
    .proto = _f[12]
    .src_ip = _f[15]
    .dst_ip = _f[16]
    _ports = 17
  }
  if .proto == "tcp" || .proto == "udp" {
    if _ports == 20 {
      .src_port = _f[20]
      .dst_port = _f[21]
    } else if _ports == 17 {
      .src_port = _f[17]
      .dst_port = _f[18]
    }
  }
  .event.dataset = "filterlog"
  .message = _inner
}
"#;

/// VRL that maps the flat or ECS fields to `CommonSecurityLog` columns.
const CEF: &str = r#"_out = {}
_out.TimeGenerated = if exists(."@timestamp") { ."@timestamp" } else { .timestamp }
_out.DeviceVendor = if is_string(.observer.vendor) { .observer.vendor } else { "" }
_out.DeviceProduct = .observer.product
_out.DeviceVersion = .observer.version
_host = if exists(.observer.hostname) { .observer.hostname } else if exists(.host.name) { .host.name } else { .hostname }
_out.DeviceName = _host
_out.Computer = _host
_out.DeviceAction = if exists(.action) { .action } else { .event.action }
_out.Activity = if exists(.event.dataset) { .event.dataset } else { .event.action }
_out.DeviceEventClassID = if exists(.rule_number) { to_string(.rule_number) ?? null } else { .rule.id }
_d = if exists(.direction) { .direction } else { .network.direction }
_dir = if is_string(_d) { downcase(string!(_d)) } else { "" }
_out.CommunicationDirection = if _dir == "in" || _dir == "inbound" || _dir == "ingress" { "Inbound" } else if _dir == "out" || _dir == "outbound" || _dir == "egress" { "Outbound" } else { null }
_out.SourceIP = if exists(.src_ip) { .src_ip } else { .source.ip }
_sp = if exists(.src_port) { .src_port } else { .source.port }
_out.SourcePort = if _sp == null { null } else { to_int(_sp) ?? null }
_out.DestinationIP = if exists(.dst_ip) { .dst_ip } else { .destination.ip }
_dp = if exists(.dst_port) { .dst_port } else { .destination.port }
_out.DestinationPort = if _dp == null { null } else { to_int(_dp) ?? null }
_proto = if exists(.proto) { .proto } else { .network.transport }
_out.Protocol = if is_string(_proto) { upcase(string!(_proto)) } else { null }
_iface = if exists(.interface) { .interface } else { .observer.ingress.interface.name }
_out.DeviceInboundInterface = if _out.CommunicationDirection == "Inbound" { _iface } else { null }
_out.DeviceOutboundInterface = if _out.CommunicationDirection == "Outbound" { _iface } else { null }
_out.Message = if exists(.message) { .message } else { .event.original }
. = compact(_out, recursive: false, string: false, object: false, array: false)
"#;

/// A data collection rule that stores the records in `CommonSecurityLog` unchanged.
#[must_use]
pub fn common_security_log_dcr(location: &str, workspace_resource_id: &str) -> Value {
    let columns: Vec<Value> = COMMON_SECURITY_LOG_COLUMNS
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": { COMMON_SECURITY_LOG_STREAM: { "columns": columns } },
            "destinations": {
                "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
            },
            "dataFlows": [{
                "streams": [COMMON_SECURITY_LOG_STREAM],
                "destinations": ["sentinel"],
                "transformKql": "source",
                "outputStream": "Microsoft-CommonSecurityLog",
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
        let program = CompiledProgram::compile("csl", common_security_log_program())
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
    fn a_flat_filterlog_record_becomes_cef_columns() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:49.000Z", "action": "pass", "direction": "out",
            "dst_ip": "13.107.42.14", "dst_port": 80, "interface": "igb1", "proto": "tcp",
            "rule_number": 12, "src_ip": "10.10.0.20", "src_port": 64664,
            "message": "12,,,1000000065,igb1,match,pass,out,4",
            "event": { "dataset": "opnsense.filterlog" },
            "observer": { "hostname": "fw01", "product": "OPNsense", "vendor": "Deciso", "version": "24.7.5" },
        }));
        assert_eq!(out["DeviceVendor"], "Deciso");
        assert_eq!(out["DeviceProduct"], "OPNsense");
        assert_eq!(out["Computer"], "fw01");
        assert_eq!(out["DeviceAction"], "pass");
        assert_eq!(out["CommunicationDirection"], "Outbound");
        assert_eq!(out["DeviceOutboundInterface"], "igb1");
        assert!(out.get("DeviceInboundInterface").is_none());
        assert_eq!(out["SourceIP"], "10.10.0.20");
        assert_eq!(out["SourcePort"], 64664);
        assert_eq!(out["DestinationPort"], 80);
        assert_eq!(out["Protocol"], "TCP");
        assert_eq!(out["DeviceEventClassID"], "12");
        assert_eq!(out["Activity"], "opnsense.filterlog");
    }

    #[test]
    fn ecs_records_map_too_and_the_vendor_is_always_there() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:49.000Z",
            "source": { "ip": "203.0.113.9", "port": "50022" },
            "destination": { "ip": "10.0.0.5", "port": 22 },
            "network": { "transport": "udp", "direction": "inbound" },
            "event": { "action": "block" },
        }));
        assert_eq!(out["DeviceVendor"], "");
        assert_eq!(out["SourceIP"], "203.0.113.9");
        assert_eq!(out["SourcePort"], 50022);
        assert_eq!(out["CommunicationDirection"], "Inbound");
        assert_eq!(out["Protocol"], "UDP");
        assert_eq!(out["DeviceAction"], "block");
    }

    #[test]
    fn raw_filterlog_lines_are_parsed() {
        let v4 = shaped(&json!({
            "message": "<134>Oct 11 18:00:00 fw01 filterlog[4242]: 12,,,1000000065,igb1,match,pass,out,4,0x0,,75,23425,0,DF,6,tcp,680,10.10.0.20,13.107.42.14,64664,80,640,S,,,,",
        }));
        assert_eq!(v4["Computer"], "fw01");
        assert_eq!(v4["DeviceAction"], "pass");
        assert_eq!(v4["CommunicationDirection"], "Outbound");
        assert_eq!(v4["Protocol"], "TCP");
        assert_eq!(v4["SourceIP"], "10.10.0.20");
        assert_eq!(v4["DestinationPort"], 80);
        assert_eq!(v4["DeviceEventClassID"], "12");
        assert_eq!(v4["Activity"], "filterlog");
        assert!(v4["TimeGenerated"].is_string());
        let v6 = shaped(&json!({
            "appname": "filterlog", "hostname": "fw02", "timestamp": "2026-10-11T18:00:00Z",
            "message": "5,,,1000000103,igb0,match,block,in,6,0x00,0x00000,64,udp,17,72,2001:db8::1,2001:db8::2,5353,53,72",
        }));
        assert_eq!(v6["DeviceAction"], "block");
        assert_eq!(v6["CommunicationDirection"], "Inbound");
        assert_eq!(v6["DeviceInboundInterface"], "igb0");
        assert_eq!(v6["Protocol"], "UDP");
        assert_eq!(v6["SourceIP"], "2001:db8::1");
        assert_eq!(v6["SourcePort"], 5353);
        assert_eq!(v6["DestinationPort"], 53);
        let icmp = shaped(&json!({
            "message": "7,,,1000000104,igb1,match,block,in,4,0x0,,64,1,0,none,1,icmp,84,192.0.2.1,10.0.0.1,request,1,2",
        }));
        assert_eq!(icmp["Protocol"], "ICMP");
        assert!(icmp.get("SourcePort").is_none());
    }

    #[test]
    fn the_dcr_stores_records_in_common_security_log_unchanged() {
        let dcr = common_security_log_dcr("westeurope", "/ws");
        assert_eq!(
            dcr["properties"]["dataFlows"][0]["outputStream"],
            "Microsoft-CommonSecurityLog"
        );
    }
}
