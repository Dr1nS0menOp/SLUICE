//! Firewall records as Microsoft Sentinel's normalized `ASimNetworkSessionLogs` table (ASIM
//! Network Session schema), which ASIM parsers and the rules that use them read directly.
//!
//! A `sluice up` source with `shape: sentinel_asim_network_session` runs
//! [`asim_network_session_program`] after its archive. It reads the same records as the
//! `CommonSecurityLog` shape (raw `filterlog` lines, flat or ECS fields). The ASIM values follow
//! what Microsoft's own Network Session parsers set most (Azure/Azure-Sentinel, commit `55296e6`):
//! schema version `0.2.6`, event type `NetworkSession`, actions `Allow`/`Deny`/`Reset`, and
//! `EventResult` `Failure` for anything not allowed. `EventSchemaVersion` is always set: rules on
//! the table are bounded to records that have it.

use serde_json::{Value, json};

use crate::common_security_log::FILTERLOG;

/// The DCR stream Sluice sends `ASimNetworkSessionLogs` records to.
pub const ASIM_NETWORK_SESSION_STREAM: &str = "Custom-SluiceASimNetworkSession";

/// The `ASimNetworkSessionLogs` columns Sluice fills, with their types (from the tables API).
pub const ASIM_NETWORK_SESSION_COLUMNS: [(&str, &str); 25] = [
    ("TimeGenerated", "datetime"),
    ("EventStartTime", "datetime"),
    ("EventEndTime", "datetime"),
    ("EventCount", "int"),
    ("EventType", "string"),
    ("EventResult", "string"),
    ("EventSeverity", "string"),
    ("EventSchemaVersion", "string"),
    ("EventVendor", "string"),
    ("EventProduct", "string"),
    ("EventProductVersion", "string"),
    ("Dvc", "string"),
    ("DvcHostname", "string"),
    ("DvcAction", "string"),
    ("DvcOriginalAction", "string"),
    ("DvcInboundInterface", "string"),
    ("DvcOutboundInterface", "string"),
    ("NetworkDirection", "string"),
    ("NetworkProtocol", "string"),
    ("NetworkProtocolVersion", "string"),
    ("NetworkRuleNumber", "int"),
    ("SrcIpAddr", "string"),
    ("SrcPortNumber", "int"),
    ("DstIpAddr", "string"),
    ("DstPortNumber", "int"),
];

/// VRL that turns a firewall record into an `ASimNetworkSessionLogs` record.
#[must_use]
pub fn asim_network_session_program() -> String {
    format!("{FILTERLOG}{ASIM}")
}

const ASIM: &str = r#"_out = {}
_time = if exists(."@timestamp") { ."@timestamp" } else { .timestamp }
_out.TimeGenerated = _time
_out.EventStartTime = _time
_out.EventEndTime = _time
_out.EventCount = 1
_out.EventType = "NetworkSession"
_out.EventSchemaVersion = "0.2.6"
_out.EventSeverity = "Informational"
_out.EventVendor = .observer.vendor
_out.EventProduct = .observer.product
_out.EventProductVersion = .observer.version
_host = if exists(.observer.hostname) { .observer.hostname } else if exists(.host.name) { .host.name } else { .hostname }
_out.Dvc = _host
_out.DvcHostname = _host
_a = if exists(.action) { .action } else { .event.action }
_action = if is_string(_a) { downcase(string!(_a)) } else { "" }
_out.DvcOriginalAction = _a
_out.DvcAction = if _action == "pass" || _action == "allow" || _action == "accept" { "Allow" } else if _action == "block" || _action == "deny" || _action == "drop" { "Deny" } else if _action == "reject" || _action == "reset" { "Reset" } else { null }
_out.EventResult = if _out.DvcAction == "Allow" { "Success" } else if _out.DvcAction == null { "NA" } else { "Failure" }
_d = if exists(.direction) { .direction } else { .network.direction }
_dir = if is_string(_d) { downcase(string!(_d)) } else { "" }
_out.NetworkDirection = if _dir == "in" || _dir == "inbound" || _dir == "ingress" { "Inbound" } else if _dir == "out" || _dir == "outbound" || _dir == "egress" { "Outbound" } else { null }
_iface = if exists(.interface) { .interface } else { .observer.ingress.interface.name }
_out.DvcInboundInterface = if _out.NetworkDirection == "Inbound" { _iface } else { null }
_out.DvcOutboundInterface = if _out.NetworkDirection == "Outbound" { _iface } else { null }
_proto = if exists(.proto) { .proto } else { .network.transport }
_out.NetworkProtocol = if is_string(_proto) { upcase(string!(_proto)) } else { null }
_v = if exists(.ip_version) { .ip_version } else { .network.type }
_version = if _v == null { "" } else { downcase(to_string(_v) ?? "") }
_out.NetworkProtocolVersion = if _version == "4" || _version == "ipv4" { "IPv4" } else if _version == "6" || _version == "ipv6" { "IPv6" } else { null }
_rule = if exists(.rule_number) { .rule_number } else { .rule.id }
_out.NetworkRuleNumber = if _rule == null { null } else { to_int(_rule) ?? null }
_out.SrcIpAddr = if exists(.src_ip) { .src_ip } else { .source.ip }
_sp = if exists(.src_port) { .src_port } else { .source.port }
_out.SrcPortNumber = if _sp == null { null } else { to_int(_sp) ?? null }
_out.DstIpAddr = if exists(.dst_ip) { .dst_ip } else { .destination.ip }
_dp = if exists(.dst_port) { .dst_port } else { .destination.port }
_out.DstPortNumber = if _dp == null { null } else { to_int(_dp) ?? null }
. = compact(_out, recursive: false, string: false, object: false, array: false)
"#;

/// A data collection rule that stores the records in `ASimNetworkSessionLogs` unchanged.
#[must_use]
pub fn asim_network_session_dcr(location: &str, workspace_resource_id: &str) -> Value {
    let columns: Vec<Value> = ASIM_NETWORK_SESSION_COLUMNS
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": { ASIM_NETWORK_SESSION_STREAM: { "columns": columns } },
            "destinations": {
                "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
            },
            "dataFlows": [{
                "streams": [ASIM_NETWORK_SESSION_STREAM],
                "destinations": ["sentinel"],
                "transformKql": "source",
                "outputStream": "Microsoft-ASimNetworkSessionLogs",
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
        let program = CompiledProgram::compile("asim", asim_network_session_program())
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
    fn a_blocked_packet_becomes_a_failed_network_session() {
        let out = shaped(&json!({
            "message": "<134>Oct 11 18:00:00 fw01 filterlog[4242]: 12,,,1000000065,igb1,match,block,in,4,0x0,,75,23425,0,DF,6,tcp,60,203.0.113.9,10.0.0.5,50022,22,0,S,,,,",
        }));
        assert_eq!(out["DvcAction"], "Deny");
        assert_eq!(out["DvcOriginalAction"], "block");
        assert_eq!(out["EventResult"], "Failure");
        assert_eq!(out["NetworkDirection"], "Inbound");
        assert_eq!(out["DvcInboundInterface"], "igb1");
        assert_eq!(out["NetworkProtocol"], "TCP");
        assert_eq!(out["SrcIpAddr"], "203.0.113.9");
        assert_eq!(out["DstPortNumber"], 22);
        assert_eq!(out["NetworkRuleNumber"], 12);
        assert_eq!(out["EventType"], "NetworkSession");
        assert_eq!(out["EventSchemaVersion"], "0.2.6");
        assert_eq!(out["DvcHostname"], "fw01");
        assert_eq!(out["NetworkProtocolVersion"], "IPv4");
    }

    #[test]
    fn a_parsed_record_maps_too() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:49.000Z", "action": "pass", "direction": "out",
            "dst_ip": "13.107.42.14", "dst_port": 443, "ip_version": 4, "proto": "udp",
            "src_ip": "10.10.0.20",
            "observer": { "hostname": "fw01", "product": "OPNsense", "vendor": "Deciso" },
        }));
        assert_eq!(out["DvcAction"], "Allow");
        assert_eq!(out["EventResult"], "Success");
        assert_eq!(out["NetworkProtocolVersion"], "IPv4");
        assert_eq!(out["EventVendor"], "Deciso");
        assert!(out.get("SrcPortNumber").is_none());
    }

    #[test]
    fn the_dcr_stores_records_in_the_asim_table_unchanged() {
        let dcr = asim_network_session_dcr("westeurope", "/ws");
        assert_eq!(
            dcr["properties"]["dataFlows"][0]["outputStream"],
            "Microsoft-ASimNetworkSessionLogs"
        );
    }
}
