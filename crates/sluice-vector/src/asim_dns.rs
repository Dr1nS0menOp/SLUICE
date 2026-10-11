//! DNS query records as Microsoft Sentinel's normalized `ASimDnsActivityLogs` table (ASIM DNS
//! schema).
//!
//! A `sluice up` source with `shape: sentinel_asim_dns` runs [`asim_dns_program`] after its
//! archive. It reads ECS DNS fields (`dns.question.name`/`type`/`class`, `dns.response_code`,
//! `dns.id`, `dns.header_flags`, `dns.resolved_ip`, `client.ip`/`port`, `server.ip`). The ASIM
//! values follow Microsoft's DNS parsers (Azure/Azure-Sentinel, commit `55296e6`): schema version
//! `0.1.7`, event type `Query`, `EventResult` `Success` for `NOERROR` and `Failure` otherwise, the
//! response code name in `EventResultDetails`. Type, class and response code numbers are the IANA
//! DNS parameters. `DnsQuery` is always set, if only to `""`: rules on the table are bounded to
//! records that have it.

use serde_json::{Value, json};

/// The DCR stream Sluice sends `ASimDnsActivityLogs` records to.
pub const ASIM_DNS_STREAM: &str = "Custom-SluiceASimDns";

/// The `ASimDnsActivityLogs` columns Sluice fills, with their types (from the tables API).
pub const ASIM_DNS_COLUMNS: [(&str, &str); 24] = [
    ("TimeGenerated", "datetime"),
    ("EventStartTime", "datetime"),
    ("EventEndTime", "datetime"),
    ("EventCount", "int"),
    ("EventType", "string"),
    ("EventResult", "string"),
    ("EventResultDetails", "string"),
    ("EventSeverity", "string"),
    ("EventSchemaVersion", "string"),
    ("EventVendor", "string"),
    ("EventProduct", "string"),
    ("Dvc", "string"),
    ("SrcIpAddr", "string"),
    ("SrcPortNumber", "int"),
    ("DstIpAddr", "string"),
    ("DnsQuery", "string"),
    ("DnsQueryType", "int"),
    ("DnsQueryTypeName", "string"),
    ("DnsQueryClass", "int"),
    ("DnsQueryClassName", "string"),
    ("DnsResponseCode", "int"),
    ("DnsResponseName", "string"),
    ("DnsFlags", "string"),
    ("TransactionIdHex", "string"),
];

/// VRL that turns a DNS record into an `ASimDnsActivityLogs` record.
#[must_use]
pub fn asim_dns_program() -> String {
    r#"_out = {}
_time = if exists(."@timestamp") { ."@timestamp" } else { .timestamp }
_out.TimeGenerated = _time
_out.EventStartTime = _time
_out.EventEndTime = _time
_out.EventCount = 1
_out.EventType = "Query"
_out.EventSchemaVersion = "0.1.7"
_out.EventSeverity = "Informational"
_out.EventVendor = .observer.vendor
_out.EventProduct = if exists(.observer.product) { .observer.product } else { .resolver }
_out.Dvc = if exists(.observer.hostname) { .observer.hostname } else if exists(.host.name) { .host.name } else { .hostname }
_name = if exists(.dns.question.name) { .dns.question.name } else { .query.name }
_out.DnsQuery = if is_string(_name) { _name } else { "" }
_t = if exists(.dns.question.type) { .dns.question.type } else { .query.type }
_type = if is_string(_t) { upcase(string!(_t)) } else { "" }
_out.DnsQueryTypeName = if _type == "" { null } else { _type }
_types = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35, "DS": 43, "DNSKEY": 48, "SVCB": 64, "HTTPS": 65, "ANY": 255}
_out.DnsQueryType = get(_types, [_type]) ?? null
_c = if exists(.dns.question.class) { .dns.question.class } else { .query.class }
_class = if is_string(_c) { upcase(string!(_c)) } else { "" }
_out.DnsQueryClassName = if _class == "" { null } else { _class }
_classes = {"IN": 1, "CH": 3, "HS": 4, "ANY": 255}
_out.DnsQueryClass = get(_classes, [_class]) ?? null
_rc = if exists(.dns.response_code) { .dns.response_code } else { .response_code }
_rcode = if is_string(_rc) { upcase(string!(_rc)) } else { "" }
_codes = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5, "YXDOMAIN": 6, "YXRRSET": 7, "NXRRSET": 8, "NOTAUTH": 9, "NOTZONE": 10}
_out.DnsResponseCode = get(_codes, [_rcode]) ?? null
_out.EventResultDetails = if _rcode == "" { null } else { _rcode }
_out.EventResult = if _rcode == "" { "NA" } else if _rcode == "NOERROR" { "Success" } else { "Failure" }
_out.DnsResponseName = if is_array(.dns.resolved_ip) { join(array!(.dns.resolved_ip), ",") ?? null } else { null }
_out.DnsFlags = if is_array(.dns.header_flags) { join(array!(.dns.header_flags), " ") ?? null } else { null }
_out.TransactionIdHex = if is_integer(.dns.id) { format_int(int!(.dns.id), base: 16) ?? null } else { null }
_out.SrcIpAddr = .client.ip
_out.SrcPortNumber = if .client.port == null { null } else { to_int(.client.port) ?? null }
_out.DstIpAddr = if exists(.server.ip) { .server.ip } else { .destination.ip }
. = compact(_out, recursive: false, string: false, object: false, array: false)
"#
    .to_owned()
}

/// A data collection rule that stores the records in `ASimDnsActivityLogs` unchanged.
#[must_use]
pub fn asim_dns_dcr(location: &str, workspace_resource_id: &str) -> Value {
    let columns: Vec<Value> = ASIM_DNS_COLUMNS
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": { ASIM_DNS_STREAM: { "columns": columns } },
            "destinations": {
                "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
            },
            "dataFlows": [{
                "streams": [ASIM_DNS_STREAM],
                "destinations": ["sentinel"],
                "transformKql": "source",
                "outputStream": "Microsoft-ASimDnsActivityLogs",
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
        let program = CompiledProgram::compile("asim_dns", asim_dns_program())
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
    fn an_ecs_dns_record_becomes_an_asim_query() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:03:00.000Z",
            "client": { "ip": "10.10.1.21", "port": 64200 },
            "dns": {
                "header_flags": ["RD", "RA"], "id": 46188,
                "question": { "class": "IN", "name": "update.microsoft.com", "type": "A" },
                "resolved_ip": ["52.97.146.162"], "response_code": "NOERROR",
            },
            "resolver": "unbound",
        }));
        assert_eq!(out["DnsQuery"], "update.microsoft.com");
        assert_eq!(out["DnsQueryType"], 1);
        assert_eq!(out["DnsQueryTypeName"], "A");
        assert_eq!(out["DnsQueryClass"], 1);
        assert_eq!(out["DnsResponseCode"], 0);
        assert_eq!(out["EventResult"], "Success");
        assert_eq!(out["EventResultDetails"], "NOERROR");
        assert_eq!(out["DnsResponseName"], "52.97.146.162");
        assert_eq!(out["DnsFlags"], "RD RA");
        assert_eq!(out["SrcIpAddr"], "10.10.1.21");
        assert_eq!(out["SrcPortNumber"], 64200);
        assert_eq!(out["EventProduct"], "unbound");
        assert_eq!(out["EventSchemaVersion"], "0.1.7");
        assert_eq!(out["TransactionIdHex"], "b46c");
    }

    #[test]
    fn a_failed_lookup_is_a_failure_and_the_query_is_always_there() {
        let out = shaped(&json!({
            "dns": { "question": { "name": "nope.example", "type": "aaaa" }, "response_code": "nxdomain" },
        }));
        assert_eq!(out["EventResult"], "Failure");
        assert_eq!(out["DnsResponseCode"], 3);
        assert_eq!(out["DnsQueryType"], 28);
        let empty = shaped(&json!({ "message": "not dns" }));
        assert_eq!(empty["DnsQuery"], "");
        assert_eq!(empty["EventResult"], "NA");
    }

    #[test]
    fn the_dcr_stores_records_in_the_asim_table_unchanged() {
        let dcr = asim_dns_dcr("westeurope", "/ws");
        assert_eq!(
            dcr["properties"]["dataFlows"][0]["outputStream"],
            "Microsoft-ASimDnsActivityLogs"
        );
    }
}
