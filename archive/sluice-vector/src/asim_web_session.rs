//! Web server access logs as Microsoft Sentinel's normalized `ASimWebSessionLogs` table (ASIM Web
//! Session schema). Microsoft ships ASIM parsers for Apache and IIS but none for nginx, so nginx
//! access logs reach ASIM rules only through this table.
//!
//! A `sluice up` source with `shape: sentinel_asim_web_session` runs [`asim_web_session_program`]
//! after its archive. It reads a combined-format access line (in `message`, as Filebeat sends it,
//! parsed with VRL's `parse_nginx_log`) or ECS fields (`url.original`, `http.request.method`,
//! `http.response.status_code`, `source.ip`, `user_agent.original`). The values follow
//! Microsoft's Apache parser (Azure/Azure-Sentinel, commit `55296e6`): event type
//! `WebServerSession`, schema version `0.2.6`, the status code in `EventResultDetails`,
//! `EventResult` `Success` below 400, and `-` read as empty. Vendor and product come from
//! `observer.vendor`/`observer.product` when present, else `F5`/`NGINX`. `Url` is always set,
//! if only to `""`: rules on the table are bounded to records that have it.

use serde_json::{Value, json};

/// The DCR stream Sluice sends `ASimWebSessionLogs` records to.
pub const ASIM_WEB_SESSION_STREAM: &str = "Custom-SluiceASimWebSession";

/// The `ASimWebSessionLogs` columns Sluice fills, with their types (from the tables API).
pub const ASIM_WEB_SESSION_COLUMNS: [(&str, &str); 21] = [
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
    ("DvcHostname", "string"),
    ("Url", "string"),
    ("HttpRequestMethod", "string"),
    ("HttpVersion", "string"),
    ("HttpUserAgent", "string"),
    ("HttpReferrer", "string"),
    ("SrcIpAddr", "string"),
    ("SrcUsername", "string"),
    ("DstBytes", "long"),
];

/// VRL that turns an access log record into an `ASimWebSessionLogs` record.
#[must_use]
pub fn asim_web_session_program() -> String {
    r#"_line = if is_string(.message) { string!(.message) } else { "" }
_p = if _line == "" { {} } else { parse_nginx_log(_line, format: "combined") ?? {} }
_req = if is_string(_p.request) { split(string!(_p.request), " ") } else { [] }
_out = {}
_time = if exists(."@timestamp") { ."@timestamp" } else if exists(_p.timestamp) { _p.timestamp } else { .timestamp }
_out.TimeGenerated = _time
_out.EventStartTime = _time
_out.EventEndTime = _time
_out.EventCount = 1
_out.EventType = "WebServerSession"
_out.EventSchemaVersion = "0.2.6"
_out.EventSeverity = "Informational"
_out.EventVendor = if is_string(.observer.vendor) { .observer.vendor } else { "F5" }
_out.EventProduct = if is_string(.observer.product) { .observer.product } else { "NGINX" }
_host = if exists(.host.hostname) { .host.hostname } else if exists(.host.name) { .host.name } else { .hostname }
_out.Dvc = _host
_out.DvcHostname = _host
_url = if exists(.url.original) { .url.original } else { _req[1] }
_out.Url = if is_string(_url) { _url } else { "" }
_out.HttpRequestMethod = if exists(.http.request.method) { .http.request.method } else { _req[0] }
_proto = if exists(.http.version) { .http.version } else { _req[2] }
_out.HttpVersion = if is_string(_proto) { replace(string!(_proto), "HTTP/", "") } else { null }
_status = if exists(.http.response.status_code) { .http.response.status_code } else { _p.status }
_code = if _status == null { null } else { to_int(_status) ?? null }
_out.EventResultDetails = if _code == null { null } else { to_string(_code) }
_out.EventResult = if _code == null { "NA" } else if int!(_code) < 400 { "Success" } else { "Failure" }
_agent = if exists(.user_agent.original) { .user_agent.original } else { _p.agent }
_out.HttpUserAgent = if _agent == "-" { null } else { _agent }
_ref = if exists(.http.request.referrer) { .http.request.referrer } else { _p.referer }
_out.HttpReferrer = if _ref == "-" { null } else { _ref }
_out.SrcIpAddr = if exists(.source.ip) { .source.ip } else { _p.client }
_user = if exists(.user.name) { .user.name } else { _p.user }
_out.SrcUsername = if _user == "-" { null } else { _user }
_bytes = if exists(.http.response.body.bytes) { .http.response.body.bytes } else { _p.size }
_out.DstBytes = if _bytes == null { null } else { to_int(_bytes) ?? null }
. = compact(_out, recursive: false, string: false, object: false, array: false)
"#
    .to_owned()
}

/// A data collection rule that stores the records in `ASimWebSessionLogs` unchanged.
#[must_use]
pub fn asim_web_session_dcr(location: &str, workspace_resource_id: &str) -> Value {
    let columns: Vec<Value> = ASIM_WEB_SESSION_COLUMNS
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": { ASIM_WEB_SESSION_STREAM: { "columns": columns } },
            "destinations": {
                "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
            },
            "dataFlows": [{
                "streams": [ASIM_WEB_SESSION_STREAM],
                "destinations": ["sentinel"],
                "transformKql": "source",
                "outputStream": "Microsoft-ASimWebSessionLogs",
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
        let program = CompiledProgram::compile("asim_web", asim_web_session_program())
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
    fn a_combined_access_line_becomes_a_web_session() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:01.000Z",
            "host": { "hostname": "web01" },
            "message": "203.0.113.9 - bob [10/Oct/2026:08:00:01 +0000] \"POST /login HTTP/1.1\" 401 512 \"https://shop.example/\" \"curl/8.5\"",
        }));
        assert_eq!(out["Url"], "/login");
        assert_eq!(out["HttpRequestMethod"], "POST");
        assert_eq!(out["HttpVersion"], "1.1");
        assert_eq!(out["EventResultDetails"], "401");
        assert_eq!(out["EventResult"], "Failure");
        assert_eq!(out["SrcIpAddr"], "203.0.113.9");
        assert_eq!(out["SrcUsername"], "bob");
        assert_eq!(out["HttpReferrer"], "https://shop.example/");
        assert_eq!(out["HttpUserAgent"], "curl/8.5");
        assert_eq!(out["DstBytes"], 512);
        assert_eq!(out["DvcHostname"], "web01");
        assert_eq!(out["EventType"], "WebServerSession");
        assert_eq!(out["EventProduct"], "NGINX");
    }

    #[test]
    fn dashes_are_empty_and_success_is_below_400() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:01.000Z",
            "message": "10.10.3.2 - - [10/Oct/2026:08:00:01 +0000] \"GET /healthz HTTP/1.1\" 200 2 \"-\" \"kube-probe/1.31\"",
        }));
        assert_eq!(out["EventResult"], "Success");
        assert_eq!(out["Url"], "/healthz");
        assert!(out.get("SrcUsername").is_none() && out.get("HttpReferrer").is_none());
        let other = shaped(&json!({ "message": "not an access line" }));
        assert_eq!(other["Url"], "");
        assert_eq!(other["EventResult"], "NA");
    }

    #[test]
    fn ecs_fields_map_too() {
        let out = shaped(&json!({
            "@timestamp": "2026-10-10T08:00:01.000Z",
            "url": { "original": "/api" }, "http": { "request": { "method": "GET" }, "response": { "status_code": 503 } },
            "source": { "ip": "10.0.0.1" }, "observer": { "vendor": "Caddy", "product": "Caddy" },
        }));
        assert_eq!(out["Url"], "/api");
        assert_eq!(out["EventResult"], "Failure");
        assert_eq!(out["EventVendor"], "Caddy");
    }

    #[test]
    fn the_dcr_stores_records_in_the_asim_table_unchanged() {
        let dcr = asim_web_session_dcr("westeurope", "/ws");
        assert_eq!(
            dcr["properties"]["dataFlows"][0]["outputStream"],
            "Microsoft-ASimWebSessionLogs"
        );
    }
}
