//! nginx access log (combined format), shipped by Filebeat as raw lines.
//!
//! A load balancer health check hits `/healthz` every few seconds on every backend: the textbook
//! low-value template no rule covers.

use crate::fields::{Fields, clf_time, object, rfc3339};
use crate::sources::{Ctx, Spec, beats_envelope, logsource, text_format};
use crate::world::{INTERNAL_IPS, SCANNER_IP, USER_AGENTS, WEB_PATHS};

pub(crate) const SPEC: Spec = Spec {
    id: "nginx",
    generate,
    logsource: || logsource("nginx", Some("access")),
    format: text_format,
};

pub(crate) const PATH_TRAVERSAL: &str = "path-traversal";

const BACKENDS: [&str; 2] = ["web01", "web02"];
const LOAD_BALANCER: &str = "10.10.3.2";

/// One HTTP request.
struct Request<'a> {
    client: &'a str,
    method: &'a str,
    path: &'a str,
    status: u64,
    bytes: u64,
    user_agent: &'a str,
}

fn generate(ctx: &mut Ctx) {
    for _ in 0..ctx.volume(5_000) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&BACKENDS);
        let request = Request {
            client: ctx.rng.pick(&INTERNAL_IPS),
            method: ctx.rng.pick(&["GET", "GET", "GET", "POST"]),
            path: ctx.rng.pick(&WEB_PATHS),
            status: *ctx.rng.pick(&[200, 200, 200, 304, 302, 404]),
            bytes: ctx.rng.between(200, 40_000),
            user_agent: ctx.rng.pick(&USER_AGENTS),
        };
        let fields = access(ctx, ts, host, &request);
        ctx.emit(ts, fields);
    }
    for _ in 0..ctx.volume(3_000) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&BACKENDS);
        let request = Request {
            client: LOAD_BALANCER,
            method: "GET",
            path: "/healthz",
            status: 200,
            bytes: 2,
            user_agent: "kube-probe/1.31",
        };
        let fields = access(ctx, ts, host, &request);
        ctx.emit(ts, fields);
    }
    path_traversal(ctx);
}

/// Scenario: a scanner tries path traversal against the web app.
fn path_traversal(ctx: &mut Ctx) {
    let start = ctx.at_percent(75);
    let paths = [
        "/static/../../../../etc/passwd",
        "/api/v1/orders?file=../../../../etc/shadow",
        "/..%2f..%2f..%2f..%2fetc%2fpasswd",
        "/static/%2e%2e/%2e%2e/%2e%2e/windows/win.ini",
    ];
    for (offset, path) in (0..).zip(paths) {
        let ts = start + offset;
        let request = Request {
            client: SCANNER_IP,
            method: "GET",
            path,
            status: 400,
            bytes: 157,
            user_agent: "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        };
        let fields = access(ctx, ts, "web01", &request);
        ctx.emit_attack(PATH_TRAVERSAL, ts, fields);
    }
}

fn access(ctx: &mut Ctx, ts: i64, host: &str, request: &Request<'_>) -> Fields {
    let line = format!(
        r#"{client} - - [{time}] "{method} {path} HTTP/1.1" {status} {bytes} "-" "{agent}""#,
        client = request.client,
        time = clf_time(ts),
        method = request.method,
        path = request.path,
        status = request.status,
        bytes = request.bytes,
        agent = request.user_agent,
    );
    let agent_id = format!("filebeat-{host}");
    beats_envelope("filebeat", host, &agent_id)
        .set("@timestamp", rfc3339(ts))
        .set(
            "host",
            object([("name", host.into()), ("hostname", host.into())]),
        )
        .set(
            "log",
            object([
                ("offset", ctx.rng.between(0, 900_000_000).into()),
                (
                    "file",
                    object([("path", "/var/log/nginx/access.log".into())]),
                ),
            ]),
        )
        .set("input", object([("type", "filestream".into())]))
        .set("fileset", object([("name", "access".into())]))
        .set("message", line)
}
