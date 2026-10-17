//! The MCP tools. Answers are built in [`crate::answers`]; this module fetches and wires.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sluice_archive::{Query, Scan, parse_time};
use sluice_core::ids::SourceId;
use sluice_server::{RuleInfo, Status};

use crate::McpConfig;
use crate::answers::{self, utc};

/// Most events one `search_archive` call returns: enough to reason about, small enough for a
/// model's context.
const MAX_EVENTS: usize = 100;

const INSTRUCTIONS: &str = "Sluice writes Vector configurations that send less data to a SIEM \
without changing any detection: it proves each saving against the rules before proposing it, \
re-proves what runs continuously, and switches savings off on any mismatch. Every event is \
archived in full before any saving. Use `status` for savings and \
proof, `explain` for what is done to a kind of event and why, `what_breaks` for which detections \
depend on a field or source, `coverage_gaps` and `source_health` for data problems, and \
`search_archive` to look at original events, including fields a reduction removed.";

/// The MCP server.
#[derive(Debug, Clone)]
pub(crate) struct Sluice {
    config: Arc<McpConfig>,
    tool_router: ToolRouter<Self>,
}

/// Which archived events to read.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
struct Selection {
    /// Source ids, such as `windows-security`. Empty or absent means every source.
    #[serde(default)]
    sources: Vec<String>,
    /// Earliest receive time, inclusive: RFC 3339 or `YYYY-MM-DD` (UTC).
    from: Option<String>,
    /// Latest receive time, exclusive: RFC 3339 or `YYYY-MM-DD` (UTC).
    to: Option<String>,
    /// Conditions that must all hold: `field=value`, `field!=value` or `field~text` (contains,
    /// ignoring case). Fields are dotted paths, such as `process.name`.
    #[serde(default, rename = "where")]
    conditions: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SearchRequest {
    #[serde(flatten)]
    selection: Selection,
    /// Most events to return (at most 100, default 20).
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ProfileRequest {
    /// The rule profile (the rules a group of destinations' SIEMs run), such as `sigma` or
    /// `sigma+wazuh`. Each is proven and cut separately. Default: the first one.
    profile: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TemplatesRequest {
    /// Only templates in this stage: `shadow` or `enforced`.
    stage: Option<String>,
    /// The rule profile, such as `sigma` or `sigma+wazuh` (default: the first).
    profile: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExplainRequest {
    /// Part of a template id or pattern, such as `4624`, `sysmon:10` or `pam_unix`.
    template: String,
    /// The rule profile, such as `sigma` or `sigma+wazuh` (default: the first).
    profile: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WhatBreaksRequest {
    /// A field, as a dotted path such as `TargetUserName` or `process.name`.
    field: Option<String>,
    /// A source id, such as `windows-security`. With a field: only rules for this source.
    /// Alone: every rule this source feeds.
    source: Option<String>,
    /// The rule profile, such as `sigma` or `sigma+wazuh` (default: the first).
    profile: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReplayRequest {
    #[serde(flatten)]
    selection: Selection,
    /// Endpoint that receives the events as newline-delimited JSON.
    url: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ActionToolRequest {
    /// `hold` (forward a template unchanged until released), `release`, `approve` (enforce a
    /// template's recipe in shadow at its next proof), `keep` or `unkeep` (a field of a source),
    /// or `acknowledge` (a rollback).
    action: String,
    /// The template id, for `hold`, `release`, `approve` and `acknowledge`.
    template: Option<String>,
    /// The source id, for `keep` and `unkeep`.
    source: Option<String>,
    /// The field, for `keep` and `unkeep`.
    field: Option<String>,
    /// The rollback's time (Unix seconds, from the history), for `acknowledge`.
    at: Option<i64>,
    /// Why, for the audit log. Give the user's own words.
    reason: Option<String>,
    /// The rule profile, such as `sigma` or `sigma+wazuh` (default: the first).
    profile: Option<String>,
}

#[tool_router]
impl Sluice {
    /// A server for `config`. Archive tools are offered only with an archive, and `replay` only
    /// when allowed.
    #[must_use]
    pub(crate) fn new(config: McpConfig) -> Self {
        let mut tool_router = Self::tool_router();
        if config.archive.is_none() {
            tool_router.remove_route("search_archive");
        }
        if config.archive.is_none() || config.replay_to.is_empty() {
            tool_router.remove_route("replay");
        }
        if !config.allow_actions {
            tool_router.remove_route("operator_action");
        }
        Self {
            config: Arc::new(config),
            tool_router,
        }
    }

    #[tool(
        description = "Live status of `sluice up`: ingest savings and the detection proof of the \
                       last cycle, how many reductions are enforced or in shadow, and recent \
                       transitions (promotions and rollbacks)."
    )]
    async fn status(
        &self,
        Parameters(request): Parameters<ProfileRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .fetch::<Status>(&status_path(request.profile.as_deref()))
            .await
        {
            Ok(status) => reply(&answers::status(&status)),
            Err(message) => Ok(failure(message)),
        }
    }

    #[tool(
        description = "Templates (event shapes) with a proven reduction and their stage: \
                       `shadow` (proven, not yet enforced) or `enforced` (Vector applies it)."
    )]
    async fn templates(
        &self,
        Parameters(request): Parameters<TemplatesRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let status = match self
            .fetch::<Status>(&status_path(request.profile.as_deref()))
            .await
        {
            Ok(status) => status,
            Err(message) => return Ok(failure(message)),
        };
        let templates: Vec<Value> = status
            .templates
            .iter()
            .filter(|t| request.stage.as_ref().is_none_or(|s| *s == t.stage))
            .map(|t| {
                json!({
                    "template": t.template,
                    "stage": t.stage,
                    "since": utc(t.since),
                    "proofs": t.proofs,
                })
            })
            .collect();
        reply(&json!({ "templates": templates }))
    }

    #[tool(
        description = "What Sluice does to a kind of event and why: the reductions, why a \
                       proposal was narrowed or refused (usually because a rule needs the data), \
                       where it came from, and its volume and savings in the last window."
    )]
    async fn explain(
        &self,
        Parameters(request): Parameters<ExplainRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .fetch::<Status>(&status_path(request.profile.as_deref()))
            .await
        {
            Ok(status) => reply(&answers::explain(&status, &request.template)),
            Err(message) => Ok(failure(message)),
        }
    }

    #[tool(
        description = "Which loaded detection rules depend on a field or a source, so would \
                       break if it went missing or was renamed upstream. Sluice itself never \
                       removes data these rules need."
    )]
    async fn what_breaks(
        &self,
        Parameters(request): Parameters<WhatBreaksRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        if request.field.is_none() && request.source.is_none() {
            return Ok(failure("give a field, a source, or both".to_owned()));
        }
        let path = status_path(request.profile.as_deref());
        let fetched = tokio::try_join!(
            self.fetch::<Status>(&path),
            self.fetch::<Vec<RuleInfo>>("rules")
        );
        let (status, rules) = match fetched {
            Ok(both) => both,
            Err(message) => return Ok(failure(message)),
        };
        match answers::what_breaks(
            &status,
            &rules,
            request.field.as_deref(),
            request.source.as_deref(),
        ) {
            Ok(answer) => reply(&answer),
            Err(message) => Ok(failure(message)),
        }
    }

    #[tool(
        description = "Rules that cannot fire because no traffic matches their log source, rules \
                       or recipes Sluice could not fully understand (treated with care), and \
                       sources whose description is incomplete, which keeps rules in scope that \
                       may not belong there."
    )]
    async fn coverage_gaps(
        &self,
        Parameters(request): Parameters<ProfileRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .fetch::<Status>(&status_path(request.profile.as_deref()))
            .await
        {
            Ok(status) => reply(&answers::coverage_gaps(&status)),
            Err(message) => Ok(failure(message)),
        }
    }

    #[tool(
        description = "Per source in the last window: events, templates, bytes in and out, and \
                       warnings such as a source that went silent."
    )]
    async fn source_health(
        &self,
        Parameters(request): Parameters<ProfileRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        match self
            .fetch::<Status>(&status_path(request.profile.as_deref()))
            .await
        {
            Ok(status) => reply(&answers::source_health(&status)),
            Err(message) => Ok(failure(message)),
        }
    }

    #[tool(
        description = "Search the full-fidelity archive: original events exactly as received, \
                       before any reduction. Bounded to 100 events per call; narrow by source, \
                       time and conditions."
    )]
    async fn search_archive(
        &self,
        Parameters(request): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let limit = request.limit.unwrap_or(20).clamp(1, MAX_EVENTS);
        let mut scan = match self.scan(&request.selection) {
            Ok(scan) => scan,
            Err(message) => return Ok(failure(message)),
        };
        let (mut events, stats) = tokio::task::spawn_blocking(move || {
            let events: Vec<Value> = scan
                .by_ref()
                .take(limit + 1)
                .map(
                    |r| json!({ "source": r.source, "received": utc(r.time.0), "event": r.fields }),
                )
                .collect();
            (events, scan.stats().clone())
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let more = events.len() > limit;
        events.truncate(limit);
        reply(&json!({
            "events": events,
            "more_available": more,
            "files_read": stats.files,
            "incomplete_files": stats.incomplete.len(),
        }))
    }

    #[tool(
        description = "Steer Sluice for a rule profile: hold or release a template, approve a \
                       recipe in shadow, keep or unkeep a field of a source, or acknowledge a \
                       rollback. None of these can weaken the safety contract, but each changes \
                       what the SIEM receives or when: confirm with the user first, and pass \
                       their reason. Every action is audited."
    )]
    async fn operator_action(
        &self,
        Parameters(request): Parameters<ActionToolRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut body = serde_json::Map::new();
        body.insert("action".into(), Value::String(request.action));
        let optional = [
            ("template", request.template.map(Value::String)),
            ("source", request.source.map(Value::String)),
            ("field", request.field.map(Value::String)),
            ("at", request.at.map(Value::from)),
            ("reason", request.reason.map(Value::String)),
            ("profile", request.profile.map(Value::String)),
        ];
        for (key, value) in optional {
            if let Some(value) = value {
                body.insert(key.into(), value);
            }
        }
        match self.post("actions", &Value::Object(body)).await {
            Ok(answer) => reply(&json!({ "done": answer })),
            Err(message) => Ok(failure(message)),
        }
    }

    #[tool(
        description = "Send archived events, exactly as received, to an HTTP endpoint (for \
                       example the SIEM's ingest). Changes what the SIEM holds: confirm the \
                       selection and destination with the user first."
    )]
    async fn replay(
        &self,
        Parameters(request): Parameters<ReplayRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        if !self.config.replay_to.contains(&request.url) {
            return Ok(failure(format!(
                "replay only sends to the endpoints Sluice was started with (--replay-to): {}",
                self.config.replay_to.join(", ")
            )));
        }
        let mut scan = match self.scan(&request.selection) {
            Ok(scan) => scan,
            Err(message) => return Ok(failure(message)),
        };
        let url = request.url;
        let sent = tokio::task::spawn_blocking(move || {
            sluice_archive::replay(&mut scan, &url, 500).map(|sent| (sent, url))
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        match sent {
            Ok((sent, url)) => reply(&json!({ "replayed": sent, "to": url })),
            Err(error) => Ok(failure(error.to_string())),
        }
    }
}

// The router field, not a fresh `Self::tool_router()`: `new` removes the tools this server must
// not offer, such as `replay` without `--replay-to`.
#[tool_handler(router = self.tool_router)]
#[allow(
    clippy::unused_async_trait_impl,
    reason = "the async handlers are generated by rmcp's macro"
)]
impl ServerHandler for Sluice {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            // `Implementation::from_build_env` would name rmcp itself: it expands in rmcp's crate.
            .with_server_info(
                Implementation::new("sluice", env!("CARGO_PKG_VERSION")).with_title("Sluice"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

impl Sluice {
    /// `GET /<path>` on the control plane.
    async fn fetch<T: DeserializeOwned + Send + 'static>(&self, path: &str) -> Result<T, String> {
        let url = format!("http://{}/{path}", self.config.control_plane);
        let token = self.config.control_token.clone();
        tokio::task::spawn_blocking(move || {
            let mut request = ureq::get(&url);
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            let body = request
                .call()
                .and_then(|mut r| r.body_mut().read_to_string())
                .map_err(|e| {
                    format!("cannot reach the control plane at {url}: {e}. Is `sluice up` running?")
                })?;
            serde_json::from_str(&body).map_err(|e| format!("unexpected answer from {url}: {e}"))
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// `POST /<path>` on the control plane with a JSON body; the answer text, or why it failed.
    async fn post(&self, path: &str, body: &Value) -> Result<String, String> {
        let url = format!("http://{}/{path}", self.config.control_plane);
        let token = self.config.control_token.clone();
        let body = body.to_string();
        tokio::task::spawn_blocking(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into();
            let mut request = agent.post(&url).header("content-type", "application/json");
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            let mut answer = request.send(&body).map_err(|e| {
                format!("cannot reach the control plane at {url}: {e}. Is `sluice up` running?")
            })?;
            let status = answer.status();
            let text = answer
                .body_mut()
                .read_to_string()
                .map_err(|e| e.to_string())?;
            if status.is_success() {
                Ok(text.trim().to_owned())
            } else {
                Err(format!("refused ({status}): {}", text.trim()))
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    fn scan(&self, selection: &Selection) -> Result<Scan, String> {
        let Some(archive) = &self.config.archive else {
            return Err("no archive configured: start `sluice mcp --archive DIR`".to_owned());
        };
        let time = |t: Option<&str>| t.map(parse_time).transpose().map_err(|e| e.to_string());
        let query = Query {
            sources: selection.sources.iter().map(SourceId::new).collect(),
            from: time(selection.from.as_deref())?,
            to: time(selection.to.as_deref())?,
            conditions: selection
                .conditions
                .iter()
                .map(|c| {
                    c.parse()
                        .map_err(|e: sluice_archive::ArchiveError| e.to_string())
                })
                .collect::<Result<_, _>>()?,
        };
        Scan::new(archive, query).map_err(|e| e.to_string())
    }
}

/// The control plane path of a profile's status (the first profile without one).
fn status_path(profile: Option<&str>) -> String {
    profile.map_or_else(
        || "status".to_owned(),
        |p| format!("status?profile={}", percent_encode(p)),
    )
}

/// Encodes a query value: everything but unreserved characters (RFC 3986) as `%XX`.
fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn reply(value: &Value) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::json(value)?]))
}

/// A failure the assistant should see and explain, as opposed to a protocol error.
fn failure(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

#[cfg(test)]
mod tests;
