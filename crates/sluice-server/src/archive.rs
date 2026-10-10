//! `GET /archive/search`: original events from the full-fidelity archive, for the web console.
//!
//! Read-only on purpose. Replaying events into a SIEM changes what it holds, so it stays with the
//! CLI (`sluice replay`) and the gated MCP tool, where the operator names the destination.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query as Params, State};
use axum::http::StatusCode;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sluice_archive::{Condition, Query, Scan, parse_time};
use sluice_core::ids::SourceId;

use crate::control::Shared;

/// Most events one search returns.
pub(crate) const MAX_EVENTS: usize = 100;

/// Most archive lines one search reads, so a search that matches nothing on a large archive
/// ends in bounded time. The answer then says it is incomplete.
pub(crate) const MAX_LINES: u64 = 2_000_000;

/// The query string: `source` and `where` may hold several entries, comma- and newline-separated.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct SearchParams {
    /// Source ids, comma-separated; none means every source.
    source: Option<String>,
    /// Earliest time, RFC 3339 or a date.
    from: Option<String>,
    /// Latest time (exclusive).
    to: Option<String>,
    /// Conditions such as `EventID=4624` or `CommandLine~mimikatz`, one per line.
    #[serde(rename = "where")]
    conditions: Option<String>,
    /// Events to return, 1 to [`MAX_EVENTS`].
    limit: Option<usize>,
}

/// One archived event.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Found {
    source: String,
    received: String,
    event: Map<String, Value>,
}

/// The answer, with what the scan read so the console can say how complete it is.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SearchResult {
    pub(crate) events: Vec<Found>,
    pub(crate) more_available: bool,
    pub(crate) files_read: usize,
    pub(crate) lines_read: u64,
    pub(crate) incomplete_files: usize,
    /// The line budget ran out before the archive was read to the end.
    pub(crate) truncated: bool,
}

pub(crate) async fn search(
    State(shared): State<Arc<Shared>>,
    Params(params): Params<SearchParams>,
) -> Result<Json<SearchResult>, (StatusCode, String)> {
    let query = query(&params).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let limit = params.limit.unwrap_or(25).clamp(1, MAX_EVENTS);
    let root = shared.config.archive_dir.clone();
    tokio::task::spawn_blocking(move || {
        let scan = Scan::new(&root, query).map_err(|e| e.to_string())?;
        Ok(collect(scan.with_line_budget(MAX_LINES), limit))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map(Json)
    .map_err(|e: String| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

fn query(params: &SearchParams) -> Result<Query, String> {
    let time = |t: Option<&String>| {
        t.map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(parse_time)
            .transpose()
            .map_err(|e| e.to_string())
    };
    Ok(Query {
        sources: params
            .source
            .iter()
            .flat_map(|s| s.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(SourceId::new)
            .collect(),
        from: time(params.from.as_ref())?,
        to: time(params.to.as_ref())?,
        conditions: params
            .conditions
            .iter()
            .flat_map(|c| c.lines())
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| c.parse::<Condition>().map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?,
    })
}

fn collect(mut scan: Scan, limit: usize) -> SearchResult {
    let mut events: Vec<Found> = scan
        .by_ref()
        .take(limit + 1)
        .map(|record| Found {
            source: record.source.to_string(),
            received: DateTime::from_timestamp(record.time.0, 0)
                .map_or_else(|| record.time.0.to_string(), |t| t.to_rfc3339()),
            event: record.fields,
        })
        .collect();
    let more_available = events.len() > limit;
    events.truncate(limit);
    let stats = scan.stats();
    SearchResult {
        events,
        more_available,
        files_read: stats.files,
        lines_read: stats.lines,
        incomplete_files: stats.incomplete.len(),
        truncated: stats.budget_exhausted,
    }
}
