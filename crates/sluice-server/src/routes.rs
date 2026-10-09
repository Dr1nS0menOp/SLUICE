//! The control plane's HTTP API.

use std::sync::{Arc, PoisonError};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use sluice_core::ids::SourceId;

use crate::control::{Shared, as_object, lock};
use crate::status::{RuleInfo, Status};
use crate::unix_now;

/// Largest tap batch accepted (Vector batches up to 500 events).
const MAX_BODY: usize = 32 * 1024 * 1024;

pub(crate) fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/tap/{source}", post(tap))
        .route("/status", get(status))
        .route("/rules", get(rules))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}

/// `POST /tap/{source}`: newline-delimited JSON objects from Vector's tap sink.
async fn tap(
    State(shared): State<Arc<Shared>>,
    Path(source): Path<String>,
    body: String,
) -> (StatusCode, String) {
    let source = SourceId::new(source);
    if !shared.sources.iter().any(|s| s.id == source) {
        return (StatusCode::NOT_FOUND, format!("unknown source {source}"));
    }
    let now = unix_now();
    let mut windows = lock(&shared.windows);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str(line).ok().and_then(as_object) {
            Some(fields) => {
                windows.push(&source, fields, now);
                accepted += 1;
            }
            None => rejected += 1,
        }
    }
    let status = if rejected == 0 {
        StatusCode::ACCEPTED
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status,
        format!("accepted {accepted}, rejected {rejected}\n"),
    )
}

/// `GET /rules`: what every loaded rule needs.
async fn rules(State(shared): State<Arc<Shared>>) -> Json<Vec<RuleInfo>> {
    Json(shared.rule_info.clone())
}

/// `GET /status`: the lifecycle and the last cycle.
async fn status(State(shared): State<Arc<Shared>>) -> Json<Status> {
    let status = shared.status.read().unwrap_or_else(PoisonError::into_inner);
    Json(status.clone())
}
