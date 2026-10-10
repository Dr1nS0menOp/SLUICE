//! The control plane's HTTP API.

use std::sync::{Arc, PoisonError};

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sluice_core::ids::SourceId;

use crate::control::{Shared, as_object, lock};
use crate::status::{RuleInfo, Status};
use crate::unix_now;

/// Largest tap batch accepted (Vector batches up to 500 events).
const MAX_BODY: usize = 32 * 1024 * 1024;

pub(crate) fn router(shared: Arc<Shared>) -> Router {
    let protected = Router::new()
        .route("/tap/{source}", post(tap))
        .route("/status", get(status))
        .route("/rules", get(rules))
        .route("/archive/search", get(crate::archive::search))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            authorize,
        ));
    Router::new()
        .merge(protected)
        .merge(crate::ui::router())
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}

/// Requires `Authorization: Bearer <token>` when the control plane has a token.
async fn authorize(State(shared): State<Arc<Shared>>, request: Request, next: Next) -> Response {
    let Some(token) = &shared.control_token else {
        return next.run(request).await;
    };
    let expected = format!("Bearer {token}");
    let given = request
        .headers()
        .get(header::AUTHORIZATION)
        .map(header::HeaderValue::as_bytes);
    if given.is_some_and(|given| same(given, expected.as_bytes())) {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "missing or wrong bearer token\n").into_response()
    }
}

/// Compares without stopping at the first difference, so timing reveals nothing about the token.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

/// The query of `GET /status`.
#[derive(Debug, Default, serde::Deserialize)]
struct StatusParams {
    /// The rule profile; the first one when absent.
    profile: Option<String>,
}

/// `GET /status[?profile=…]`: the lifecycle and the last cycle of one rule profile.
async fn status(
    State(shared): State<Arc<Shared>>,
    Query(params): Query<StatusParams>,
) -> Result<Json<Status>, (StatusCode, String)> {
    let profile = shared.profile(params.profile.as_deref()).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!(
                "no rule profile {}\n",
                params.profile.as_deref().unwrap_or("(none configured)")
            ),
        )
    })?;
    let status = profile
        .status
        .read()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(Json(status.clone()))
}
