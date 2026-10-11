//! The control plane's HTTP API.

use std::sync::{Arc, PoisonError};

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use sluice_core::ids::SourceId;

use crate::control::{Shared, as_object, lock};
use crate::operators::Actor;
use crate::status::{RuleInfo, Status};
use crate::unix_now;

/// Largest tap batch accepted (Vector batches up to 500 events).
const MAX_BODY: usize = 32 * 1024 * 1024;

pub(crate) fn router(shared: Arc<Shared>) -> Router {
    let protected = Router::new()
        .route("/tap/{source}", post(tap))
        .route("/status", get(status))
        .route("/rules", get(rules))
        .route("/actions", post(act))
        .route("/auth/me", get(me))
        .route("/archive/search", get(crate::archive::search))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&shared),
            authorize,
        ));
    Router::new()
        .merge(protected)
        .merge(crate::ui::router())
        .merge(crate::oidc::routes::router())
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}

/// Requires `Authorization: Bearer <token>` when the control plane has a control token or
/// operator tokens, and records who made the request ([`Actor`]): the operator's name, `token`
/// for the control token, or `local` when no token is configured.
async fn authorize(
    State(shared): State<Arc<Shared>>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(name) = shared.oidc.as_ref().and_then(|oidc| {
        crate::oidc::routes::session_id(request.headers())
            .and_then(|id| oidc.session(&id, unix_now()))
    }) {
        request.extensions_mut().insert(Actor(name));
        return next.run(request).await;
    }
    if shared.control_token.is_none() && shared.operators.is_empty() {
        request.extensions_mut().insert(Actor("local".to_owned()));
        return next.run(request).await;
    }
    let given = request
        .headers()
        .get(header::AUTHORIZATION)
        .map(|value| value.as_bytes().to_vec());
    let bearer = |token: &str| format!("Bearer {token}");
    let actor = given.and_then(|given| {
        let control = shared
            .control_token
            .as_deref()
            .is_some_and(|token| same(&given, bearer(token).as_bytes()));
        if control {
            return Some("token".to_owned());
        }
        // Every token is compared, so timing does not reveal which operator matched.
        let mut found = None;
        for operator in &shared.operators {
            if same(&given, bearer(&operator.token).as_bytes()) {
                found = Some(operator.name.clone());
            }
        }
        found
    });
    match actor {
        Some(actor) => {
            request.extensions_mut().insert(Actor(actor));
            next.run(request).await
        }
        None => (StatusCode::UNAUTHORIZED, "missing or wrong bearer token\n").into_response(),
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

/// `POST /actions`: an operator action (ADR 0016). Only JSON is accepted, which a cross-site
/// form cannot send; the bearer token guards it like every other route.
async fn act(
    State(shared): State<Arc<Shared>>,
    Extension(Actor(actor)): Extension<Actor>,
    Json(request): Json<crate::operator::ActionRequest>,
) -> (StatusCode, String) {
    match shared.act(&request, &actor, unix_now()) {
        Ok(()) => (
            StatusCode::OK,
            format!("{} {}\n", request.action.kind(), request.action.target()),
        ),
        Err(crate::operator::Refusal::Invalid(why)) => (StatusCode::CONFLICT, format!("{why}\n")),
        Err(crate::operator::Refusal::Failed(error)) => {
            tracing::error!(%error, "operator action not recorded");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the action could not be recorded\n".to_owned(),
            )
        }
    }
}

/// `GET /auth/me`: who the console is signed in as.
async fn me(Extension(Actor(actor)): Extension<Actor>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "actor": actor }))
}
