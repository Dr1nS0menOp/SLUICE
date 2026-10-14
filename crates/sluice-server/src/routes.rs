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

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::{Map, json};
    use tower::ServiceExt;

    use super::*;
    use crate::tests::{build, scratch};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn shared(name: &str, token: Option<&str>, operators: &[(&str, &str)]) -> Arc<Shared> {
        let mut destinations = Map::new();
        destinations.insert("siem".into(), json!({"type": "blackhole"}));
        let mut built = build(
            &scratch(&format!("routes-{name}")),
            token,
            destinations,
            false,
        )
        .unwrap();
        built.operators = operators
            .iter()
            .map(|(name, token)| crate::operators::Operator {
                name: (*name).to_owned(),
                token: (*token).to_owned(),
            })
            .collect();
        Arc::new(built)
    }

    async fn call(shared: &Arc<Shared>, request: Request<Body>) -> (StatusCode, String) {
        let response = router(Arc::clone(shared)).oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn me(authorization: Option<&str>) -> Request<Body> {
        let mut request = Request::get("/auth/me");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        request.body(Body::empty()).unwrap()
    }

    #[test]
    fn same_compares_whole_byte_strings() {
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"abcd"));
        assert!(same(b"", b""));
    }

    #[tokio::test]
    async fn almost_right_tokens_are_refused() {
        let shared = shared("near-tokens", Some(TOKEN), &[]);
        for wrong in [
            String::new(),
            "Bearer".to_owned(),
            "Bearer ".to_owned(),
            format!("bearer {TOKEN}"),
            format!("Bearer {TOKEN} "),
            format!("Bearer  {TOKEN}"),
            format!("Bearer {}", &TOKEN[..31]),
            format!("Bearer {TOKEN}x"),
            format!("Basic {TOKEN}"),
        ] {
            let (status, _) = call(&shared, me(Some(&wrong))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong:?}");
        }
        let (status, _) = call(&shared, me(None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = call(&shared, me(Some(&format!("Bearer {TOKEN}")))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"token\""));
    }

    #[tokio::test]
    async fn an_operator_token_names_the_operator() {
        let other = "fedcba9876543210fedcba9876543210";
        let shared = shared("operators", None, &[("alice", TOKEN), ("bob", other)]);
        let (status, body) = call(&shared, me(Some(&format!("Bearer {other}")))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"bob\""), "{body}");
        let (status, _) = call(&shared, me(None)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "operators alone require a token too"
        );
    }

    #[tokio::test]
    async fn without_any_token_the_caller_is_local() {
        let shared = shared("local", None, &[]);
        let (status, body) = call(&shared, me(None)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"local\""));
    }

    #[tokio::test]
    async fn health_needs_no_token() {
        let shared = shared("health", Some(TOKEN), &[]);
        let request = Request::get("/healthz").body(Body::empty()).unwrap();
        assert_eq!(
            call(&shared, request).await,
            (StatusCode::OK, "ok".to_owned())
        );
    }

    #[tokio::test]
    async fn actions_accept_json_only_so_a_cross_site_form_cannot_post_one() {
        let shared = shared("csrf", None, &[]);
        let form = Request::post("/actions")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("action=hold"))
            .unwrap();
        let (status, _) = call(&shared, form).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let text = Request::post("/actions")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            call(&shared, text).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[tokio::test]
    async fn the_tap_counts_what_it_accepts_and_refuses_non_objects() {
        let shared = shared("tap-mixed", None, &[]);
        let body = "{\"a\":1}\n[1,2]\nnot json\n\n42\n{\"b\":2}\n";
        let request = Request::post("/tap/windows-security")
            .body(Body::from(body))
            .unwrap();
        let (status, text) = call(&shared, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(text, "accepted 2, rejected 3\n");
    }

    #[tokio::test]
    async fn an_oversized_tap_batch_is_refused() {
        let shared = shared("tap-large", None, &[]);
        let body = "x".repeat(MAX_BODY + 1);
        let request = Request::post("/tap/windows-security")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            call(&shared, request).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn an_unknown_profile_is_not_found() {
        let shared = shared("profile", None, &[]);
        let request = Request::get("/status?profile=nope")
            .body(Body::empty())
            .unwrap();
        assert_eq!(call(&shared, request).await.0, StatusCode::NOT_FOUND);
    }
}
