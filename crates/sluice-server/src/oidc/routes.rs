//! The sign-in routes of single sign-on. They need no token: they are how an operator gets a
//! session in the first place.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::COOKIE;
use crate::control::Shared;
use crate::unix_now;

pub(crate) fn router() -> Router<Arc<Shared>> {
    Router::new()
        .route("/auth/info", get(info))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
}

/// The session id in a request's cookies.
pub(crate) fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(&format!("{COOKIE}="))
                .map(str::to_owned)
        })
        .filter(|id| !id.is_empty())
}

/// `GET /auth/info`: whether single sign-on is available, for the console's sign-in page.
async fn info(State(shared): State<Arc<Shared>>) -> Json<serde_json::Value> {
    Json(json!({ "oidc": shared.oidc.is_some() }))
}

/// `GET /auth/login`: sends the browser to the provider.
async fn login(State(shared): State<Arc<Shared>>) -> Response {
    if shared.oidc.is_none() {
        return (StatusCode::NOT_FOUND, "single sign-on is not configured\n").into_response();
    }
    let started = tokio::task::spawn_blocking(move || {
        shared.oidc.as_ref().map(|oidc| oidc.login_url(unix_now()))
    })
    .await;
    match started {
        Ok(Some(Ok(url))) => Redirect::to(&url).into_response(),
        Ok(Some(Err(why))) => {
            tracing::warn!(%why, "single sign-on could not start");
            (
                StatusCode::BAD_GATEWAY,
                format!("the identity provider is not reachable: {why}\n"),
            )
                .into_response()
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed\n").into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/callback`: the provider's answer; opens a session and returns to the console.
async fn callback(
    State(shared): State<Arc<Shared>>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(error) = params.error {
        return (
            StatusCode::FORBIDDEN,
            format!("the identity provider refused: {error}\n"),
        )
            .into_response();
    }
    let (Some(code), Some(state)) = (params.code, params.state) else {
        return (StatusCode::BAD_REQUEST, "missing code or state\n").into_response();
    };
    let done = tokio::task::spawn_blocking(move || {
        let oidc = shared.oidc.as_ref()?;
        Some((oidc.callback(&code, &state, unix_now()), shared))
    })
    .await;
    match done {
        Ok(Some((Ok((session, name)), shared))) => {
            tracing::info!(operator = %name, "signed in");
            let cookie = shared
                .oidc
                .as_ref()
                .map(|oidc| oidc.cookie(Some(&session)))
                .unwrap_or_default();
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Ok(Some((Err(why), _))) => {
            tracing::warn!(%why, "sign-in refused");
            (StatusCode::FORBIDDEN, format!("sign-in refused: {why}\n")).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "single sign-on is not configured\n").into_response(),
    }
}

/// `POST /auth/logout`: ends the session.
async fn logout(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let Some(oidc) = &shared.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(id) = session_id(&headers) {
        oidc.sign_out(&id);
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, oidc.cookie(None))],
    )
        .into_response()
}
