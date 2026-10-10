//! The web console: three static files built into the binary, served at `/`.
//!
//! The files hold no data, so they are served without the bearer token; the page asks for the
//! token and sends it with every API call, like any other client. Everything it shows comes from
//! `/status`, `/rules` and `/archive/search`. Archived events are untrusted input, so the page
//! writes them as text only, and the Content-Security-Policy allows no inline or third-party
//! script, style or connection.

use axum::Router;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;

const INDEX: &str = include_str!("../ui/index.html");
const SCRIPT: &str = include_str!("../ui/app.js");
const STYLE: &str = include_str!("../ui/app.css");

/// Same-origin only: the console talks to the control plane that served it and nothing else.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub(crate) fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(
            "/",
            get(|| async { file("text/html; charset=utf-8", INDEX) }),
        )
        .route(
            "/ui/app.js",
            get(|| async { file("text/javascript; charset=utf-8", SCRIPT) }),
        )
        .route(
            "/ui/app.css",
            get(|| async { file("text/css; charset=utf-8", STYLE) }),
        )
}

fn file(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
}
