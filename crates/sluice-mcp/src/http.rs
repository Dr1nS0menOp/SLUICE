//! MCP over streamable HTTP, behind a bearer token.
//!
//! The tools read the archive and can replay it, so the HTTP transport never runs open: every
//! request must carry `Authorization: Bearer <token>`. rmcp's host check (DNS rebinding
//! protection) stays on, with the operator's extra host names added.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::tools::Sluice;
use crate::{McpConfig, McpError};

/// The shortest token accepted: guessing it must be impractical.
pub const MIN_TOKEN_LEN: usize = 32;

/// How the HTTP transport listens and who may use it.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Address to listen on, such as `127.0.0.1:8687`.
    pub listen: SocketAddr,
    /// The bearer token clients must send. At least [`MIN_TOKEN_LEN`] characters.
    pub token: String,
    /// Host names clients use to reach the server, besides `localhost` and loopback addresses.
    pub allowed_hosts: Vec<String>,
}

/// Serves MCP at `http://<listen>/mcp` until SIGINT or SIGTERM.
///
/// # Errors
///
/// Returns [`McpError::Token`] for a short token, and [`McpError::Serve`] if the address cannot
/// be bound or the server fails.
pub async fn serve_http(config: McpConfig, options: HttpOptions) -> Result<(), McpError> {
    let listener = tokio::net::TcpListener::bind(options.listen)
        .await
        .map_err(|e| McpError::Serve(format!("cannot listen on {}: {e}", options.listen)))?;
    axum::serve(listener, router(config, &options)?)
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| McpError::Serve(e.to_string()))
}

pub(crate) fn router(config: McpConfig, options: &HttpOptions) -> Result<Router, McpError> {
    if options.token.chars().count() < MIN_TOKEN_LEN {
        return Err(McpError::Token(MIN_TOKEN_LEN));
    }
    let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    hosts.extend(options.allowed_hosts.iter().cloned());
    let server = Sluice::new(config);
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_allowed_hosts(hosts),
    );
    let token: Arc<str> = Arc::from(format!("Bearer {}", options.token));
    Ok(Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(token, authorize)))
}

async fn authorize(State(expected): State<Arc<str>>, request: Request, next: Next) -> Response {
    let given = request
        .headers()
        .get(header::AUTHORIZATION)
        .map(header::HeaderValue::as_bytes);
    if given.is_some_and(|given| same(given, expected.as_bytes())) {
        next.run(request).await
    } else {
        let mut response = Response::new("missing or wrong bearer token\n".into());
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
        response
    }
}

/// Compares without stopping at the first difference, so timing reveals nothing about the token.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn shutdown() {
    let interrupt = tokio::signal::ctrl_c();
    let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return interrupt.await.unwrap_or(());
    };
    tokio::select! {
        _ = interrupt => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use tower::ServiceExt;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app() -> Router {
        let config = McpConfig {
            control_plane: "127.0.0.1:9".into(),
            control_token: None,
            archive: None,
            allow_replay: false,
        };
        let options = HttpOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            token: TOKEN.into(),
            allowed_hosts: vec![],
        };
        router(config, &options).unwrap()
    }

    /// The first request of a session.
    fn initialize(authorization: Option<&str>) -> Request {
        let mut request = Request::post("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        request
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn requests_without_the_token_are_refused() {
        for authorization in [None, Some("Bearer wrong"), Some(TOKEN)] {
            let response = app().oneshot(initialize(authorization)).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{authorization:?}"
            );
        }
    }

    #[tokio::test]
    async fn requests_with_the_token_reach_the_server() {
        let response = app()
            .oneshot(initialize(Some(&format!("Bearer {TOKEN}"))))
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(r#""serverInfo":{"name":"sluice""#), "{body}");
    }

    #[test]
    fn short_tokens_are_rejected() {
        let options = HttpOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            token: "short".into(),
            allowed_hosts: vec![],
        };
        let config = McpConfig {
            control_plane: String::new(),
            control_token: None,
            archive: None,
            allow_replay: false,
        };
        assert!(matches!(router(config, &options), Err(McpError::Token(_))));
    }
}
