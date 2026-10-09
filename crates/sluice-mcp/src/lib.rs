//! The MCP server (`sluice mcp`): lets an AI assistant ask what Sluice cut, why, and whether it
//! still holds, and look things up in the archive.
//!
//! It speaks MCP over stdio ([`serve_stdio`]) or streamable HTTP behind a bearer token
//! ([`serve_http`]). It is a thin, read-mostly view. Live state comes from the control plane's `GET /status`, so
//! the server holds no state of its own and can be started and stopped freely. Archive search is
//! bounded per call. Replay changes what reaches a SIEM, so it is only offered when the operator
//! starts the server with replay allowed.

mod answers;
mod error;
mod http;
mod tools;

use std::path::PathBuf;

use rmcp::ServiceExt;

pub use crate::error::McpError;
pub use crate::http::{HttpOptions, MIN_TOKEN_LEN, serve_http};
use crate::tools::Sluice;

/// What the server connects to and allows.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// The control plane's address, such as `127.0.0.1:8686`.
    pub control_plane: String,
    /// The archive directory. Without it, the archive tools are not offered.
    pub archive: Option<PathBuf>,
    /// Offer the `replay` tool.
    pub allow_replay: bool,
}

/// Serves MCP over stdin and stdout until the client disconnects.
///
/// # Errors
///
/// Returns [`McpError::Serve`] if the session cannot start or ends with a transport error.
pub async fn serve_stdio(config: McpConfig) -> Result<(), McpError> {
    let service = Sluice::new(config)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| McpError::Serve(e.to_string()))?;
    service
        .waiting()
        .await
        .map_err(|e| McpError::Serve(e.to_string()))?;
    Ok(())
}
