//! Errors of the MCP server.

/// Why the MCP server stopped. Failures inside a tool are reported to the client as tool errors
/// instead, so the assistant can see and explain them.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    /// The MCP session could not start or broke off.
    #[error("MCP session failed: {0}")]
    Serve(String),
    /// The HTTP bearer token is too short to be safe.
    #[error("the MCP token must be at least {0} characters (for example `openssl rand -hex 32`)")]
    Token(usize),
}
