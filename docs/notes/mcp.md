# rmcp (MCP Rust SDK): verified notes

Verified against `rmcp` 3.5.1 (pinned `=3.5.1`) on 2026-10-09, from the crate's source and tests.

## Server shape

- Tools are methods in an `impl` marked `#[tool_router]`, each with `#[tool(description = …)]`.
  Arguments come in as `Parameters<T>` with `T: Deserialize + schemars::JsonSchema`; use the
  `rmcp::schemars` re-export so the schemars version always matches. A tool without arguments
  takes only `&self`.
- `#[tool_handler] impl ServerHandler` wires the router in. **Pass `router = self.tool_router`**
  when the server removes routes (`ToolRouter::remove_route`) at construction: without it the
  macro builds a fresh router with every tool, so a removed tool would still be callable.
- `ServerConfig` (3.x name for `InitializeResult`): `ServerConfig::new(capabilities)`,
  `.with_server_info(…)`, `.with_instructions(…)`. **Do not use
  `Implementation::from_build_env()`**: its `env!` expands inside rmcp, so the server announces
  itself as `rmcp 3.5.1`. Use `Implementation::new("sluice", env!("CARGO_PKG_VERSION"))`.
- Streamable HTTP (feature `transport-streamable-http-server`): `StreamableHttpService::new(
  factory, Arc::new(LocalSessionManager::default()), config)` nested in axum. Session mode wants
  `initialize` first (a bare `tools/list` gets 422), and answers as SSE (a priming event, then
  the JSON-RPC message). The config checks the `Host` header against `allowed_hosts` (localhost
  and loopback by default) against DNS rebinding.
- Content: `ContentBlock::text`, `ContentBlock::json` (fallible). Results:
  `CallToolResult::success` / `CallToolResult::error`. Errors the assistant should see and
  explain (control plane down, bad filter) are `CallToolResult::error`; `ErrorData` is for
  protocol failures.
- stdio: `server.serve(rmcp::transport::stdio()).await?.waiting().await`. Feature
  `transport-io`. Nothing else may write to stdout in `sluice mcp`.
- The macros generate `async` trait methods without `.await`, which trips clippy's
  `unused_async_trait_impl`; it is allowed on that impl with a reason.

## Testing

- Client side for tests: features `client` and `transport-child-process`;
  `().serve(TokioChildProcess::new(command)?)`, then `list_all_tools`, `call_tool(
  CallToolRequestParams::new(name).with_arguments(map))`, `cancel`.
- Protocol revision `2026-07-28` removed the `initialize` handshake; rmcp handles version
  discovery itself, so tests do not need to.

## Use in Sluice

`sluice mcp` (crate `sluice-mcp`) offers `status`, `templates`, `explain`, `what_breaks`,
`coverage_gaps`, `source_health`, `search_archive` (with `--archive`, bounded to 100 events) and
`replay` (only with `--allow-replay`). It reads the control plane's `GET /status` and
`GET /rules` and holds no state. Answers are built by pure functions in `answers.rs`; blocking
work (ureq, archive scans) runs in `spawn_blocking`.
