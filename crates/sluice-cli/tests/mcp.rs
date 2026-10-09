//! `sluice mcp` end to end: an MCP client starts the binary over stdio, lists the tools and calls
//! them.

use std::io::Write;
use std::path::{Path, PathBuf};

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use serde_json::{Value, json};

/// A fresh archive per test, so tests can run in parallel.
fn archive(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("mcp-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("sysmon/2026-10-09");
    std::fs::create_dir_all(&dir).expect("creating the archive");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for image in ["C:\\Windows\\explorer.exe", "C:\\Tools\\mimikatz.exe"] {
        let event = json!({"EventID": 1, "Image": image, "timestamp": "2026-10-09T17:05:00Z"});
        writeln!(gz, "{event}").expect("gzip");
    }
    std::fs::write(dir.join("17.ndjson.gz"), gz.finish().expect("gzip")).expect("writing");
    root
}

async fn start(args: &[&str]) -> RunningService<RoleClient, ()> {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_sluice"));
    command.arg("mcp").args(args);
    let transport = TokioChildProcess::new(command).expect("spawning sluice mcp");
    ().serve(transport).await.expect("MCP session starts")
}

async fn call(client: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let Value::Object(args) = args else {
        unreachable!("tool arguments are an object")
    };
    client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(args))
        .await
        .expect("tool call completes")
}

fn text(result: &CallToolResult) -> String {
    serde_json::to_string(&result.content).expect("content serializes")
}

#[tokio::test]
async fn tools_answer_over_stdio() {
    let archive = archive("tools");
    // Nothing listens on this port, so `status` must report that clearly.
    let client = start(&[
        "--listen",
        "127.0.0.1:9",
        "--archive",
        archive.to_str().unwrap(),
    ])
    .await;

    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .expect("tools list")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for tool in [
        "status",
        "templates",
        "explain",
        "what_breaks",
        "coverage_gaps",
        "source_health",
    ] {
        assert!(tools.contains(&tool.to_owned()), "{tool}: {tools:?}");
    }
    assert!(tools.contains(&"search_archive".to_owned()));
    assert!(
        !tools.contains(&"replay".to_owned()),
        "replay needs --allow-replay"
    );

    let found = call(
        &client,
        "search_archive",
        json!({"sources": ["sysmon"], "where": ["Image~mimikatz"]}),
    )
    .await;
    assert_ne!(found.is_error, Some(true), "{}", text(&found));
    let body = text(&found);
    assert!(body.contains("mimikatz.exe"), "{body}");
    assert!(!body.contains("explorer.exe"), "{body}");

    let replay = client
        .call_tool(
            CallToolRequestParams::new("replay").with_arguments(
                json!({"url": "http://127.0.0.1:9"})
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await;
    assert!(
        replay.is_err() || replay.as_ref().is_ok_and(|r| r.is_error == Some(true)),
        "an unoffered tool cannot be called: {replay:?}"
    );

    let status = call(&client, "status", json!({})).await;
    assert_eq!(status.is_error, Some(true));
    assert!(text(&status).contains("sluice up"), "{}", text(&status));

    client.cancel().await.expect("session closes");
}

#[tokio::test]
async fn replay_is_offered_only_when_allowed() {
    let archive = archive("replay");
    let client = start(&["--archive", archive.to_str().unwrap(), "--allow-replay"]).await;
    let tools = client.list_all_tools().await.expect("tools list");
    assert!(tools.iter().any(|t| t.name == "replay"));
    client.cancel().await.expect("session closes");
}
