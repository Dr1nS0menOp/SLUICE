//! The tools against a fake control plane that records what it was asked.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::write::GzEncoder;
use sluice_server::TemplateStatus;

use super::*;

#[test]
fn profiles_reach_the_control_plane_encoded() {
    assert_eq!(status_path(None), "status");
    assert_eq!(
        status_path(Some("sigma+wazuh")),
        "status?profile=sigma%2Bwazuh",
        "a raw + would arrive as a space"
    );
    assert_eq!(percent_encode("a b/é"), "a%20b%2F%C3%A9");
}

/// Each request: path with query, `authorization` header and body.
type Seen = Arc<Mutex<Vec<(String, Option<String>, String)>>>;

async fn control_plane(
    State(seen): State<Seen>,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let path = uri
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    seen.lock().unwrap().push((path, auth, body.clone()));
    match uri.path() {
        "/status" => {
            let stage = |template: &str, stage: &str| TemplateStatus {
                template: template.into(),
                stage: stage.into(),
                since: 0,
                proofs: None,
            };
            let status = Status {
                profile: "sigma".into(),
                templates: vec![stage("t-shadow", "shadow"), stage("t-enforced", "enforced")],
                ..Status::default()
            };
            axum::Json(status).into_response()
        }
        "/rules" => axum::Json(json!([])).into_response(),
        "/actions" if body.contains("\"hold\"") => "held\n".into_response(),
        "/actions" => (StatusCode::BAD_REQUEST, "unknown action\n").into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// A running fake control plane: its address and what it saw.
async fn start() -> (String, Seen) {
    let seen = Seen::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let app = Router::new()
        .fallback(control_plane)
        .with_state(Arc::clone(&seen));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, seen)
}

fn config(control_plane: &str) -> McpConfig {
    McpConfig {
        control_plane: control_plane.to_owned(),
        control_token: Some("secret-token".into()),
        archive: None,
        replay_to: Vec::new(),
        allow_actions: false,
    }
}

/// Whether the call failed, and its text.
fn answer(result: &CallToolResult) -> (bool, String) {
    let value = serde_json::to_value(result).unwrap();
    let text = value["content"][0]["text"].as_str().unwrap_or_default();
    (result.is_error == Some(true), text.to_owned())
}

#[test]
fn tools_that_change_or_send_data_are_offered_only_when_configured() {
    let plain = Sluice::new(config("x"));
    for tool in ["status", "explain", "what_breaks"] {
        assert!(plain.tool_router.has_route(tool), "{tool}");
    }
    for tool in ["search_archive", "replay", "operator_action"] {
        assert!(!plain.tool_router.has_route(tool), "{tool}");
    }
    let archive_only = Sluice::new(McpConfig {
        archive: Some("a".into()),
        ..config("x")
    });
    assert!(archive_only.tool_router.has_route("search_archive"));
    assert!(
        !archive_only.tool_router.has_route("replay"),
        "no --replay-to"
    );
    let all = Sluice::new(McpConfig {
        archive: Some("a".into()),
        replay_to: vec!["http://siem".into()],
        allow_actions: true,
        ..config("x")
    });
    assert!(all.tool_router.has_route("replay") && all.tool_router.has_route("operator_action"));
    let without_archive = Sluice::new(McpConfig {
        replay_to: vec!["http://siem".into()],
        ..config("x")
    });
    assert!(!without_archive.tool_router.has_route("replay"));
}

#[tokio::test(flavor = "multi_thread")]
async fn status_asks_for_the_profile_with_the_token() {
    let (address, seen) = start().await;
    let sluice = Sluice::new(config(&address));
    let result = sluice
        .status(Parameters(ProfileRequest {
            profile: Some("sigma+wazuh".into()),
        }))
        .await
        .unwrap();
    assert!(!answer(&result).0, "{result:?}");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen[0].0, "/status?profile=sigma%2Bwazuh");
    assert_eq!(seen[0].1.as_deref(), Some("Bearer secret-token"));
}

#[tokio::test(flavor = "multi_thread")]
async fn templates_filter_by_stage() {
    let (address, _) = start().await;
    let sluice = Sluice::new(config(&address));
    let request = |stage: Option<&str>| TemplatesRequest {
        stage: stage.map(str::to_owned),
        profile: None,
    };
    let (_, enforced) = answer(
        &sluice
            .templates(Parameters(request(Some("enforced"))))
            .await
            .unwrap(),
    );
    assert!(
        enforced.contains("t-enforced") && !enforced.contains("t-shadow"),
        "{enforced}"
    );
    let (_, all) = answer(&sluice.templates(Parameters(request(None))).await.unwrap());
    assert!(
        all.contains("t-enforced") && all.contains("t-shadow"),
        "{all}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_control_plane_that_is_not_running_is_a_failure_the_assistant_can_explain() {
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    };
    let sluice = Sluice::new(config(&closed));
    let (failed, text) = answer(
        &sluice
            .source_health(Parameters(ProfileRequest { profile: None }))
            .await
            .unwrap(),
    );
    assert!(failed && text.contains("Is `sluice up` running?"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn what_breaks_needs_a_field_or_a_source() {
    let (address, seen) = start().await;
    let sluice = Sluice::new(config(&address));
    let (failed, text) = answer(
        &sluice
            .what_breaks(Parameters(WhatBreaksRequest {
                field: None,
                source: None,
                profile: None,
            }))
            .await
            .unwrap(),
    );
    assert!(failed && text.contains("give a field"), "{text}");
    assert!(seen.lock().unwrap().is_empty(), "nothing fetched");
    let result = sluice
        .what_breaks(Parameters(WhatBreaksRequest {
            field: Some("TargetUserName".into()),
            source: None,
            profile: None,
        }))
        .await
        .unwrap();
    assert!(!answer(&result).0, "{result:?}");
}

fn action(name: &str) -> ActionToolRequest {
    ActionToolRequest {
        action: name.into(),
        template: Some("t1".into()),
        source: None,
        field: None,
        at: Some(7),
        reason: Some("user asked".into()),
        profile: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_action_posts_only_what_was_given_and_reports_a_refusal() {
    let (address, seen) = start().await;
    let sluice = Sluice::new(McpConfig {
        allow_actions: true,
        ..config(&address)
    });
    let (failed, text) = answer(
        &sluice
            .operator_action(Parameters(action("hold")))
            .await
            .unwrap(),
    );
    assert!(!failed && text.contains("held"), "{text}");
    let body: Value = serde_json::from_str(&seen.lock().unwrap()[0].2).unwrap();
    assert_eq!(
        body,
        json!({"action": "hold", "template": "t1", "at": 7, "reason": "user asked"})
    );
    assert_eq!(
        seen.lock().unwrap()[0].1.as_deref(),
        Some("Bearer secret-token")
    );

    let (failed, text) = answer(
        &sluice
            .operator_action(Parameters(action("smash")))
            .await
            .unwrap(),
    );
    assert!(
        failed && text.contains("refused (400") && text.contains("unknown action"),
        "{text}"
    );
}

fn archive(name: &str, events: usize) -> PathBuf {
    let root = std::env::temp_dir().join(format!("sluice-mcp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("windows-security/2026-10-09");
    std::fs::create_dir_all(&dir).unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    for n in 0..events {
        writeln!(
            encoder,
            "{}",
            json!({"n": n, "timestamp": "2026-10-09T17:00:00Z"})
        )
        .unwrap();
    }
    std::fs::write(dir.join("17.ndjson.gz"), encoder.finish().unwrap()).unwrap();
    root
}

fn search(limit: Option<usize>, from: Option<&str>) -> SearchRequest {
    SearchRequest {
        selection: Selection {
            from: from.map(str::to_owned),
            ..Selection::default()
        },
        limit,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_search_returns_at_most_its_limit_and_says_when_there_is_more() {
    let sluice = Sluice::new(McpConfig {
        archive: Some(archive("search", 3)),
        ..config("x")
    });
    let (failed, text) = answer(
        &sluice
            .search_archive(Parameters(search(Some(2), None)))
            .await
            .unwrap(),
    );
    assert!(!failed, "{text}");
    let found: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(found["events"].as_array().unwrap().len(), 2);
    assert_eq!(found["more_available"], true);
    assert_eq!(found["events"][0]["source"], "windows-security");

    let (_, text) = answer(
        &sluice
            .search_archive(Parameters(search(Some(0), None)))
            .await
            .unwrap(),
    );
    let found: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        found["events"].as_array().unwrap().len(),
        1,
        "a limit of 0 is 1"
    );

    let (failed, text) = answer(
        &sluice
            .search_archive(Parameters(search(None, Some("yesterday"))))
            .await
            .unwrap(),
    );
    assert!(failed, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_sends_only_to_an_endpoint_it_was_started_with() {
    let sluice = Sluice::new(McpConfig {
        archive: Some(archive("replay", 1)),
        replay_to: vec!["http://127.0.0.1:9/siem".into()],
        ..config("x")
    });
    let (failed, text) = answer(
        &sluice
            .replay(Parameters(ReplayRequest {
                selection: Selection::default(),
                url: "http://attacker.example/".into(),
            }))
            .await
            .unwrap(),
    );
    assert!(
        failed && text.contains("--replay-to") && text.contains("127.0.0.1:9"),
        "{text}"
    );

    let none = Sluice::new(config("x"));
    let (failed, text) = answer(
        &none
            .search_archive(Parameters(search(None, None)))
            .await
            .unwrap(),
    );
    assert!(failed && text.contains("no archive configured"), "{text}");
}
