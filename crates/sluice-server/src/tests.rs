//! The control plane without Vector: tap ingest over HTTP, a full cycle, and the written config.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Map, Value, json};
use sluice_autopilot::RecipeBook;
use sluice_rules::SigmaRules;
use sluice_synth::{SynthConfig, generate};
use tower::ServiceExt;

use crate::config::{LiveSourceConfig, PromotionConfig, ServerConfig, WindowConfig};
use crate::control::{Rules, Shared};
use crate::routes::router;

fn shared(dir: &std::path::Path) -> Arc<Shared> {
    let sample = generate(&SynthConfig {
        scale_percent: 1,
        ..SynthConfig::default()
    });
    let sources = sample
        .sources
        .iter()
        .map(|source| LiveSourceConfig {
            source: source.clone(),
            vector: json!({"type": "http_server", "address": "127.0.0.1:0", "decoding": {"codec": "json"}}),
        })
        .collect();
    let mut destinations = Map::new();
    destinations.insert("siem".into(), json!({"type": "blackhole"}));
    let config = ServerConfig {
        listen: "127.0.0.1:8686".into(),
        sources,
        destinations,
        archive_dir: dir.join("archive"),
        data_dir: dir.join("data"),
        vector_config: dir.join("vector.yaml"),
        vector_binary: PathBuf::from("vector"),
        tap_rate: 10,
        cycle_secs: 60,
        window: WindowConfig::default(),
        promotion: PromotionConfig {
            shadow_secs: 0,
            min_proofs: 2,
        },
    };
    let rules = Rules {
        sigma: SigmaRules::parse([include_str!("../../../examples/rules/sigma/windows.yml")])
            .unwrap(),
        wazuh: None,
    };
    Arc::new(Shared::new(config, rules, RecipeBook::embedded().unwrap()))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sluice-server-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

async fn post(shared: &Arc<Shared>, uri: &str, body: String) -> StatusCode {
    let request = Request::post(uri).body(Body::from(body)).unwrap();
    router(Arc::clone(shared))
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

fn ndjson(source: &str, scale: u64) -> String {
    let sample = generate(&SynthConfig {
        scale_percent: scale,
        ..SynthConfig::default()
    });
    sample
        .events
        .iter()
        .filter(|e| e.source.as_str() == source)
        .map(|e| Value::Object(e.fields.clone()).to_string() + "\n")
        .collect()
}

#[tokio::test]
async fn tap_accepts_known_sources_only() {
    let shared = shared(&scratch("tap"));
    assert_eq!(
        post(&shared, "/tap/sysmon", ndjson("sysmon", 1)).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post(&shared, "/tap/nope", "{}\n".into()).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(&shared, "/tap/sysmon", "not json\n".into()).await,
        StatusCode::BAD_REQUEST
    );
    let sizes = crate::control::lock(&shared.windows).sizes();
    assert!(sizes[&"sysmon".into()] > 100);
}

#[tokio::test]
async fn cycles_shadow_then_enforce_and_rewrite_the_config() {
    let dir = scratch("cycle");
    let shared = shared(&dir);
    shared.write_initial_config().unwrap();
    let initial = std::fs::read_to_string(dir.join("vector.yaml")).unwrap();
    assert!(
        !initial.contains("sluice_windows_security_route"),
        "nothing enforced yet"
    );

    assert_eq!(
        post(
            &shared,
            "/tap/windows-security",
            ndjson("windows-security", 10)
        )
        .await,
        StatusCode::ACCEPTED
    );
    let now = 1_791_622_800; // just after the sample's hour
    let first = shared.run_cycle(now).unwrap();
    assert!(!first.transitions.is_empty(), "recipes enter shadow");
    let second = shared.run_cycle(now + 60).unwrap();
    assert!(
        second
            .transitions
            .iter()
            .any(|t| matches!(t, sluice_autopilot::Transition::Promoted(_)))
    );
    assert!(second.config_changed);

    let config = std::fs::read_to_string(dir.join("vector.yaml")).unwrap();
    assert!(
        config.contains("sluice_windows_security_route"),
        "enforced recipes are deployed"
    );
    assert!(config.contains("/tap/windows-security"));
    assert!(!dir.join("vector.yaml.tmp").exists(), "written atomically");

    let status = shared.status.read().unwrap().clone();
    assert_eq!(status.cycles, 2);
    let last = status.last_cycle.unwrap();
    assert!(last.proven && last.bytes_out < last.bytes_in);
    assert!(status.templates.iter().any(|t| t.stage == "enforced"));

    // What `sluice mcp` explains from: actions and reasons per template, health per source.
    let logon = status
        .details
        .iter()
        .find(|d| d.pattern.contains("4624") && d.stage == "enforced")
        .expect("the logon template is enforced");
    assert!(!logon.actions.is_empty(), "{logon:?}");
    let health = status
        .sources
        .iter()
        .find(|s| s.source == "windows-security")
        .unwrap();
    assert!(health.volume.events > 0 && health.volume.bytes_out < health.volume.bytes_in);
    assert!(
        status
            .sources
            .iter()
            .any(|s| s.source == "nginx" && s.volume.events == 0),
        "a silent source shows up with no events"
    );
}

#[tokio::test]
async fn rules_lists_what_each_rule_needs() {
    let shared = shared(&scratch("rules"));
    let response = router(Arc::clone(&shared))
        .oneshot(Request::get("/rules").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let rules: Vec<crate::RuleInfo> = serde_json::from_slice(&body).unwrap();
    assert!(!rules.is_empty());
    assert!(rules.iter().all(|r| r.engine == "sigma"));
    assert!(
        rules.iter().any(|r| r.stateful),
        "the example correlation rule"
    );
}
