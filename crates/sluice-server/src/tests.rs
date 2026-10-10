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
    shared_with_token(dir, None)
}

fn shared_with_token(dir: &std::path::Path, token: Option<&str>) -> Arc<Shared> {
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
        vector_secrets: Map::new(),
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
    Arc::new(Shared::new(
        config,
        rules,
        RecipeBook::embedded().unwrap(),
        token.map(str::to_owned),
    ))
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

#[tokio::test]
async fn a_control_token_guards_every_route_but_health() {
    let token = "0123456789abcdef0123456789abcdef";
    let shared = shared_with_token(&scratch("token"), Some(token));
    let get = |uri: &str, auth: Option<String>| {
        let mut request = Request::get(uri);
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        request.body(Body::empty()).unwrap()
    };
    let status = |request: Request<Body>| {
        let app = router(Arc::clone(&shared));
        async move { app.oneshot(request).await.unwrap().status() }
    };
    assert_eq!(status(get("/status", None)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        status(get("/rules", Some("Bearer nope".into()))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(get("/status", Some(format!("Bearer {token}")))).await,
        StatusCode::OK
    );
    assert_eq!(status(get("/healthz", None)).await, StatusCode::OK);
    assert_eq!(
        post(&shared, "/tap/sysmon", "{}\n".into()).await,
        StatusCode::UNAUTHORIZED
    );

    // Vector's tap sinks read the token from a secret file only this user can read.
    shared.write_secrets().unwrap();
    shared.write_initial_config().unwrap();
    let config = std::fs::read_to_string(shared.config.vector_config.clone()).unwrap();
    assert!(config.contains("SECRET[sluice.control_token]"));
    assert!(!config.contains(token));
    let file = shared.config.data_dir.join("sluice-secrets/control_token");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), token);
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&file).unwrap().permissions());
    assert_eq!(mode & 0o777, 0o600);
}

async fn get(shared: &Arc<Shared>, uri: &str, token: Option<&str>) -> axum::response::Response {
    let mut request = Request::get(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    router(Arc::clone(shared))
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn the_console_is_served_without_data_and_under_a_strict_policy() {
    let token = "0123456789abcdef0123456789abcdef";
    let shared = shared_with_token(&scratch("console"), Some(token));
    for (uri, kind) in [
        ("/", "text/html"),
        ("/ui/app.js", "text/javascript"),
        ("/ui/app.css", "text/css"),
    ] {
        let response = get(&shared, uri, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let headers = response.headers();
        assert!(headers["content-type"].to_str().unwrap().starts_with(kind));
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
        assert_eq!(headers["x-content-type-options"], "nosniff");
    }
    // Archived events are untrusted: the console writes them as text, never as markup.
    let script = include_str!("../ui/app.js");
    assert!(!script.contains("innerHTML") && !script.contains("insertAdjacentHTML"));
    assert!(!script.contains("eval("));
}

#[tokio::test]
async fn archive_search_needs_the_token_and_reads_originals() {
    use std::io::Write as _;

    let token = "0123456789abcdef0123456789abcdef";
    let dir = scratch("archive-search");
    let shared = shared_with_token(&dir, Some(token));
    let hour = dir.join("archive/sysmon/2026-10-10");
    std::fs::create_dir_all(&hour).unwrap();
    let mut gz = flate2::write::GzEncoder::new(
        std::fs::File::create(hour.join("06.ndjson.gz")).unwrap(),
        flate2::Compression::default(),
    );
    for (id, image) in [(10, "lsass.exe"), (1, "cmd.exe"), (10, "LSASS.EXE")] {
        let event =
            json!({"timestamp": "2026-10-10T06:15:00Z", "EventID": id, "TargetImage": image});
        writeln!(gz, "{event}").unwrap();
    }
    gz.finish().unwrap();

    assert_eq!(
        get(&shared, "/archive/search", None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let search = |uri: &'static str| {
        let shared = Arc::clone(&shared);
        async move {
            let response = get(&shared, uri, Some(token)).await;
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, body)
        }
    };
    let (status, body) =
        search("/archive/search?source=sysmon&where=EventID%3D10%0ATargetImage~lsass").await;
    assert_eq!(status, StatusCode::OK);
    let result: crate::archive::SearchResult = serde_json::from_slice(&body).unwrap();
    assert_eq!(result.events.len(), 2, "both lsass events, any case");
    assert!(!result.more_available && !result.truncated);

    let (_, body) = search("/archive/search?limit=1").await;
    let result: crate::archive::SearchResult = serde_json::from_slice(&body).unwrap();
    assert_eq!(result.events.len(), 1);
    assert!(result.more_available);

    let (_, body) = search("/archive/search?source=nginx").await;
    let result: crate::archive::SearchResult = serde_json::from_slice(&body).unwrap();
    assert!(
        result.events.is_empty(),
        "another source's files are not read"
    );

    let (status, _) = search("/archive/search?where=no-operator").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = search("/archive/search?from=yesterday").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn listening_beyond_loopback_needs_a_token() {
    assert!(crate::check_exposure("127.0.0.1:8686", None).is_ok());
    assert!(crate::check_exposure("[::1]:8686", None).is_ok());
    assert!(crate::check_exposure("localhost:8686", None).is_ok());
    assert!(crate::check_exposure("0.0.0.0:8686", None).is_err());
    assert!(crate::check_exposure("10.0.0.5:8686", Some("short")).is_err());
    assert!(
        crate::check_exposure("0.0.0.0:8686", Some("0123456789abcdef0123456789abcdef")).is_ok()
    );
}
