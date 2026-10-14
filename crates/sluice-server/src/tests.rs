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

pub(crate) fn shared(dir: &std::path::Path) -> Arc<Shared> {
    shared_with_token(dir, None)
}

pub(crate) fn shared_with_token(dir: &std::path::Path, token: Option<&str>) -> Arc<Shared> {
    let mut destinations = Map::new();
    destinations.insert("siem".into(), json!({"type": "blackhole"}));
    shared_with(dir, token, destinations, false)
}

fn shared_with(
    dir: &std::path::Path,
    token: Option<&str>,
    destinations: Map<String, Value>,
    wazuh: bool,
) -> Arc<Shared> {
    Arc::new(build(dir, token, destinations, wazuh).unwrap())
}

pub(crate) fn build(
    dir: &std::path::Path,
    token: Option<&str>,
    destinations: Map<String, Value>,
    wazuh: bool,
) -> Result<Shared, crate::ServerError> {
    let rules = Rules {
        sigma: SigmaRules::parse([include_str!("../../../examples/rules/sigma/windows.yml")])
            .unwrap(),
        wazuh: wazuh.then(|| {
            sluice_rules::WazuhRules::parse([include_str!(
                "../../../examples/rules/wazuh/local_rules.xml"
            )])
            .unwrap()
        }),
        sentinel: None,
        bases: ["sigma", "wazuh", "sentinel"]
            .map(|set| (set.to_owned(), sluice_autopilot::RulesBasis::SelfContained))
            .into(),
    };
    build_with(dir, token, destinations, rules)
}

fn build_with(
    dir: &std::path::Path,
    token: Option<&str>,
    destinations: Map<String, Value>,
    rules: Rules,
) -> Result<Shared, crate::ServerError> {
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
            shape: None,
        })
        .collect();
    let config = ServerConfig {
        listen: "127.0.0.1:8686".into(),
        sources,
        destinations,
        vector_secrets: Map::new(),
        archive_dir: dir.join("archive"),
        data_dir: dir.join("data"),
        operators_file: None,
        oidc: None,
        vector_config: dir.join("vector.yaml"),
        proposals_dir: None,
        // These tests drive the lifecycle; the proposal tests switch it off.
        auto_apply: true,
        vector_binary: PathBuf::from("vector"),
        tap_rate: 10,
        cycle_secs: 60,
        window: WindowConfig::default(),
        promotion: PromotionConfig {
            shadow_secs: 0,
            min_proofs: 2,
            approval: false,
        },
    };
    Shared::new(
        config,
        rules,
        RecipeBook::embedded().unwrap(),
        token.map(str::to_owned),
    )
}

pub(crate) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sluice-server-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

pub(crate) async fn post(shared: &Arc<Shared>, uri: &str, body: String) -> StatusCode {
    let request = Request::post(uri).body(Body::from(body)).unwrap();
    router(Arc::clone(shared))
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

pub(crate) fn ndjson(source: &str, scale: u64) -> String {
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
            .any(|(_, t)| matches!(t, sluice_autopilot::Transition::Promoted(_)))
    );
    assert!(second.config_changed);

    let config = std::fs::read_to_string(dir.join("vector.yaml")).unwrap();
    assert!(
        config.contains("sluice_windows_security_route"),
        "enforced recipes are deployed"
    );
    assert!(config.contains("/tap/windows-security"));
    assert!(!dir.join("vector.yaml.tmp").exists(), "written atomically");

    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    assert_eq!(status.profile, "sigma");
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
    // One real event, before and after: the recipe's work made visible.
    let example = logon.example.as_ref().expect("an example event");
    assert!(example.before.contains_key("Message"));
    let after = example.after.as_ref().expect("logons are forwarded");
    assert!(
        !after.contains_key("Message"),
        "the rendered message is dropped"
    );
    assert_eq!(after.get("EventID"), example.before.get("EventID"));
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

/// A control plane in its default mode: it proposes, the operator deploys.
async fn proposing(dir: &std::path::Path) -> Arc<Shared> {
    let mut destinations = Map::new();
    destinations.insert("siem".into(), json!({"type": "blackhole"}));
    let mut built = build(dir, None, destinations, false).unwrap();
    built.config.auto_apply = false;
    built.config.proposals_dir = Some(dir.join("proposals"));
    let shared = Arc::new(built);
    shared.write_startup_config().unwrap();
    post(
        &shared,
        "/tap/windows-security",
        ndjson("windows-security", 10),
    )
    .await;
    shared
}

#[tokio::test]
async fn c5_with_a_proposals_directory_the_proven_config_is_proposed_not_applied() {
    let dir = scratch("proposals");
    let shared = proposing(&dir).await;
    let initial = std::fs::read_to_string(dir.join("vector.yaml")).unwrap();
    let now = 1_791_622_800;
    shared.run_cycle(now).unwrap();
    let second = shared.run_cycle(now + 60).unwrap();
    assert!(!second.config_changed, "nothing for Vector to reload");
    assert_eq!(
        std::fs::read_to_string(dir.join("vector.yaml")).unwrap(),
        initial,
        "the running configuration is untouched"
    );
    let proposed = std::fs::read_to_string(dir.join("proposals/vector.yaml")).unwrap();
    assert!(proposed.contains("sluice_windows_security_route"));
    let proposal: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("proposals/proposal.json")).unwrap(),
    )
    .unwrap();
    let profile = &proposal["profiles"][0];
    assert_eq!(profile["proof"]["holds"], true);
    assert_eq!(
        profile["proof"]["alerts_full"],
        profile["proof"]["alerts_forwarded"]
    );
    assert_ne!(profile["enforced_templates"], json!([]));
    assert_eq!(
        shared.profile(None).unwrap().status.read().unwrap().mode,
        "proposing"
    );
}

#[tokio::test]
async fn c5_a_deployed_proposal_is_proven_and_switched_off_the_moment_it_fails() {
    let dir = scratch("deployed");
    let shared = proposing(&dir).await;
    let safe = std::fs::read_to_string(dir.join("vector.yaml")).unwrap();
    let now = 1_791_622_800;
    shared.run_cycle(now).unwrap();
    shared.run_cycle(now + 60).unwrap();

    // The operator reviews the proposal and deploys it.
    std::fs::copy(dir.join("proposals/vector.yaml"), dir.join("vector.yaml")).unwrap();
    let deployed = shared.run_cycle(now + 120).unwrap();
    assert!(
        deployed.config_changed,
        "Vector loads the proven deployment"
    );
    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    assert!(status.running.unwrap().contains("proven"));

    // Someone deploys a configuration that summarizes every Windows Security event.
    let mut config: Value =
        serde_yaml_ng::from_str(&std::fs::read_to_string(dir.join("vector.yaml")).unwrap())
            .unwrap();
    let program = &mut config["transforms"]["sluice_windows_security"]["source"];
    *program = format!(
        "{}\n%sluice.route = \"summarize\"\n",
        program.as_str().unwrap()
    )
    .into();
    std::fs::write(
        dir.join("vector.yaml"),
        serde_yaml_ng::to_string(&config).unwrap(),
    )
    .unwrap();
    let failed = shared.run_cycle(now + 180).unwrap();
    assert!(
        failed.config_changed,
        "Vector reloads the safe configuration"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("vector.yaml")).unwrap(),
        safe,
        "every event is forwarded unchanged again"
    );
    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    assert!(
        status
            .running
            .unwrap()
            .starts_with("safe configuration since")
    );
    assert_eq!(status.history.last().unwrap().kind, "switched_off");
}

#[tokio::test]
async fn c5_each_destination_is_proven_against_its_own_siems_rules() {
    let dir = scratch("profiles");
    let mut destinations = Map::new();
    destinations.insert(
        "sentinel".into(),
        json!({"type": "blackhole", "sluice_rules": ["sigma"]}),
    );
    destinations.insert("wazuh".into(), json!({"type": "blackhole"}));
    let shared = shared_with(&dir, None, destinations, true);
    let names: Vec<&str> = shared.profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["sigma", "sigma+wazuh"]);

    post(
        &shared,
        "/tap/windows-security",
        ndjson("windows-security", 10),
    )
    .await;
    let now = 1_791_622_800;
    shared.run_cycle(now).unwrap();
    let report = shared.run_cycle(now + 60).unwrap();
    assert!(
        report
            .transitions
            .iter()
            .any(|(p, t)| p == "sigma" && matches!(t, sluice_autopilot::Transition::Promoted(_)))
    );
    // The example Wazuh rules include a `<match>` without a decoder: it reads the whole JSON
    // line, so nothing may be cut for the destination whose SIEM runs it.
    assert!(!report.transitions.iter().any(|(p, _)| p == "sigma+wazuh"));

    // One archive and tap per source; the Sentinel destination gets its own reduced pipeline,
    // the Wazuh destination never does.
    let yaml = std::fs::read_to_string(dir.join("vector.yaml")).unwrap();
    let config: Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let transforms = config["transforms"].as_object().unwrap();
    assert!(transforms.contains_key("sluice_windows_security_sigma_route"));
    let inputs = |sink: &str| config["sinks"][sink]["inputs"].to_string();
    assert!(inputs("sentinel").contains("sluice_windows_security_sigma_route."));
    assert!(!inputs("wazuh").contains("sluice_windows_security_sigma_route"));
    assert!(
        inputs("wazuh").contains("sluice_windows_security_sigma_wazuh_route.")
            || inputs("wazuh").contains("sluice_windows_security_input"),
        "its own pass-through pipeline, or the source itself"
    );
    assert_eq!(
        config["sinks"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.ends_with("_archive"))
            .count(),
        shared.sources.len()
    );

    // More rules never allow more cuts.
    let out = |name: &str| {
        let status = shared
            .profile(Some(name))
            .unwrap()
            .status
            .read()
            .unwrap()
            .clone();
        let last = status.last_cycle.unwrap();
        assert!(last.proven, "{name}");
        last.bytes_out
    };
    assert!(out("sigma") < out("sigma+wazuh"));

    let response = get(&shared, "/status?profile=sigma%2Bwazuh", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: crate::Status = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.profile, "sigma+wazuh");
    assert_eq!(status.profiles, ["sigma", "sigma+wazuh"]);
    assert_eq!(
        get(&shared, "/status?profile=nope", None).await.status(),
        StatusCode::NOT_FOUND
    );
}

/// Alerts on every field of every event: any cut changes its alerts.
struct EveryField;

impl sluice_core::alert::RuleEngine for EveryField {
    fn alerts_refs(
        &self,
        events: &[&sluice_core::event::Event],
    ) -> Result<
        std::collections::BTreeSet<sluice_core::alert::Alert>,
        sluice_core::alert::EngineError,
    > {
        Ok(events
            .iter()
            .flat_map(|e| {
                e.fields.keys().map(|k| sluice_core::alert::Alert {
                    rule: sluice_core::ids::RuleId::new(format!("sentinel:{k}")),
                    event: e.id,
                })
            })
            .collect())
    }
}

#[tokio::test]
async fn c5_a_sentinel_engine_takes_part_in_its_profiles_proof() {
    let dir = scratch("sentinel");
    let mut destinations = Map::new();
    destinations.insert(
        "sentinel".into(),
        json!({"type": "blackhole", "sluice_rules": ["sigma", "sentinel"]}),
    );
    destinations.insert(
        "other".into(),
        json!({"type": "blackhole", "sluice_rules": ["sigma"]}),
    );
    let rules = Rules {
        sigma: SigmaRules::parse([include_str!("../../../examples/rules/sigma/windows.yml")])
            .unwrap(),
        wazuh: None,
        sentinel: Some(crate::SentinelRuleSet {
            rules: sluice_rules::SentinelRules::parse(std::iter::empty::<(&str, &str)>()),
            engine: Some(Box::new(EveryField)),
        }),
        bases: ["sigma", "wazuh", "sentinel"]
            .map(|set| (set.to_owned(), sluice_autopilot::RulesBasis::SelfContained))
            .into(),
    };
    let shared = Arc::new(build_with(&dir, None, destinations, rules).unwrap());
    let names: Vec<&str> = shared.profiles.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["sentinel+sigma", "sigma"]);

    post(
        &shared,
        "/tap/windows-security",
        ndjson("windows-security", 10),
    )
    .await;
    let now = 1_791_622_800;
    shared.run_cycle(now).unwrap();
    let report = shared.run_cycle(now + 60).unwrap();
    assert!(report.transitions.iter().any(|(p, _)| p == "sigma"));
    assert!(
        !report
            .transitions
            .iter()
            .any(|(p, _)| p == "sigma+sentinel"),
        "every cut changes the Sentinel engine's alerts"
    );
}

#[test]
fn a_destination_naming_rules_that_are_not_loaded_is_refused() {
    let mut destinations = Map::new();
    destinations.insert(
        "wazuh".into(),
        json!({"type": "blackhole", "sluice_rules": ["wazuh"]}),
    );
    let refused = build(&scratch("refused"), None, destinations, false);
    assert!(
        matches!(refused, Err(crate::ServerError::Config(ref m)) if m.contains("sluice_rules")),
        "Wazuh rules are not loaded"
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
