//! Operator actions through the HTTP API (ADR 0016).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::control::{Shared, lock};
use crate::routes::router;
use crate::tests::{ndjson, post, scratch, shared, shared_with_token};

async fn act(shared: &Arc<Shared>, body: &Value, token: Option<&str>) -> StatusCode {
    let mut request = Request::post("/actions").header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    router(Arc::clone(shared))
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
        .status()
}

/// Runs two cycles on Windows Security traffic, so recipes are enforced (shadow 0, 2 proofs).
async fn with_enforced_recipes(name: &str) -> (Arc<Shared>, std::path::PathBuf, String) {
    let dir = scratch(name);
    let shared = shared(&dir);
    post(
        &shared,
        "/tap/windows-security",
        ndjson("windows-security", 10),
    )
    .await;
    let now = 1_791_622_800;
    shared.run_cycle(now).unwrap();
    shared.run_cycle(now + 60).unwrap();
    let profile = shared.profile(None).unwrap();
    let enforced = lock(&profile.lifecycle).enforced();
    let template = enforced
        .iter()
        .next()
        .expect("an enforced recipe")
        .to_string();
    (shared, dir, template)
}

#[tokio::test]
async fn c3_a_held_template_is_forwarded_unchanged_and_the_hold_is_recorded() {
    let (shared, dir, template) = with_enforced_recipes("hold").await;
    let hold = json!({ "action": "hold", "template": template, "reason": "analysts asked" });
    assert_eq!(act(&shared, &hold, None).await, StatusCode::OK);

    let profile = shared.profile(None).unwrap();
    assert!(
        !lock(&profile.lifecycle)
            .enforced()
            .contains(&template.as_str().into())
    );
    shared.run_cycle(1_791_622_800 + 120).unwrap();
    assert!(
        !lock(&profile.lifecycle)
            .enforced()
            .contains(&template.as_str().into()),
        "proven again, but held"
    );
    let status = profile.status.read().unwrap().clone();
    assert_eq!(status.operator.held, std::slice::from_ref(&template));
    let last = status
        .history
        .iter()
        .rev()
        .find(|r| r.kind == "hold")
        .expect("in the history");
    assert_eq!(last.reason.as_deref(), Some("analysts asked"));
    assert_eq!(last.actor.as_deref(), Some("local"));

    let audit = std::fs::read_to_string(dir.join("data/audit.ndjson")).unwrap();
    assert!(
        audit.contains(&template) && audit.contains("\"hold\""),
        "{audit}"
    );
    let stored = std::fs::read_to_string(dir.join("data/operator.json")).unwrap();
    assert!(stored.contains(&template), "{stored}");

    // A restart keeps the hold.
    let restarted = crate::tests::shared(&dir);
    let profile = restarted.profile(None).unwrap();
    assert!(
        lock(&profile.lifecycle)
            .held()
            .contains(&template.as_str().into())
    );

    let release = json!({ "action": "release", "template": template });
    assert_eq!(act(&shared, &release, None).await, StatusCode::OK);
    assert_eq!(act(&shared, &release, None).await, StatusCode::CONFLICT);
}

#[tokio::test]
async fn c3_kept_fields_become_rules_the_guardrails_respect() {
    let (shared, _dir, _) = with_enforced_recipes("keep").await;
    let keep = json!({ "action": "keep", "source": "windows-security", "field": "Message" });
    assert_eq!(act(&shared, &keep, None).await, StatusCode::OK);
    shared.run_cycle(1_791_622_800 + 120).unwrap();
    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    assert_eq!(status.operator.kept, ["windows-security:Message"]);
    assert!(
        status.details.iter().any(|d| d
            .adjustments
            .iter()
            .any(|a| a.contains("operator:keep:windows-security:Message"))),
        "the recipes that drop Message keep it now"
    );
    let unknown = json!({ "action": "keep", "source": "nope", "field": "x" });
    assert_eq!(act(&shared, &unknown, None).await, StatusCode::CONFLICT);
}

#[tokio::test]
async fn actions_that_do_not_fit_are_refused_and_change_nothing() {
    let (shared, dir, template) = with_enforced_recipes("refused").await;
    let approve = json!({ "action": "approve", "template": template });
    assert_eq!(
        act(&shared, &approve, None).await,
        StatusCode::CONFLICT,
        "enforced, not in shadow"
    );
    let ack = json!({ "action": "acknowledge", "template": template, "at": 1 });
    assert_eq!(act(&shared, &ack, None).await, StatusCode::CONFLICT);
    assert!(
        !dir.join("data/audit.ndjson").exists(),
        "refused actions are not audited"
    );

    let form = Request::post("/actions")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("action=hold&template=x"))
        .unwrap();
    let status = router(Arc::clone(&shared))
        .oneshot(form)
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "no cross-site forms"
    );
}

#[tokio::test]
async fn actions_need_the_token() {
    let token = "0123456789abcdef0123456789abcdef";
    let shared = shared_with_token(&scratch("action-token"), Some(token));
    let hold = json!({ "action": "hold", "template": "t" });
    assert_eq!(act(&shared, &hold, None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(act(&shared, &hold, Some(token)).await, StatusCode::OK);
    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    assert_eq!(
        status.history.last().and_then(|r| r.actor.as_deref()),
        Some("token")
    );
}

#[tokio::test]
async fn operators_sign_in_with_their_own_token_and_the_audit_names_them() {
    use std::os::unix::fs::PermissionsExt;
    let alice = "alice-0123456789abcdef0123456789abcdef";
    let control = "0123456789abcdef0123456789abcdef";
    let dir = scratch("operators");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("operators");
    std::fs::write(&file, format!("# the SOC\nalice@example.org {alice}\n")).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut destinations = serde_json::Map::new();
    destinations.insert("siem".into(), json!({"type": "blackhole"}));
    let mut built = crate::tests::build(&dir, Some(control), destinations, false).unwrap();
    built.operators = crate::operators::load(&file).unwrap();
    let shared = Arc::new(built);

    let hold = json!({ "action": "hold", "template": "t1", "reason": "IR case 42" });
    assert_eq!(
        act(&shared, &hold, Some("someone-elses-token-0123456789abcdef")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(act(&shared, &hold, Some(alice)).await, StatusCode::OK);
    let release = json!({ "action": "release", "template": "t1" });
    assert_eq!(act(&shared, &release, Some(control)).await, StatusCode::OK);

    let status = shared.profile(None).unwrap().status.read().unwrap().clone();
    let actors: Vec<&str> = status
        .history
        .iter()
        .filter_map(|r| r.actor.as_deref())
        .collect();
    assert_eq!(actors, ["alice@example.org", "token"]);
    let audit = std::fs::read_to_string(dir.join("data/audit.ndjson")).unwrap();
    assert!(audit.contains("\"actor\":\"alice@example.org\""), "{audit}");
    assert!(!audit.contains(alice), "tokens never reach the audit log");
}
