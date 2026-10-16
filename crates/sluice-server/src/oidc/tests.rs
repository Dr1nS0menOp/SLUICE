//! The login flow against a fake provider that serves discovery, keys and tokens.

use std::sync::{Arc, Mutex};

use axum::extract::{Form, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use super::jwt::tests::TestKey;
use super::{Oidc, OidcConfig};

/// The fake provider: the nonce of the login it answers for, the key it signs with now and the
/// keys it publishes.
struct Idp {
    issuer: String,
    nonce: Mutex<String>,
    email: Mutex<String>,
    /// The `email_verified` claim, when the provider sends it.
    email_verified: Mutex<Option<Value>>,
    signer: Mutex<Arc<TestKey>>,
    published: Mutex<Value>,
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks", idp.issuer),
    }))
}

async fn jwks(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(idp.published.lock().unwrap().clone())
}

async fn token(
    State(idp): State<Arc<Idp>>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    assert_eq!(form["grant_type"], "authorization_code");
    assert!(form["code_verifier"].len() >= 43, "PKCE verifier sent");
    let mut claims = json!({
        "iss": idp.issuer, "aud": "sluice", "exp": 4_000_000_000_i64,
        "nonce": *idp.nonce.lock().unwrap(), "email": *idp.email.lock().unwrap(),
    });
    if let Some(verified) = idp.email_verified.lock().unwrap().clone() {
        claims["email_verified"] = verified;
    }
    let signer = Arc::clone(&idp.signer.lock().unwrap());
    let kid = signer.jwks["keys"][0]["kid"].as_str().unwrap().to_owned();
    Json(json!({ "id_token": signer.sign(&json!({ "alg": "ES256", "kid": kid }), &claims) }))
}

async fn start() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let key = Arc::new(TestKey::new("k1"));
    let idp = Arc::new(Idp {
        issuer,
        nonce: Mutex::new(String::new()),
        email: Mutex::new("Alice@Example.org".to_owned()),
        email_verified: Mutex::new(None),
        published: Mutex::new(key.jwks.clone()),
        signer: Mutex::new(key),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(Arc::clone(&idp));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

fn oidc(idp: &Idp) -> Oidc {
    Oidc::new(OidcConfig {
        enabled: true,
        issuer: idp.issuer.clone(),
        client_id: "sluice".into(),
        client_secret_file: None,
        redirect_url: "https://sluice.example/auth/callback".into(),
        name_claim: "email".into(),
        operators: vec!["alice@example.org".into()],
        session_secs: 3_600,
    })
    .unwrap()
}

/// The query parameter `key` of a URL.
fn param(url: &str, key: &str) -> String {
    url.split(['?', '&'])
        .find_map(|p| p.strip_prefix(&format!("{key}=")))
        .unwrap()
        .to_owned()
}

/// Starts a login and has the fake provider answer for it.
fn begin(oidc: &Oidc, idp: &Idp) -> String {
    let url = oidc.login_url(1_000).unwrap();
    assert_eq!(param(&url, "code_challenge_method"), "S256");
    *idp.nonce.lock().unwrap() = param(&url, "nonce");
    param(&url, "state")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_signs_in_and_out() {
    let idp = start().await;
    let result = tokio::task::spawn_blocking(move || {
        let oidc = oidc(&idp);
        let state = begin(&oidc, &idp);
        let (session, name) = oidc.callback("code-1", &state, 1_010).unwrap();
        assert_eq!(name, "alice@example.org", "the configured spelling");
        assert_eq!(
            oidc.session(&session, 1_020).as_deref(),
            Some("alice@example.org")
        );
        assert_eq!(oidc.session(&session, 1_010 + 3_600), None, "expired");
        assert!(
            oidc.callback("code-1", &state, 1_011).is_err(),
            "a login cannot be completed twice"
        );
        oidc.sign_out(&session);
        assert_eq!(oidc.session(&session, 1_020), None);
        assert!(oidc.cookie(Some("x")).contains("HttpOnly; SameSite=Strict"));
        assert!(oidc.cookie(Some("x")).ends_with("; Secure"));
    })
    .await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn only_listed_operators_get_in() {
    let idp = start().await;
    let result = tokio::task::spawn_blocking(move || {
        let oidc = oidc(&idp);
        *idp.email.lock().unwrap() = "mallory@example.org".to_owned();
        let state = begin(&oidc, &idp);
        let refused = oidc.callback("code-1", &state, 1_010).unwrap_err();
        assert!(refused.contains("not an operator"), "{refused}");
    })
    .await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_keys_are_fetched_again() {
    let idp = start().await;
    let result = tokio::task::spawn_blocking(move || {
        let oidc = oidc(&idp);
        let state = begin(&oidc, &idp);
        // The provider rotates its key after Sluice cached the old one.
        let next = Arc::new(TestKey::new("k2"));
        *idp.published.lock().unwrap() = next.jwks.clone();
        *idp.signer.lock().unwrap() = next;
        assert!(oidc.callback("code-1", &state, 1_010).is_ok());
    })
    .await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn c1_an_address_the_provider_has_not_verified_names_nobody() {
    let idp = start().await;
    let result = tokio::task::spawn_blocking(move || {
        let oidc = oidc(&idp);
        for refused in [json!(false), json!("false")] {
            *idp.email_verified.lock().unwrap() = Some(refused.clone());
            let state = begin(&oidc, &idp);
            let error = oidc.callback("code-1", &state, 1_010).unwrap_err();
            assert!(error.contains("not verified"), "{refused}: {error}");
        }
        *idp.email_verified.lock().unwrap() = Some(json!(true));
        let state = begin(&oidc, &idp);
        assert!(oidc.callback("code-1", &state, 1_010).is_ok());
    })
    .await;
    result.unwrap();
}

fn settings(enabled: bool) -> OidcConfig {
    serde_json::from_value(json!({
        "enabled": enabled,
        "issuer": "https://idp.example",
        "client_id": "sluice",
        "redirect_url": "https://sluice.example/auth/callback",
        "operators": [],
    }))
    .unwrap()
}

fn shared_with_oidc(
    name: &str,
    oidc: OidcConfig,
) -> Result<crate::control::Shared, crate::ServerError> {
    let rules = crate::control::Rules {
        sigma: sluice_rules::SigmaRules::parse(std::iter::empty::<&str>()).unwrap(),
        wazuh: None,
        sentinel: None,
        bases: std::collections::BTreeMap::new(),
    };
    let mut destinations = serde_json::Map::new();
    destinations.insert("siem".into(), json!({"type": "blackhole"}));
    crate::tests::build_tuned(
        &crate::tests::scratch(name),
        Some(&"t".repeat(32)),
        destinations,
        rules,
        |config| config.oidc = Some(oidc),
    )
}

#[test]
fn single_sign_on_is_on_unless_switched_off() {
    let yaml: OidcConfig = serde_json::from_value(json!({
        "issuer": "https://idp.example", "client_id": "sluice",
        "redirect_url": "https://sluice.example/auth/callback", "operators": ["a"],
    }))
    .unwrap();
    assert!(yaml.enabled, "on by default");

    // Switched on, an empty operator list is refused: nobody could sign in.
    assert!(shared_with_oidc("oidc-on", settings(true)).is_err());
    // Switched off, the settings are kept but not used.
    let off = shared_with_oidc("oidc-off", settings(false)).expect("starts");
    assert!(off.oidc.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sign_in_routes_open_a_session_the_api_accepts_and_close_it() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let idp = start().await;
    let config = OidcConfig {
        enabled: true,
        issuer: idp.issuer.clone(),
        client_id: "sluice".into(),
        client_secret_file: None,
        redirect_url: "https://sluice.example/auth/callback".into(),
        name_claim: "email".into(),
        operators: vec!["alice@example.org".into()],
        session_secs: 3_600,
    };
    let shared = tokio::task::spawn_blocking(move || shared_with_oidc("oidc-flow", config))
        .await
        .unwrap()
        .expect("starts");
    let shared = Arc::new(shared);
    let call = |request: Request<Body>| {
        let app = crate::routes::router(Arc::clone(&shared));
        async move { app.oneshot(request).await.unwrap() }
    };
    let get = |uri: &str, cookie: Option<&str>| {
        let mut request = Request::get(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        request.body(Body::empty()).unwrap()
    };

    let login = call(get("/auth/login", None)).await;
    assert!(login.status().is_redirection(), "{}", login.status());
    let location = login.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with(&format!("{}/authorize", idp.issuer)));
    *idp.nonce.lock().unwrap() = param(&location, "nonce");
    let state = param(&location, "state");

    for (uri, refused) in [
        ("/auth/callback?error=access_denied", StatusCode::FORBIDDEN),
        ("/auth/callback?code=c", StatusCode::BAD_REQUEST),
        ("/auth/callback?state=s", StatusCode::BAD_REQUEST),
        ("/auth/callback?code=c&state=forged", StatusCode::FORBIDDEN),
    ] {
        assert_eq!(call(get(uri, None)).await.status(), refused, "{uri}");
    }

    let done = call(get(&format!("/auth/callback?code=c&state={state}"), None)).await;
    assert!(done.status().is_redirection(), "{}", done.status());
    assert_eq!(done.headers()[header::LOCATION], "/");
    let set_cookie = done.headers()[header::SET_COOKIE].to_str().unwrap();
    let session = set_cookie.split(';').next().unwrap().to_owned();

    let with_others = format!("theme=dark; {session}");
    assert_eq!(
        call(get("/status", Some(&with_others))).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        call(get("/status", Some("sluice_session=guessed")))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let logout = Request::post("/auth/logout")
        .header(header::COOKIE, &session)
        .body(Body::empty())
        .unwrap();
    let out = call(logout).await;
    assert_eq!(out.status(), StatusCode::NO_CONTENT);
    assert!(out.headers().contains_key(header::SET_COOKIE), "cleared");
    assert_eq!(
        call(get("/status", Some(&session))).await.status(),
        StatusCode::UNAUTHORIZED,
        "signed out"
    );
}

#[test]
fn the_session_cookie_is_found_among_others_and_is_never_empty() {
    use axum::http::{HeaderMap, header};

    use super::COOKIE;
    use super::routes::session_id;

    let headers = |values: &[String]| {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::COOKIE, value.parse().unwrap());
        }
        headers
    };
    let found = |values: &[String]| session_id(&headers(values));
    assert_eq!(
        found(&[format!("a=1; {COOKIE}=s1; b=2")]).as_deref(),
        Some("s1")
    );
    assert_eq!(
        found(&["a=1".into(), format!("{COOKIE}=s2")]).as_deref(),
        Some("s2"),
        "in a second Cookie header"
    );
    assert_eq!(found(&[format!("{COOKIE}=")]), None);
    assert_eq!(found(&[format!("x{COOKIE}=s3")]), None);
    assert_eq!(found(&[]), None);
}

#[tokio::test]
async fn switched_off_the_sign_in_routes_say_so() {
    use tower::ServiceExt;
    let shared = Arc::new(shared_with_oidc("oidc-routes", settings(false)).expect("starts"));
    let get = |uri: &'static str| {
        let app = crate::routes::router(Arc::clone(&shared));
        async move {
            app.oneshot(
                axum::http::Request::get(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    let info = get("/auth/info").await;
    let body = axum::body::to_bytes(info.into_body(), 1024).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"oidc": false})
    );
    for uri in ["/auth/login", "/auth/callback?code=c&state=s"] {
        assert_eq!(
            get(uri).await.status(),
            axum::http::StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
    let logout = crate::routes::router(Arc::clone(&shared))
        .oneshot(
            axum::http::Request::post("/auth/logout")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), axum::http::StatusCode::NOT_FOUND);
}
