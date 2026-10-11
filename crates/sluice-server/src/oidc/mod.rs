//! Single sign-on with OIDC (ADR 0016): operators sign in to the console with their
//! organization's identity provider, and the audit log names them as the provider does.
//!
//! The flow is the authorization code flow with PKCE, `state` and `nonce`. The provider is found
//! through its discovery document, its keys through its JWKS (refreshed once when a token names
//! an unknown key). Only names listed in `operators` may sign in. A session is a random id in a
//! `HttpOnly`, `SameSite=Strict` cookie, kept in memory: a restart signs everyone out.

mod jwt;
pub(crate) mod routes;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::Value;

use crate::control::lock;
use crate::error::ServerError;

/// The session cookie's name.
pub(crate) const COOKIE: &str = "sluice_session";

/// How long a login may take, from redirect to callback.
const LOGIN_SECS: i64 = 600;

/// Most logins in progress at once; older ones are dropped first.
const MAX_PENDING: usize = 1_000;

/// Single sign-on settings in the `sluice up` configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The provider's issuer URL, as its discovery document states it.
    pub issuer: String,
    /// Sluice's client id at the provider.
    pub client_id: String,
    /// A file with the client secret, for providers that require one; without it, the client is
    /// public and PKCE alone binds the code to the login.
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
    /// Where the provider sends the browser back: `https://<console>/auth/callback`.
    pub redirect_url: String,
    /// The claim that names the operator (default `email`; `preferred_username` for Keycloak).
    #[serde(default = "default_name_claim")]
    pub name_claim: String,
    /// The names that may sign in, as the claim states them (compared ignoring case).
    pub operators: Vec<String>,
    /// How long a session lasts, in seconds (default 8 hours).
    #[serde(default = "default_session_secs")]
    pub session_secs: i64,
}

fn default_name_claim() -> String {
    "email".to_owned()
}

fn default_session_secs() -> i64 {
    8 * 3_600
}

/// The provider's endpoints and keys.
#[derive(Debug, Clone)]
struct Provider {
    authorization_endpoint: String,
    token_endpoint: String,
    keys: jwt::JwkSet,
}

/// A login between the redirect and the callback.
#[derive(Debug)]
struct Pending {
    nonce: String,
    verifier: String,
    started: i64,
}

/// A signed-in operator.
#[derive(Debug, Clone)]
struct Session {
    name: String,
    expires: i64,
}

/// Single sign-on state.
#[derive(Debug)]
pub(crate) struct Oidc {
    config: OidcConfig,
    client_secret: Option<String>,
    provider: Mutex<Option<Provider>>,
    pending: Mutex<BTreeMap<String, Pending>>,
    sessions: Mutex<BTreeMap<String, Session>>,
}

impl Oidc {
    /// Reads the client secret; the provider itself is contacted at the first login.
    pub(crate) fn new(config: OidcConfig) -> Result<Self, ServerError> {
        if config.operators.is_empty() {
            return Err(ServerError::Config(
                "oidc.operators is empty: nobody could sign in".to_owned(),
            ));
        }
        let client_secret = match &config.client_secret_file {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| ServerError::Config(format!("{}: {e}", path.display())))?
                    .trim()
                    .to_owned(),
            ),
            None => None,
        };
        Ok(Self {
            config,
            client_secret,
            provider: Mutex::new(None),
            pending: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(BTreeMap::new()),
        })
    }

    /// Starts a login: the URL to send the browser to.
    pub(crate) fn login_url(&self, now: i64) -> Result<String, String> {
        let provider = self.provider(false)?;
        let state = random()?;
        let nonce = random()?;
        let verifier = random()?;
        let challenge = URL_SAFE_NO_PAD
            .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
        let mut pending = lock(&self.pending);
        pending.retain(|_, p| now - p.started < LOGIN_SECS);
        while pending.len() >= MAX_PENDING {
            let oldest = pending
                .iter()
                .min_by_key(|(_, p)| p.started)
                .map(|(state, _)| state.clone());
            match oldest {
                Some(state) => pending.remove(&state),
                None => break,
            };
        }
        pending.insert(
            state.clone(),
            Pending {
                nonce: nonce.clone(),
                verifier,
                started: now,
            },
        );
        let query = [
            ("response_type", "code"),
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("scope", "openid email profile"),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        let separator = if provider.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!(
            "{}{separator}{}",
            provider.authorization_endpoint,
            form(&query)
        ))
    }

    /// Completes a login: exchanges the code, verifies the ID token and opens a session. Returns
    /// the session id and the operator's name.
    pub(crate) fn callback(
        &self,
        code: &str,
        state: &str,
        now: i64,
    ) -> Result<(String, String), String> {
        let pending = lock(&self.pending)
            .remove(state)
            .filter(|p| now - p.started < LOGIN_SECS)
            .ok_or("this login expired or was already used; sign in again")?;
        let provider = self.provider(false)?;
        let mut body = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        if let Some(secret) = &self.client_secret {
            body.push(("client_secret", secret.as_str()));
        }
        let answer = post_form(&provider.token_endpoint, &form(&body))?;
        let token = answer
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or("the provider returned no ID token")?;
        let expected = jwt::Expected {
            issuer: &self.config.issuer,
            client_id: &self.config.client_id,
            nonce: &pending.nonce,
            now,
        };
        let claims = match jwt::verify(token, &provider.keys, expected) {
            Err(jwt::JwtError::UnknownKey) => {
                let refreshed = self.provider(true)?;
                jwt::verify(token, &refreshed.keys, expected)
            }
            other => other,
        }
        .map_err(|e| format!("the ID token was refused: {e}"))?;
        let name = claims
            .get(&self.config.name_claim)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the ID token has no `{}` claim", self.config.name_claim))?;
        let operator = self
            .config
            .operators
            .iter()
            .find(|o| o.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("{name} is not an operator of this Sluice"))?
            .clone();
        let id = random()?;
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(
            id.clone(),
            Session {
                name: operator.clone(),
                expires: now + self.config.session_secs,
            },
        );
        Ok((id, operator))
    }

    /// The operator a session cookie belongs to, if it is valid.
    pub(crate) fn session(&self, id: &str, now: i64) -> Option<String> {
        lock(&self.sessions)
            .get(id)
            .filter(|s| s.expires > now)
            .map(|s| s.name.clone())
    }

    /// Ends a session.
    pub(crate) fn sign_out(&self, id: &str) {
        lock(&self.sessions).remove(id);
    }

    /// The cookie that carries a session, or clears it with `None`.
    pub(crate) fn cookie(&self, session: Option<&str>) -> String {
        let secure = if self.config.redirect_url.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        match session {
            Some(id) => format!(
                "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
                self.config.session_secs
            ),
            None => format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"),
        }
    }

    /// The provider, discovered on first use; `refresh` reloads it (new signing keys).
    fn provider(&self, refresh: bool) -> Result<Provider, String> {
        let mut cached = lock(&self.provider);
        if let (Some(provider), false) = (cached.as_ref(), refresh) {
            return Ok(provider.clone());
        }
        let issuer = self.config.issuer.trim_end_matches('/');
        let discovery = get_json(&format!("{issuer}/.well-known/openid-configuration"))?;
        if discovery.get("issuer").and_then(Value::as_str) != Some(self.config.issuer.as_str()) {
            return Err("the provider's discovery document names another issuer".to_owned());
        }
        let endpoint = |key: &str| {
            discovery
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("the provider's discovery document has no {key}"))
        };
        let jwks_uri = endpoint("jwks_uri")?;
        let keys = serde_json::from_value(get_json(&jwks_uri)?)
            .map_err(|e| format!("the provider's keys could not be read: {e}"))?;
        let provider = Provider {
            authorization_endpoint: endpoint("authorization_endpoint")?,
            token_endpoint: endpoint("token_endpoint")?,
            keys,
        };
        *cached = Some(provider.clone());
        Ok(provider)
    }
}

/// 32 random bytes, base64url.
fn random() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "no randomness available".to_owned())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// `application/x-www-form-urlencoded` pairs.
fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into()
}

fn read(mut answer: ureq::http::Response<ureq::Body>, url: &str) -> Result<Value, String> {
    let status = answer.status();
    let text = answer
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("{url}: {e}"))?;
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("{url}: {e}"))
}

fn get_json(url: &str) -> Result<Value, String> {
    let answer = agent().get(url).call().map_err(|e| format!("{url}: {e}"))?;
    read(answer, url)
}

fn post_form(url: &str, body: &str) -> Result<Value, String> {
    let answer = agent()
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .send(body)
        .map_err(|e| format!("{url}: {e}"))?;
    read(answer, url)
}

#[cfg(test)]
mod tests;
