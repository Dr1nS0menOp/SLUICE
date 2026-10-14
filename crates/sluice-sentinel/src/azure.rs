//! A minimal, read-only client for Azure Resource Manager and the Log Analytics query API.

use std::time::Duration;

use serde_json::Value;

/// An Azure API could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SentinelError {
    /// The request failed or returned an error status.
    #[error("Azure request failed: {0}")]
    Http(String),
    /// The response did not have the documented shape.
    #[error("unexpected Azure response: {0}")]
    Invalid(String),
}

/// How requests leave the process; swapped out in tests.
pub trait Transport {
    /// Sends a request and returns `(status, body)`.
    ///
    /// # Errors
    ///
    /// Returns [`SentinelError::Http`] if the request cannot be sent.
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), SentinelError>;
}

/// HTTPS transport with certificate verification.
#[derive(Debug)]
pub struct Http {
    agent: ureq::Agent,
}

impl Default for Http {
    fn default() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl Transport for Http {
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), SentinelError> {
        // The URL may carry no secret, but keep it out of errors anyway: only the path.
        let place = url.split('?').next().unwrap_or(url);
        let failed = |e: String| SentinelError::Http(format!("{method} {place}: {e}"));
        let request = ureq::http::Request::builder().method(method).uri(url);
        let request = headers
            .iter()
            .fold(request, |r, (name, value)| r.header(*name, value.as_str()))
            .body(body.unwrap_or_default().to_owned())
            .map_err(|e| failed(e.to_string()))?;
        let mut response = self.agent.run(request).map_err(|e| failed(e.to_string()))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| failed(e.to_string()))?;
        Ok((status, text))
    }
}

/// An Azure AD application's client credentials. The secret never appears in errors.
#[derive(Clone)]
pub struct Credentials {
    /// Directory (tenant) id.
    pub tenant: String,
    /// Application (client) id.
    pub client_id: String,
    /// Client secret.
    pub client_secret: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("tenant", &self.tenant)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

/// Resource Manager.
pub(crate) const ARM: &str = "https://management.azure.com";
/// The Log Analytics query API.
pub(crate) const LOG_ANALYTICS: &str = "https://api.loganalytics.io";

/// A client with a token for one API.
pub(crate) struct Client<'a, T> {
    pub(crate) transport: &'a T,
    token: String,
}

impl<'a, T: Transport> Client<'a, T> {
    /// Gets a token for `resource` (such as [`ARM`]) with the client credentials flow.
    pub(crate) fn new(
        transport: &'a T,
        credentials: &Credentials,
        resource: &str,
    ) -> Result<Self, SentinelError> {
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("scope", &format!("{resource}/.default")),
        ]
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect::<Vec<_>>()
        .join("&");
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            encode(&credentials.tenant)
        );
        let (status, body) = transport.send(
            "POST",
            &url,
            &[(
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            )],
            Some(&form),
        )?;
        let token = json(status, &body)?["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                SentinelError::Invalid("no access_token in the token response".into())
            })?;
        Ok(Self { transport, token })
    }

    fn headers(&self) -> [(&'static str, String); 2] {
        [
            ("authorization", format!("Bearer {}", self.token)),
            ("content-type", "application/json".to_owned()),
        ]
    }

    pub(crate) fn get(&self, url: &str) -> Result<Value, SentinelError> {
        let (status, body) = self.transport.send("GET", url, &self.headers(), None)?;
        json(status, &body)
    }

    pub(crate) fn post(&self, url: &str, body: &Value) -> Result<Value, SentinelError> {
        let (status, text) =
            self.transport
                .send("POST", url, &self.headers(), Some(&body.to_string()))?;
        json(status, &text)
    }

    /// Every item of a Resource Manager list, following `nextLink`.
    pub(crate) fn list(&self, url: &str) -> Result<Vec<Value>, SentinelError> {
        let mut items = Vec::new();
        let mut next = Some(url.to_owned());
        while let Some(url) = next.take() {
            let page = self.get(&url)?;
            let Some(values) = page["value"].as_array() else {
                return Err(SentinelError::Invalid(format!(
                    "no value array in {}",
                    short(&url)
                )));
            };
            items.extend(values.iter().cloned());
            next = page["nextLink"].as_str().map(str::to_owned);
        }
        Ok(items)
    }
}

fn json(status: u16, body: &str) -> Result<Value, SentinelError> {
    if !(200..300).contains(&status) {
        let message = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
            .unwrap_or_else(|| body.chars().take(300).collect());
        return Err(SentinelError::Http(format!("HTTP {status}: {message}")));
    }
    serde_json::from_str(body).map_err(|e| SentinelError::Invalid(e.to_string()))
}

fn short(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

/// Percent-encodes a form or query value: everything but unreserved characters.
pub(crate) fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
