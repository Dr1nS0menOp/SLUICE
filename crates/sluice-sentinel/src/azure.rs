//! A minimal, read-only client for Azure Resource Manager and the Log Analytics query API.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;
/// Percent-encodes a form or query value: everything but unreserved characters.
pub(crate) use sluice_http::percent_encode as encode;

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
    client: sluice_http::Client,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            client: sluice_http::Client::new(Duration::from_secs(60)),
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
        // The error names the URL without its query, which carries no secret but stays out.
        let answer = self
            .client
            .send(method, url, headers, body)
            .map_err(|e| SentinelError::Http(e.to_string()))?;
        Ok((answer.status, answer.body))
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
        let secret = credentials.client_secret.as_str();
        let (status, body) = transport
            .send(
                "POST",
                &url,
                &[(
                    "content-type",
                    "application/x-www-form-urlencoded".to_owned(),
                )],
                Some(&form),
            )
            .map_err(|e| scrub(e, secret))?;
        let token = json(status, &body).map_err(|e| scrub(e, secret))?["access_token"]
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
    ///
    /// A `nextLink` must stay on the list's own origin, so the bearer token never goes to a
    /// host the response names, and must not repeat, so a misbehaving API cannot loop us.
    pub(crate) fn list(&self, url: &str) -> Result<Vec<Value>, SentinelError> {
        let home = origin(url);
        let mut seen = BTreeSet::new();
        let mut items = Vec::new();
        let mut next = Some(url.to_owned());
        while let Some(url) = next.take() {
            if origin(&url) != home {
                return Err(SentinelError::Invalid(format!(
                    "a nextLink leaves {home}: {}",
                    short(&url)
                )));
            }
            if !seen.insert(url.clone()) {
                return Err(SentinelError::Invalid(format!(
                    "a nextLink repeats: {}",
                    short(&url)
                )));
            }
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

/// `scheme://host[:port]`, lowercased; the whole string when it has no `://`.
fn origin(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_ascii_lowercase();
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    format!("{scheme}://{host}").to_ascii_lowercase()
}

/// Replaces the secret, raw and form-encoded, wherever an error message repeats it.
fn scrub(error: SentinelError, secret: &str) -> SentinelError {
    if secret.is_empty() {
        return error;
    }
    let clean = |m: String| {
        m.replace(secret, "<redacted>")
            .replace(&encode(secret), "<redacted>")
    };
    match error {
        SentinelError::Http(m) => SentinelError::Http(clean(m)),
        SentinelError::Invalid(m) => SentinelError::Invalid(clean(m)),
    }
}

#[cfg(test)]
mod tests;
