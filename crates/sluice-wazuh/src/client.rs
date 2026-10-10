//! The Wazuh API client.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{Map, Value, json};
use sluice_core::alert::{EngineError, EventRules};
use sluice_core::ids::RuleId;

/// The Wazuh API could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WazuhError {
    /// The request failed or returned an error status.
    #[error("Wazuh API request failed: {0}")]
    Http(String),
    /// The response did not have the documented shape.
    #[error("unexpected Wazuh API response: {0}")]
    Invalid(String),
}

/// How requests leave the process; swapped out in tests.
pub trait Transport {
    /// Sends a request and returns `(status, body)`.
    ///
    /// # Errors
    ///
    /// Returns [`WazuhError::Http`] if the request cannot be sent.
    fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), WazuhError>;
}

/// HTTP transport. Wazuh managers usually serve the API with a self-signed certificate; pass
/// `insecure` only when the network path to the manager is trusted.
#[derive(Debug)]
pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    /// A transport, optionally skipping TLS certificate verification.
    #[must_use]
    pub fn new(insecure: bool) -> Self {
        let tls = ureq::tls::TlsConfig::builder()
            .disable_verification(insecure)
            .build();
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .tls_config(tls)
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
    ) -> Result<(u16, String), WazuhError> {
        let failed = |e: ureq::Error| WazuhError::Http(format!("{method} {url}: {e}"));
        let request = ureq::http::Request::builder().method(method).uri(url);
        let request = headers
            .iter()
            .fold(request, |r, (name, value)| r.header(*name, value.as_str()))
            .header("content-type", "application/json")
            .body(body.unwrap_or_default().to_owned())
            .map_err(|e| WazuhError::Http(format!("{method} {url}: {e}")))?;
        let mut response = self.agent.run(request).map_err(failed)?;
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().map_err(failed)?;
        Ok((status, text))
    }
}

/// Where and how to reach the manager API.
#[derive(Debug, Clone)]
pub struct LogtestConfig {
    /// Base URL, such as `https://wazuh.example:55000`.
    pub url: String,
    /// API user (needs the `logtest:run` permission).
    pub user: String,
    /// API password.
    pub password: String,
}

/// `logtest` as [`EventRules`]: the rule (if any) that alerts on an event.
pub struct Logtest<T = Http> {
    config: LogtestConfig,
    transport: T,
    jwt: RefCell<Option<String>>,
    session: RefCell<Option<String>>,
}

impl<T: Transport> Logtest<T> {
    /// A client; it authenticates on first use.
    pub fn new(config: LogtestConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            jwt: RefCell::new(None),
            session: RefCell::new(None),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.url.trim_end_matches('/'))
    }

    fn authenticate(&self) -> Result<String, WazuhError> {
        if let Some(jwt) = self.jwt.borrow().clone() {
            return Ok(jwt);
        }
        let basic = base64(&format!("{}:{}", self.config.user, self.config.password));
        let (status, body) = self.transport.send(
            "POST",
            &self.url("/security/user/authenticate"),
            &[("authorization", format!("Basic {basic}"))],
            None,
        )?;
        let jwt = ok_json(status, &body)?["data"]["token"]
            .as_str()
            .ok_or_else(|| {
                WazuhError::Invalid("no data.token in the authentication response".into())
            })?
            .to_owned();
        *self.jwt.borrow_mut() = Some(jwt.clone());
        Ok(jwt)
    }

    /// The rule that alerts on `event` (sent as JSON), or `None`.
    ///
    /// # Errors
    ///
    /// Returns [`WazuhError`] if the API cannot be used.
    pub fn alert(&self, event: &Map<String, Value>) -> Result<Option<String>, WazuhError> {
        self.logtest(&Value::Object(event.clone()).to_string(), "json")
    }

    /// The rule that alerts on a raw log line (decoded as syslog), or `None`.
    ///
    /// # Errors
    ///
    /// Returns [`WazuhError`] if the API cannot be used.
    pub fn alert_line(&self, line: &str) -> Result<Option<String>, WazuhError> {
        self.logtest(line, "syslog")
    }

    fn logtest(&self, event: &str, log_format: &str) -> Result<Option<String>, WazuhError> {
        let jwt = self.authenticate()?;
        let mut request = json!({
            "event": event,
            "log_format": log_format,
            "location": "sluice",
        });
        if let Some(session) = self.session.borrow().clone() {
            request["token"] = json!(session);
        }
        let (status, body) = self.transport.send(
            "PUT",
            &self.url("/logtest"),
            &[("authorization", format!("Bearer {jwt}"))],
            Some(&request.to_string()),
        )?;
        let response = ok_json(status, &body)?;
        let data = &response["data"];
        if let Some(session) = data["token"].as_str() {
            *self.session.borrow_mut() = Some(session.to_owned());
        }
        if data["alert"] != json!(true) {
            return Ok(None);
        }
        // `rule.id` is a string in live responses and a number in the spec's example.
        let id = match &data["output"]["rule"]["id"] {
            Value::String(id) => id.clone(),
            Value::Number(id) => id.to_string(),
            _ => return Err(WazuhError::Invalid("alert without output.rule.id".into())),
        };
        Ok(Some(id))
    }
}

impl<T: Transport> EventRules for Logtest<T> {
    fn fired(&self, fields: &Map<String, Value>) -> Result<BTreeSet<RuleId>, EngineError> {
        rule_ids(self.alert(fields))
    }

    fn fired_line(&self, line: &str) -> Result<BTreeSet<RuleId>, EngineError> {
        rule_ids(self.alert_line(line))
    }
}

fn rule_ids(alert: Result<Option<String>, WazuhError>) -> Result<BTreeSet<RuleId>, EngineError> {
    let alert = alert.map_err(|e| EngineError(e.to_string()))?;
    Ok(alert
        .into_iter()
        .map(|id| RuleId::new(format!("wazuh:{id}")))
        .collect())
}

fn ok_json(status: u16, body: &str) -> Result<Value, WazuhError> {
    if !(200..300).contains(&status) {
        return Err(WazuhError::Http(format!("HTTP {status}: {body}")));
    }
    let value: Value =
        serde_json::from_str(body).map_err(|e| WazuhError::Invalid(e.to_string()))?;
    if value["error"] != json!(0) {
        return Err(WazuhError::Invalid(format!(
            "error {} in {body}",
            value["error"]
        )));
    }
    Ok(value)
}

/// Standard base64, for the Basic authorization header.
fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (n >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[usize::try_from(index).unwrap_or(0)]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
