//! Splunk's REST API on its management port, as the fetch and the proof call it.

use std::time::Duration;

use serde_json::Value;

use crate::SplunkError;

/// How a request is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// A Splunk authentication token (`Authorization: Bearer …`).
    Token(String),
    /// A user and password.
    Basic {
        /// The user.
        user: String,
        /// The password.
        password: String,
    },
}

impl Auth {
    fn header(&self) -> String {
        match self {
            Self::Token(token) => format!("Bearer {token}"),
            Self::Basic { user, password } => sluice_http::basic_auth(user, password),
        }
    }
}

/// The management port: its address, the credentials and the HTTP client.
#[derive(Debug, Clone)]
pub(crate) struct Rest {
    http: sluice_http::Client,
    base: String,
    authorization: String,
}

impl Rest {
    pub(crate) fn new(url: &str, auth: &Auth, insecure: bool, timeout: Duration) -> Self {
        Self {
            http: sluice_http::Client::with(timeout, insecure, sluice_http::MAX_ANSWER),
            base: url.trim_end_matches('/').to_owned(),
            authorization: auth.header(),
        }
    }

    /// The management port's address, without a trailing slash.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// `method` on `path` (which may carry a query) with `form` as its body, asking for JSON.
    /// Any status is an answer; only a request that cannot be made is an error.
    pub(crate) fn send(
        &self,
        method: &str,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<sluice_http::Answer, SplunkError> {
        let separator = if path.contains('?') { '&' } else { '?' };
        let url = format!("{}{path}{separator}output_mode=json", self.base);
        let mut headers = vec![("authorization", self.authorization.clone())];
        let body = (method == "POST").then(|| {
            headers.push((
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ));
            encode(form)
        });
        self.http
            .send(method, &url, &headers, body.as_deref())
            .map_err(|e| SplunkError::Unreachable {
                url: self.base.clone(),
                reason: e.reason,
            })
    }

    /// As [`Rest::send`], for an answer that must be a success, read as JSON.
    pub(crate) fn json(
        &self,
        method: &str,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<Value, SplunkError> {
        let answer = self.send(method, path, form)?;
        if !answer.is_success() {
            return Err(SplunkError::Rejected {
                status: answer.status,
                message: answer.body,
            });
        }
        serde_json::from_str(&answer.body).map_err(|e| SplunkError::Response(e.to_string()))
    }
}

/// `form` as `application/x-www-form-urlencoded`.
pub(crate) fn encode(form: &[(&str, &str)]) -> String {
    form.iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                sluice_http::percent_encode(name),
                sluice_http::percent_encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The first entry's `content` of a REST answer, where Splunk puts an object's settings.
pub(crate) fn content(answer: &Value) -> &Value {
    &answer["entry"][0]["content"]
}

/// The text of Splunk's messages of the given types in an answer, joined; empty when it has
/// none.
pub(crate) fn messages(answer: &Value, types: &[&str]) -> String {
    answer["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["type"].as_str().is_some_and(|t| types.contains(&t)))
        .filter_map(|m| m["text"].as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_form_is_percent_encoded() {
        assert_eq!(
            encode(&[("search", "index=a | stats count"), ("count", "0")]),
            "search=index%3Da%20%7C%20stats%20count&count=0"
        );
    }

    #[test]
    fn messages_of_the_asked_types_are_joined() {
        let answer = json!({ "messages": [
            { "type": "WARN", "text": "w" },
            { "type": "FATAL", "text": "f" },
            { "type": "ERROR", "text": "e" },
        ] });
        assert_eq!(messages(&answer, &["FATAL", "ERROR"]), "f; e");
        assert_eq!(messages(&json!({}), &["FATAL"]), "");
    }

    #[test]
    fn credentials_become_the_authorization_header() {
        assert_eq!(Auth::Token("t".into()).header(), "Bearer t");
        assert_eq!(
            Auth::Basic {
                user: "admin".into(),
                password: "p".into()
            }
            .header(),
            sluice_http::basic_auth("admin", "p")
        );
    }
}
