//! The HTTP client every Sluice adapter uses: to read a SIEM's API (Azure, Wazuh, Kibana,
//! Splunk), to run rules and configurations in a real engine (Elasticsearch, the Kusto emulator)
//! and to ask a language model. One answer limit, one way to skip certificate verification and
//! one error excerpt, instead of a client per adapter that each did these its own way.
//!
//! An error status is an answer like any other: what it means is the caller's to say. Only a
//! request that cannot be made, or an answer that cannot be read, is an [`HttpError`].

use std::time::Duration;

/// The largest answer read: Azure's query log and Kibana's rule pages are the biggest the
/// adapters read.
pub const MAX_ANSWER: u64 = 256 * 1024 * 1024;

/// The most characters of an answer an error quotes.
pub const EXCERPT: usize = 300;

/// A request could not be made, or its answer not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{method} {place}: {reason}")]
pub struct HttpError {
    /// The method.
    pub method: String,
    /// The URL without its query, which may carry what should stay out of messages.
    pub place: String,
    /// What went wrong.
    pub reason: String,
}

/// An answer: its status and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The body, as text.
    pub body: String,
}

impl Answer {
    /// Whether the status is a success (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// An HTTP client: its timeout, answer limit and certificate handling.
#[derive(Debug, Clone)]
pub struct Client {
    agent: ureq::Agent,
    max_answer: u64,
}

impl Client {
    /// A client whose requests give up after `timeout`, verifying certificates and reading
    /// answers up to [`MAX_ANSWER`].
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self::with(timeout, false, MAX_ANSWER)
    }

    /// A client that skips certificate verification when `insecure` (a manager with a
    /// self-signed certificate, on a trusted network path), and reads at most `max_answer`
    /// bytes of an answer.
    #[must_use]
    pub fn with(timeout: Duration, insecure: bool, max_answer: u64) -> Self {
        let tls = ureq::tls::TlsConfig::builder()
            .disable_verification(insecure)
            .build();
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .tls_config(tls)
            .build()
            .into();
        Self { agent, max_answer }
    }

    /// Sends `method` to `url` with `headers` and `body`, and reads the answer.
    ///
    /// # Errors
    ///
    /// [`HttpError`] if the request cannot be made or its answer cannot be read, for one larger
    /// than the client's limit too.
    pub fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<Answer, HttpError> {
        let failed = |reason: String| HttpError {
            method: method.to_owned(),
            place: url.split('?').next().unwrap_or(url).to_owned(),
            reason,
        };
        let request = ureq::http::Request::builder().method(method).uri(url);
        let request = headers
            .iter()
            .fold(request, |r, (name, value)| r.header(*name, value.as_str()))
            .body(body.unwrap_or_default().to_owned())
            .map_err(|e| failed(e.to_string()))?;
        let mut response = self.agent.run(request).map_err(|e| failed(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_answer)
            .read_to_string()
            .map_err(|e| failed(e.to_string()))?;
        Ok(Answer { status, body })
    }
}

/// The start of `text`, for an error message: answers can be large, and can repeat what was
/// sent.
#[must_use]
pub fn excerpt(text: &str) -> String {
    let mut out: String = text.chars().take(EXCERPT).collect();
    if text.chars().nth(EXCERPT).is_some() {
        out.push('…');
    }
    out
}

/// The `Authorization` header value of HTTP Basic authentication.
#[must_use]
pub fn basic_auth(user: &str, password: &str) -> String {
    format!("Basic {}", base64(&format!("{user}:{password}")))
}

/// Standard base64 (RFC 4648), with padding.
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

/// `value` with every byte but the unreserved characters of RFC 3986 percent-encoded, for a
/// query parameter or a path segment.
#[must_use]
pub fn percent_encode(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (text, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
            ("elastic:changeme", "ZWxhc3RpYzpjaGFuZ2VtZQ=="),
        ] {
            assert_eq!(base64(text), encoded, "{text}");
        }
        assert_eq!(basic_auth("user", "pass"), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn percent_encoding_keeps_only_unreserved_characters() {
        assert_eq!(percent_encode("aZ09-_.~"), "aZ09-_.~");
        assert_eq!(percent_encode("a b&c=d/e?f"), "a%20b%26c%3Dd%2Fe%3Ff");
        assert_eq!(percent_encode("é"), "%C3%A9");
        assert_eq!(percent_encode("%"), "%25");
    }

    #[test]
    fn an_excerpt_is_short_and_says_so() {
        assert_eq!(excerpt("short"), "short");
        let long = "x".repeat(EXCERPT + 1);
        assert_eq!(excerpt(&long).chars().count(), EXCERPT + 1);
        assert!(excerpt(&long).ends_with('…'));
    }

    #[test]
    fn an_error_status_is_an_answer_and_no_address_is_an_error() {
        assert!(
            Answer {
                status: 204,
                body: String::new()
            }
            .is_success()
        );
        assert!(
            !Answer {
                status: 404,
                body: String::new()
            }
            .is_success()
        );
        // Nothing listens on port 9 here.
        let error = Client::new(Duration::from_secs(5))
            .send("GET", "http://127.0.0.1:9/a?secret=x", &[], None)
            .unwrap_err();
        assert_eq!(error.place, "http://127.0.0.1:9/a");
        assert!(!error.to_string().contains("secret"), "{error}");
    }
}
