//! Splunk for Sluice (ADR 0026): the saved searches and macros a Splunk runs, read through its
//! REST API into an inventory `sluice_rules::SplunkRules` reads.

pub mod inventory;

/// Splunk could not be read.
#[derive(Debug, thiserror::Error)]
pub enum SplunkError {
    /// The request did not reach Splunk.
    #[error("cannot reach Splunk at {url}: {reason}")]
    Unreachable {
        /// The management URL.
        url: String,
        /// Why.
        reason: String,
    },
    /// Splunk answered with an error status.
    #[error("Splunk refused the request ({status}): {message}")]
    Rejected {
        /// The HTTP status.
        status: u16,
        /// Splunk's answer.
        message: String,
    },
    /// The answer is not what the REST API documents.
    #[error("an unexpected answer from Splunk: {0}")]
    Response(String),
}
