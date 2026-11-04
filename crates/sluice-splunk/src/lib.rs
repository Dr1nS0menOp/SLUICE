//! Splunk for Sluice (ADR 0026, ADR 0037): the saved searches and macros a Splunk runs, read
//! through its REST API into an inventory `sluice_rules::SplunkRules` reads, and those searches
//! run in a real Splunk for the proof ([`SplunkEngine`]).

mod answer;
mod client;
mod engine;
mod hec;
mod index;
pub mod inventory;
mod scope;

pub use crate::client::Auth;
pub use crate::engine::{EVENT_FIELD, Proof, RUN_FIELD, SOURCETYPE, SplunkEngine};

/// Splunk could not be read, or could not run the proof.
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
    #[error("Splunk refused the request ({status}): {}", sluice_http::excerpt(.message))]
    Rejected {
        /// The HTTP status.
        status: u16,
        /// Splunk's whole answer.
        message: String,
    },
    /// The answer is not what the REST API documents, or not what the proof needs.
    #[error("an unexpected answer from Splunk: {0}")]
    Response(String),
}
