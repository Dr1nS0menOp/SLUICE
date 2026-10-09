//! Errors of the AI crate.

/// A model could not deliver a usable answer. The template then simply gets no AI proposal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AiError {
    /// The model is not configured (for example a missing API key).
    #[error("{0}")]
    Config(String),
    /// The request failed or returned an error status.
    #[error("request failed: {0}")]
    Http(String),
    /// The model declined to answer.
    #[error("the model declined to answer ({0})")]
    Refused(String),
    /// The answer hit the output limit.
    #[error("the answer was truncated")]
    Truncated,
    /// The answer does not match the expected shape.
    #[error("invalid answer: {0}")]
    Invalid(String),
}
