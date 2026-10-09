//! The data-plane contract the shadow proof relies on: what happens to one event.

use serde_json::{Map, Value};

use crate::event::Event;
use crate::ids::TemplateId;

/// What the data plane does with an event.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Forwarded to the SIEM with this body (possibly reduced).
    Forwarded(Map<String, Value>),
    /// Not forwarded in full: counted into a summary, with the original kept in the archive.
    Summarized,
}

/// The result of reducing one event.
#[derive(Debug, Clone, PartialEq)]
pub struct Reduced {
    /// The template the data plane classified the event as, if any.
    pub template: Option<TemplateId>,
    /// What happened to it.
    pub outcome: Outcome,
}

/// The data plane could not process an event. The proof treats this as "not proven".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("reduction failed: {0}")]
pub struct ReduceError(pub String);

/// Applies the enforced reductions to events, exactly as the data plane would.
pub trait Reducer {
    /// Classifies and reduces one event.
    ///
    /// # Errors
    ///
    /// Returns [`ReduceError`] if the event cannot be processed.
    fn reduce(&self, event: &Event) -> Result<Reduced, ReduceError>;
}
