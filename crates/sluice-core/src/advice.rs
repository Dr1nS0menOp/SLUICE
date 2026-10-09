//! The contract for AI-written proposals (safety contract rule 6: AI proposes; guardrails decide).

use crate::event::Event;
use crate::recipe::Recipe;
use crate::template::Template;

/// The advisor could not produce a proposal. The template then simply gets none.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("advisor failed: {0}")]
pub struct AdviceError(pub String);

/// Proposes a recipe for a template no community recipe covers.
///
/// It is consulted once per template, never per event. A proposal is just a [`Recipe`]: it gets
/// no extra trust, and it passes the same guardrails and shadow proof as any other.
pub trait Advisor {
    /// A proposal for `template`, based on a few of its events, or `None` to leave it alone.
    ///
    /// # Errors
    ///
    /// Returns [`AdviceError`] if the advisor is unreachable or answers invalidly.
    fn propose(
        &self,
        template: &Template,
        samples: &[&Event],
    ) -> Result<Option<Recipe>, AdviceError>;
}
