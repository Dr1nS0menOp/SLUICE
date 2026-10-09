//! AI-written recipe proposals (L3, semantic fat) for templates no community recipe covers.
//!
//! A model sees a few redacted samples of one template, never of one event in isolation, and
//! answers with JSON constrained to a narrow schema: which fields are boilerplate, and whether
//! the template is routine noise. The answer becomes an ordinary [`sluice_core::recipe::Recipe`]
//! with AI provenance and goes through the same guardrails and shadow proof as any other: AI
//! proposes, guardrails decide (safety contract rule 6).

mod advisor;
mod error;
mod model;
mod prompt;
mod proposal;
mod redact;

pub use crate::advisor::LlmAdvisor;
pub use crate::error::AiError;
pub use crate::model::{Anthropic, Credential, Http, LanguageModel, OpenAiCompatible, Transport};
