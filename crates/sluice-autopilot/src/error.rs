//! Errors of the autopilot.

use sluice_core::proof::ProofError;
use sluice_rules::RulesError;
use sluice_vector::VectorError;

/// The autopilot could not complete an analysis.
#[derive(Debug, thiserror::Error)]
pub enum AutopilotError {
    /// A recipe file is invalid.
    #[error("invalid recipe {path}: {why}")]
    Recipe {
        /// Where the recipe came from.
        path: String,
        /// What is wrong with it.
        why: String,
    },
    /// Rules could not be loaded or compiled.
    #[error(transparent)]
    Rules(#[from] RulesError),
    /// The data plane could not be generated.
    #[error(transparent)]
    Vector(#[from] VectorError),
    /// The shadow proof could not be carried out.
    #[error(transparent)]
    Proof(#[from] ProofError),
}
