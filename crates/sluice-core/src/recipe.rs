//! Proposed reductions for a template.
//!
//! A [`Recipe`] is a *proposal*, whether it comes from a community recipe file, the local cache
//! or an AI model. Nothing in a recipe is trusted: [`crate::guard`] turns it into an
//! [`crate::guard::EffectiveRecipe`], and only that is ever enforced.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::TemplateId;

/// The three reduction levels, from safest to most aggressive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// L1: remove format fat. Every forwarded event keeps all information a rule can use.
    Lossless,
    /// L2: forward in full only what a rule could match. Summarize the rest.
    RuleGuided,
    /// L3: summarize a template no rule covers.
    Semantic,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Lossless => "L1 lossless",
            Self::RuleGuided => "L2 rule-guided",
            Self::Semantic => "L3 semantic",
        })
    }
}

/// One proposed reduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Reduction {
    /// L1: drop fields that duplicate other fields or carry boilerplate.
    DropFields {
        /// Fields to drop.
        fields: BTreeSet<FieldPath>,
    },
    /// L1: drop fields whose value is `null` or an empty string.
    DropEmptyFields,
    /// L2: forward events a rule could match. The rest go to summaries keyed by `summary_keys`.
    ForwardMatching {
        /// Fields that key the summaries of events that are not forwarded.
        summary_keys: Vec<FieldPath>,
    },
    /// L3: send only summaries keyed by `summary_keys`. Full events stay in the archive.
    Summarize {
        /// Fields that key the summaries.
        summary_keys: Vec<FieldPath>,
    },
}

impl Reduction {
    /// The level this reduction belongs to.
    #[must_use]
    pub fn level(&self) -> Level {
        match self {
            Self::DropFields { .. } | Self::DropEmptyFields => Level::Lossless,
            Self::ForwardMatching { .. } => Level::RuleGuided,
            Self::Summarize { .. } => Level::Semantic,
        }
    }

    /// Whether this reduction decides which events are forwarded (as opposed to shaping them).
    #[must_use]
    pub fn is_routing(&self) -> bool {
        matches!(self, Self::ForwardMatching { .. } | Self::Summarize { .. })
    }
}

/// Where a recipe came from. Provenance is reported but never grants extra trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// A community recipe shipped with Sluice, identified by its path in the recipe tree.
    Community {
        /// Recipe path, such as `microsoft/windows/security/4624`.
        recipe: String,
    },
    /// A recipe written by an AI model for this template.
    Ai {
        /// Model identifier, as reported by the provider.
        model: String,
    },
    /// A recipe written by hand by the operator.
    Operator,
}

/// A proposal of reductions for one template.
///
/// Only [`Recipe::new`] constructs one, so every recipe in memory has passed validation. It is
/// deliberately not `Deserialize`, because recipe files are parsed into their own spec type and
/// then validated through `new`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recipe {
    template: TemplateId,
    reductions: Vec<Reduction>,
    provenance: Provenance,
    rationale: String,
}

/// A recipe that is malformed regardless of the data it would apply to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecipeError {
    /// More than one reduction decides routing; their combination has no defined meaning.
    #[error("recipe for {template} has {count} routing reductions; at most one is allowed")]
    ConflictingRouting {
        /// Template the recipe was for.
        template: TemplateId,
        /// Number of routing reductions found.
        count: usize,
    },
    /// A summarizing reduction without keys would collapse every event into one count.
    #[error("recipe for {template} summarizes without summary keys")]
    EmptySummaryKeys {
        /// Template the recipe was for.
        template: TemplateId,
    },
}

impl Recipe {
    /// Validates and builds a recipe.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeError`] if the reductions contradict each other.
    pub fn new(
        template: TemplateId,
        reductions: Vec<Reduction>,
        provenance: Provenance,
        rationale: impl Into<String>,
    ) -> Result<Self, RecipeError> {
        let routing: Vec<&Reduction> = reductions.iter().filter(|r| r.is_routing()).collect();
        if routing.len() > 1 {
            return Err(RecipeError::ConflictingRouting {
                template,
                count: routing.len(),
            });
        }
        if routing.iter().any(|r| match r {
            Reduction::ForwardMatching { summary_keys } | Reduction::Summarize { summary_keys } => {
                summary_keys.is_empty()
            }
            _ => false,
        }) {
            return Err(RecipeError::EmptySummaryKeys { template });
        }
        Ok(Self {
            template,
            reductions,
            provenance,
            rationale: rationale.into(),
        })
    }

    /// Template the recipe is for.
    #[must_use]
    pub fn template(&self) -> &TemplateId {
        &self.template
    }

    /// Proposed reductions.
    #[must_use]
    pub fn reductions(&self) -> &[Reduction] {
        &self.reductions
    }

    /// Where the recipe came from.
    #[must_use]
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Why the author believes these reductions are safe and worthwhile.
    #[must_use]
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Vec<FieldPath> {
        vec!["SourceImage".into()]
    }

    #[test]
    fn rejects_two_routing_reductions() {
        let err = Recipe::new(
            "t".into(),
            vec![
                Reduction::ForwardMatching {
                    summary_keys: keys(),
                },
                Reduction::Summarize {
                    summary_keys: keys(),
                },
            ],
            Provenance::Operator,
            "",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RecipeError::ConflictingRouting { count: 2, .. }
        ));
    }

    #[test]
    fn rejects_summary_without_keys() {
        let err = Recipe::new(
            "t".into(),
            vec![Reduction::Summarize {
                summary_keys: vec![],
            }],
            Provenance::Operator,
            "",
        )
        .unwrap_err();
        assert!(matches!(err, RecipeError::EmptySummaryKeys { .. }));
    }

    #[test]
    fn levels_are_ordered_safest_first() {
        assert!(Level::Lossless < Level::RuleGuided && Level::RuleGuided < Level::Semantic);
    }
}
