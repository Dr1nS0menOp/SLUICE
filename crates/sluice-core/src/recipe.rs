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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Reduction {
    /// L1: drop fields that duplicate other fields or carry boilerplate.
    DropFields {
        /// Fields to drop.
        fields: BTreeSet<FieldPath>,
    },
    /// L1: drop fields whose value is `null` or an empty string.
    DropEmptyFields,
    /// L1: drop a field while it holds the value the kind of event, or another field of the
    /// event, implies. A removed value can be put back exactly from `values`, so nothing is
    /// lost; any other value is kept.
    DropImplied {
        /// The implied values.
        values: Vec<ImpliedValue>,
    },
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
            Self::DropFields { .. } | Self::DropEmptyFields | Self::DropImplied { .. } => {
                Level::Lossless
            }
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

/// A scalar value as an event carries it. Integers and strings compare exactly, so a value
/// guard never mistakes `0` for `"0"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum Literal {
    /// `true` or `false`.
    Bool(bool),
    /// A whole number that fits in 64 bits.
    Integer(i64),
    /// A string.
    Text(String),
}

impl Literal {
    /// The literal a JSON value is, if it is a boolean, a 64-bit integer or a string.
    #[must_use]
    pub fn of(value: &serde_json::Value) -> Option<Self> {
        match value {
            serde_json::Value::Bool(b) => Some(Self::Bool(*b)),
            serde_json::Value::Number(n) => n.as_i64().map(Self::Integer),
            serde_json::Value::String(s) => Some(Self::Text(s.clone())),
            _ => None,
        }
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Integer(i) => write!(f, "{i}"),
            Self::Text(s) => write!(f, "{s:?}"),
        }
    }
}

/// A field's value that is implied: by the kind of event alone, or by another field's value.
/// Removing the field only while it holds `value` (and `when` holds) loses nothing: the absent
/// field means `value`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ImpliedValue {
    /// The field.
    pub field: FieldPath,
    /// The value it holds when implied.
    pub value: Literal,
    /// The field and value that imply it; `None` when the kind of event alone does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<(FieldPath, Literal)>,
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
    /// Values Sluice learned from the sample to be implied (see [`Reduction::DropImplied`]).
    Learned,
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

    fn drop_fields() -> Reduction {
        Reduction::DropFields {
            fields: ["Message".into()].into(),
        }
    }

    #[test]
    fn each_reduction_has_its_level_and_only_two_route() {
        let forward = Reduction::ForwardMatching {
            summary_keys: keys(),
        };
        let summarize = Reduction::Summarize {
            summary_keys: keys(),
        };
        assert_eq!(drop_fields().level(), Level::Lossless);
        assert_eq!(Reduction::DropEmptyFields.level(), Level::Lossless);
        assert_eq!(forward.level(), Level::RuleGuided);
        assert_eq!(summarize.level(), Level::Semantic);
        assert!(!drop_fields().is_routing() && !Reduction::DropEmptyFields.is_routing());
        assert!(forward.is_routing() && summarize.is_routing());
    }

    #[test]
    fn rejects_rule_guided_forwarding_without_keys() {
        let err = Recipe::new(
            "t".into(),
            vec![Reduction::ForwardMatching {
                summary_keys: vec![],
            }],
            Provenance::Operator,
            "",
        )
        .unwrap_err();
        assert!(matches!(err, RecipeError::EmptySummaryKeys { .. }));
    }

    #[test]
    fn accepts_lossless_reductions_with_one_route_and_keeps_everything_given() {
        let recipe = Recipe::new(
            "win-4624".into(),
            vec![
                drop_fields(),
                Reduction::DropEmptyFields,
                Reduction::ForwardMatching {
                    summary_keys: keys(),
                },
            ],
            Provenance::Ai { model: "m".into() },
            "boilerplate",
        )
        .unwrap();
        assert_eq!(recipe.template().as_str(), "win-4624");
        assert_eq!(recipe.reductions().len(), 3);
        assert_eq!(recipe.provenance(), &Provenance::Ai { model: "m".into() });
        assert_eq!(recipe.rationale(), "boilerplate");
    }

    #[test]
    fn a_recipe_with_no_reductions_is_valid_and_changes_nothing() {
        let recipe = Recipe::new("t".into(), vec![], Provenance::Operator, "").unwrap();
        assert_eq!(recipe.reductions().len(), 0);
    }

    #[test]
    fn three_routes_are_counted_in_the_error() {
        let route = || Reduction::Summarize {
            summary_keys: keys(),
        };
        let err = Recipe::new(
            "t".into(),
            vec![route(), route(), route()],
            Provenance::Operator,
            "",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RecipeError::ConflictingRouting { count: 3, .. }
        ));
        assert!(err.to_string().contains("3 routing reductions"));
    }

    #[test]
    fn levels_display_their_names() {
        assert_eq!(Level::Lossless.to_string(), "L1 lossless");
        assert_eq!(Level::RuleGuided.to_string(), "L2 rule-guided");
        assert_eq!(Level::Semantic.to_string(), "L3 semantic");
    }

    #[test]
    fn reductions_and_provenance_serialize_with_their_tags() {
        let json = serde_json::to_value(drop_fields()).unwrap();
        assert_eq!(json["op"], "drop_fields");
        let json = serde_json::to_value(Provenance::Community {
            recipe: "a/b".into(),
        })
        .unwrap();
        assert_eq!(json["kind"], "community");
    }

    #[test]
    fn levels_are_ordered_safest_first() {
        assert!(Level::Lossless < Level::RuleGuided && Level::RuleGuided < Level::Semantic);
    }
}
