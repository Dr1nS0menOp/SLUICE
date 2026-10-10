//! The guardrails' vocabulary: contract rules, the reasons a proposal is refused or narrowed,
//! and the effective recipe that may be enforced.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::{RuleId, TemplateId};
use crate::predicate::Predicate;
use crate::recipe::Level;
use crate::rules::RuleRequirements;
use crate::template::Template;

/// The rules of the safety contract, as numbered in the README.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractRule {
    /// 1. Unknown data passes through untouched.
    UnknownPassesThrough,
    /// 2. Everything is archived at full fidelity before any cut.
    ArchiveFirst,
    /// 3. Anything a rule could match is forwarded in full.
    RuleMatchesForwarded,
    /// 4. Rare is never cut.
    RareNeverCut,
    /// 5. Every cut is proven before it is enforced.
    ProvenBeforeEnforced,
    /// 6. AI proposes; guardrails decide.
    AiProposesGuardrailsDecide,
}

impl ContractRule {
    /// The rule's number in the README.
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Self::UnknownPassesThrough => 1,
            Self::ArchiveFirst => 2,
            Self::RuleMatchesForwarded => 3,
            Self::RareNeverCut => 4,
            Self::ProvenBeforeEnforced => 5,
            Self::AiProposesGuardrailsDecide => 6,
        }
    }
}

impl fmt::Display for ContractRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::UnknownPassesThrough => "unknown data passes through untouched",
            Self::ArchiveFirst => "everything is archived before any cut",
            Self::RuleMatchesForwarded => "anything a rule could match is forwarded in full",
            Self::RareNeverCut => "rare is never cut",
            Self::ProvenBeforeEnforced => "every cut is proven before it is enforced",
            Self::AiProposesGuardrailsDecide => "AI proposes; guardrails decide",
        };
        write!(f, "contract rule {}: {text}", self.number())
    }
}

/// Why a proposal was refused or narrowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Reason {
    /// No recipe exists for the template.
    NoRecipe,
    /// The archive is not enabled, so no cut can be undone.
    NoArchive,
    /// The template is below the rarity floor.
    RareTemplate {
        /// Events of the template in the sample.
        events: u64,
        /// Events of the whole source in the sample.
        source_events: u64,
    },
    /// A rule may read any field, so no field may be removed.
    AllFieldsNeededByRule {
        /// The rule.
        rule: RuleId,
    },
    /// A field proposed for dropping is needed by a rule.
    FieldNeededByRule {
        /// The field that is kept.
        field: FieldPath,
        /// One rule that needs it.
        rule: RuleId,
    },
    /// A field a rule may read is removed only from events the rule's pre-filter rules out:
    /// every event the rule could match is kept whole.
    KeptWhereRuleMayMatch {
        /// The field, or `None` when the rule may read any field.
        field: Option<FieldPath>,
        /// The rule.
        rule: RuleId,
    },
    /// So many rules could read a field that testing them per event would cost more than it
    /// saves, so the field is kept on every event (or every event is forwarded).
    ProtectionTooBroad {
        /// Tests the combined pre-filter would need.
        tests: usize,
    },
    /// A rule's pre-filter cannot be bounded, so every event could match.
    UnboundedRule {
        /// The rule.
        rule: RuleId,
    },
    /// Rules apply to the template, so L3 summarizing is narrowed to rule-guided forwarding.
    SemanticOnCoveredTemplate,
    /// A spot check with the SIEM's own rules (such as Wazuh `logtest`) found a different result
    /// on a reduced event, so the recipe was rolled back.
    StatelessRulesChanged,
    /// The shadow proof found different alerts on forwarded data, so the recipe was rolled back.
    DetectionChanged {
        /// Alerts raised on full data but not on forwarded data.
        missing: usize,
        /// Alerts raised only on forwarded data.
        extra: usize,
    },
}

/// One refusal or narrowing of a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adjustment {
    /// The contract rule that required it.
    pub contract: ContractRule,
    /// The level of the affected proposal, if any.
    pub level: Option<Level>,
    /// Why.
    #[serde(flatten)]
    pub reason: Reason,
}

/// Which events of a template are forwarded in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case")]
pub enum Route {
    /// Every event is forwarded.
    ForwardAll,
    /// Events matching `prefilter` are forwarded. The rest are summarized by `summary_keys`.
    ForwardMatching {
        /// Superset of the events any applicable rule could match.
        prefilter: Predicate,
        /// Fields that key the summaries.
        summary_keys: Vec<FieldPath>,
    },
}

/// What may be enforced for one template, after the guardrails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveRecipe {
    /// Template this applies to.
    pub template: TemplateId,
    /// Fields removed from every forwarded event.
    pub drop_fields: BTreeSet<FieldPath>,
    /// If set, null and empty-string fields are removed, except these.
    pub drop_empty_except: Option<BTreeSet<FieldPath>>,
    /// If set, field removal (both kinds above) skips events matching this predicate: they are
    /// events a protecting rule could match, so they are forwarded whole (contract rule 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_whole_when: Option<Predicate>,
    /// Which events are forwarded in full.
    pub route: Route,
    /// Every proposal the guardrails refused or narrowed, and why.
    pub adjustments: Vec<Adjustment>,
}

impl EffectiveRecipe {
    /// Forward everything unchanged.
    #[must_use]
    pub fn passthrough(template: TemplateId) -> Self {
        Self {
            template,
            drop_fields: BTreeSet::new(),
            drop_empty_except: None,
            keep_whole_when: None,
            route: Route::ForwardAll,
            adjustments: Vec::new(),
        }
    }

    /// Whether this recipe changes anything at all.
    #[must_use]
    pub fn is_passthrough(&self) -> bool {
        self.drop_fields.is_empty()
            && self.drop_empty_except.is_none()
            && self.route == Route::ForwardAll
    }
}

/// Thresholds for the guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardrailConfig {
    /// A template needs at least this many events in the sample to be cut.
    pub rarity_min_events: u64,
    /// A template needs at least this share of its source, in parts per million, to be cut.
    pub rarity_min_share_ppm: u64,
}

impl Default for GuardrailConfig {
    fn default() -> Self {
        Self {
            rarity_min_events: 100,
            rarity_min_share_ppm: 1_000, // 0.1 %
        }
    }
}

impl GuardrailConfig {
    /// Whether `template` is below the rarity floor.
    #[must_use]
    pub fn is_rare(&self, template: &Template) -> bool {
        let stats = template.stats;
        let share_too_small = u128::from(stats.events) * 1_000_000
            < u128::from(self.rarity_min_share_ppm) * u128::from(stats.source_events);
        stats.events < self.rarity_min_events || share_too_small
    }
}

/// Everything the guardrails need besides the recipe and template.
#[derive(Debug, Clone, Copy)]
pub struct GuardContext<'a> {
    /// Requirements of every loaded rule, across all engines.
    pub rules: &'a [RuleRequirements],
    /// Guardrail thresholds.
    pub config: GuardrailConfig,
    /// Whether full-fidelity archiving runs before reductions.
    pub archive_enabled: bool,
}
