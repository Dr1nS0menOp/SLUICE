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
use crate::schema::Schema;
use crate::template::Template;

/// The rules of the safety contract, as numbered in the README.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractRule {
    /// 1. Unknown data passes through untouched.
    UnknownPassesThrough,
    /// 2. Everything is archived at full fidelity before any saving.
    ArchiveFirst,
    /// 3. Anything a rule could match is forwarded in full.
    RuleMatchesForwarded,
    /// 4. Rare is never cut.
    RareNeverCut,
    /// 5. Every saving is proven before it is proposed, and what runs is re-checked.
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
            Self::ArchiveFirst => "everything is archived before any saving",
            Self::RuleMatchesForwarded => "anything a rule could match is sent in full",
            Self::RareNeverCut => "rare is never cut",
            Self::ProvenBeforeEnforced => "every saving is proven before it is used",
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
    /// A rule's field names follow another convention than the records', and no mapping between
    /// them is known, so the rule is read as reading any field of any event of its log source.
    FieldNamesDiffer {
        /// The first such rule.
        rule: RuleId,
        /// How many applicable rules are read this way.
        rules: usize,
        /// The convention the rule's field names are written in.
        rule_names: Schema,
        /// The convention the records follow (`undeclared` when the source does not say).
        data_names: Schema,
    },
    /// A rule tests fields that a text line only has once the SIEM has parsed it, so the rule
    /// may match any line of its log source, and the line is kept whole on every event.
    FieldsParsedFromText {
        /// The first such rule.
        rule: RuleId,
        /// How many applicable rules are read this way.
        rules: usize,
    },
    /// The rules are not known to be every rule the destination runs (no inventory from the
    /// SIEM, no claim by the operator), so nothing is summarized: a rule Sluice was not given
    /// could match what would not be forwarded (ADR 0021). Lossless cuts still apply.
    RulesNotComplete,
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
        self.is_rare_count(template.stats.events, template.stats.source_events)
    }

    /// Whether `events` out of `source_events` is below the rarity floor. Discovery uses it to
    /// keep a rare variant of a frequent kind of event in a template of its own.
    #[must_use]
    pub fn is_rare_count(&self, events: u64, source_events: u64) -> bool {
        let share_too_small = u128::from(events) * 1_000_000
            < u128::from(self.rarity_min_share_ppm) * u128::from(source_events);
        events < self.rarity_min_events || share_too_small
    }

    /// Whether `template` is too close to the rarity floor for a new recipe to start: below
    /// [`ENTRY_MARGIN_PERCENT`] of either threshold. A template hovering at the floor would
    /// otherwise start and stop its recipe every few cycles. The margin only delays cutting, so
    /// it is always safe.
    #[must_use]
    pub fn is_near_rare(&self, template: &Template) -> bool {
        let raised = Self {
            rarity_min_events: self.rarity_min_events * ENTRY_MARGIN_PERCENT / 100,
            rarity_min_share_ppm: self.rarity_min_share_ppm * ENTRY_MARGIN_PERCENT / 100,
        };
        raised.is_rare(template)
    }
}

/// How far above the rarity floor, in percent of it, a template must be for a new recipe to
/// enter shadow.
pub const ENTRY_MARGIN_PERCENT: u64 = 125;

/// Everything the guardrails need besides the recipe and template.
#[derive(Debug, Clone, Copy)]
pub struct GuardContext<'a> {
    /// Requirements of every loaded rule, across all engines.
    pub rules: &'a [RuleRequirements],
    /// Guardrail thresholds.
    pub config: GuardrailConfig,
    /// Whether full-fidelity archiving runs before reductions.
    pub archive_enabled: bool,
    /// Whether `rules` are every rule and query the destination runs: fetched from the SIEM or
    /// claimed by the operator (ADR 0021). Without it, only lossless cuts are allowed.
    pub rules_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{LineHeader, TemplateShape, TemplateStats};

    fn template(events: u64, source_events: u64) -> Template {
        Template {
            id: "t".into(),
            source: "s".into(),
            logsource: crate::logsource::LogSource::default(),
            schema: Schema::Sigma,
            pattern: String::new(),
            shape: TemplateShape::Text {
                field: "message".into(),
                header: LineHeader::None,
                tokens: Vec::new(),
            },
            fields: BTreeSet::new(),
            text_fields: BTreeSet::new(),
            stats: TemplateStats {
                events,
                bytes: 0,
                source_events,
            },
        }
    }

    #[test]
    fn c4_the_event_floor_is_100_events() {
        let config = GuardrailConfig::default();
        assert!(config.is_rare_count(99, 99));
        assert!(!config.is_rare_count(100, 100));
    }

    #[test]
    fn c4_the_share_floor_is_one_in_a_thousand_inclusive() {
        let config = GuardrailConfig::default();
        assert!(
            !config.is_rare_count(100, 100_000),
            "exactly 0.1 % is not rare"
        );
        assert!(config.is_rare_count(100, 100_001));
        assert!(!config.is_rare_count(1_000, 1_000_000));
    }

    #[test]
    fn c4_an_empty_source_and_huge_counts_do_not_overflow() {
        let config = GuardrailConfig::default();
        assert!(config.is_rare_count(0, 0));
        assert!(!config.is_rare_count(u64::MAX, u64::MAX));
        assert!(config.is_rare_count(100, u64::MAX));
    }

    #[test]
    fn c4_zero_thresholds_make_nothing_rare() {
        let config = GuardrailConfig {
            rarity_min_events: 0,
            rarity_min_share_ppm: 0,
        };
        assert!(!config.is_rare_count(0, 1_000));
    }

    #[test]
    fn c4_is_rare_reads_the_templates_counts() {
        let config = GuardrailConfig::default();
        assert!(config.is_rare(&template(99, 1_000)));
        assert!(!config.is_rare(&template(100, 1_000)));
    }

    #[test]
    fn c4_a_new_recipe_needs_a_quarter_above_the_floor() {
        let config = GuardrailConfig::default();
        assert!(config.is_near_rare(&template(124, 124)));
        assert!(!config.is_near_rare(&template(125, 125)));
        // 0.125 % of the source is the raised share floor.
        assert!(config.is_near_rare(&template(1_000, 800_001)));
        assert!(!config.is_near_rare(&template(1_000, 800_000)));
    }

    #[test]
    fn contract_rules_are_numbered_one_to_six_in_order() {
        let rules = [
            ContractRule::UnknownPassesThrough,
            ContractRule::ArchiveFirst,
            ContractRule::RuleMatchesForwarded,
            ContractRule::RareNeverCut,
            ContractRule::ProvenBeforeEnforced,
            ContractRule::AiProposesGuardrailsDecide,
        ];
        for (rule, number) in rules.iter().zip(1u8..) {
            assert_eq!(rule.number(), number);
            assert!(
                rule.to_string()
                    .starts_with(&format!("contract rule {number}: "))
            );
        }
    }

    #[test]
    fn a_passthrough_recipe_changes_nothing_and_any_reduction_changes_it() {
        let passthrough = EffectiveRecipe::passthrough("t".into());
        assert!(passthrough.is_passthrough());
        assert_eq!(passthrough.route, Route::ForwardAll);
        let mut empty_drop = passthrough.clone();
        empty_drop.drop_empty_except = Some(BTreeSet::new());
        assert!(!empty_drop.is_passthrough());
        let mut dropping = passthrough.clone();
        dropping.drop_fields.insert("Message".into());
        assert!(!dropping.is_passthrough());
        let mut routing = passthrough.clone();
        routing.route = Route::ForwardMatching {
            prefilter: Predicate::never(),
            summary_keys: vec![],
        };
        assert!(!routing.is_passthrough());
        let mut conditional = passthrough;
        conditional.keep_whole_when = Some(Predicate::Always);
        assert!(
            conditional.is_passthrough(),
            "a condition with nothing to keep from changes nothing"
        );
    }

    #[test]
    fn adjustments_serialize_their_reason_inline() {
        let adjustment = Adjustment {
            contract: ContractRule::RareNeverCut,
            level: Some(Level::Lossless),
            reason: Reason::RareTemplate {
                events: 3,
                source_events: 9,
            },
        };
        let json = serde_json::to_value(&adjustment).unwrap();
        assert_eq!(json["reason"], "rare_template");
        assert_eq!(json["events"], 3);
        assert_eq!(json["contract"], "rare_never_cut");
        let back: Adjustment = serde_json::from_value(json).unwrap();
        assert_eq!(back, adjustment);
    }

    #[test]
    fn an_effective_recipe_without_a_condition_omits_it_in_json() {
        let json = serde_json::to_value(EffectiveRecipe::passthrough("t".into())).unwrap();
        assert!(json.get("keep_whole_when").is_none());
        assert_eq!(json["route"]["route"], "forward_all");
    }
}
