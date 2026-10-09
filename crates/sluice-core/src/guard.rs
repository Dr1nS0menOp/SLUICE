//! The safety contract, enforced.
//!
//! [`guard`] is the only way to get an [`EffectiveRecipe`]. It takes a proposed [`Recipe`] (or
//! none), the template it targets, and the requirements of every loaded rule. It returns what may
//! actually be enforced, plus an [`Adjustment`] for every proposal it refused or narrowed, each
//! tied to the contract rule that required it.
//!
//! Every decision here fails closed. When something is unknown, the event is forwarded in full.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::{RuleId, TemplateId};
use crate::predicate::Predicate;
use crate::recipe::{Level, Recipe, Reduction};
use crate::rules::{RequiredFields, RuleRequirements};
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

/// Turns a proposal into what may be enforced.
///
/// `recipe` is `None` when no recipe is known for the template. Such templates pass through
/// untouched.
///
/// The result is not yet proven. Contract rule 5 is enforced by the shadow proof, which must pass
/// before an [`EffectiveRecipe`] is enforced.
#[must_use]
pub fn guard(
    template: &Template,
    recipe: Option<&Recipe>,
    ctx: GuardContext<'_>,
) -> EffectiveRecipe {
    let mut effective = EffectiveRecipe::passthrough(template.id.clone());

    let Some(recipe) = recipe else {
        effective.adjustments.push(Adjustment {
            contract: ContractRule::UnknownPassesThrough,
            level: None,
            reason: Reason::NoRecipe,
        });
        return effective;
    };

    if let Some((contract, reason)) = refuse_all(template, ctx) {
        effective
            .adjustments
            .extend(recipe.reductions().iter().map(|r| Adjustment {
                contract,
                level: Some(r.level()),
                reason: reason.clone(),
            }));
        return effective;
    }

    let applicable: Vec<&RuleRequirements> = ctx
        .rules
        .iter()
        .filter(|rule| rule.logsource.may_apply_to(&template.logsource))
        .collect();
    let protection = Protection::of(template, &applicable);

    for reduction in recipe.reductions() {
        match reduction {
            Reduction::DropFields { fields } => {
                effective
                    .drop_fields
                    .extend(protection.allowed_drops(fields, &mut effective.adjustments));
            }
            Reduction::DropEmptyFields => {
                effective.drop_empty_except =
                    protection.drop_empty_exceptions(&mut effective.adjustments);
            }
            Reduction::ForwardMatching { summary_keys } => {
                effective.route = rule_guided_route(
                    &applicable,
                    summary_keys,
                    Level::RuleGuided,
                    &mut effective.adjustments,
                );
            }
            Reduction::Summarize { summary_keys } => {
                if !applicable.is_empty() {
                    effective.adjustments.push(Adjustment {
                        contract: ContractRule::RuleMatchesForwarded,
                        level: Some(Level::Semantic),
                        reason: Reason::SemanticOnCoveredTemplate,
                    });
                }
                effective.route = rule_guided_route(
                    &applicable,
                    summary_keys,
                    Level::Semantic,
                    &mut effective.adjustments,
                );
            }
        }
    }

    effective
}

/// Reasons that refuse every reduction for a template, regardless of rules.
fn refuse_all(template: &Template, ctx: GuardContext<'_>) -> Option<(ContractRule, Reason)> {
    if !ctx.archive_enabled {
        return Some((ContractRule::ArchiveFirst, Reason::NoArchive));
    }
    if ctx.config.is_rare(template) {
        let reason = Reason::RareTemplate {
            events: template.stats.events,
            source_events: template.stats.source_events,
        };
        return Some((ContractRule::RareNeverCut, reason));
    }
    None
}

/// The fields applicable rules need, for deciding which field-level reductions may run.
struct Protection {
    /// Fields that must survive, each paired with one rule that needs it.
    fields: Vec<(FieldPath, RuleId)>,
    /// Set when some rule may read any field. No field may then be removed.
    all_fields_for: Option<RuleId>,
}

impl Protection {
    fn of(template: &Template, applicable: &[&RuleRequirements]) -> Self {
        let mut fields: Vec<(FieldPath, RuleId)> = Vec::new();
        let mut all_fields_for = None;
        for rule in applicable {
            match &rule.fields {
                RequiredFields::Known(known) => {
                    fields.extend(known.iter().map(|f| (f.clone(), rule.rule.clone())));
                }
                RequiredFields::Unknown => {
                    all_fields_for.get_or_insert_with(|| rule.rule.clone());
                }
            }
            if rule.matches_raw_text {
                let text = template.text_fields.iter();
                fields.extend(text.map(|f| (f.clone(), rule.rule.clone())));
            }
        }
        fields.sort();
        fields.dedup_by(|a, b| a.0 == b.0);
        Self {
            fields,
            all_fields_for,
        }
    }

    fn refuse_all_fields(&self, adjustments: &mut Vec<Adjustment>) -> bool {
        let Some(rule) = &self.all_fields_for else {
            return false;
        };
        adjustments.push(Adjustment {
            contract: ContractRule::RuleMatchesForwarded,
            level: Some(Level::Lossless),
            reason: Reason::AllFieldsNeededByRule { rule: rule.clone() },
        });
        true
    }

    /// Fields exempt from empty-field removal, or `None` if empty-field removal is refused.
    fn drop_empty_exceptions(
        &self,
        adjustments: &mut Vec<Adjustment>,
    ) -> Option<BTreeSet<FieldPath>> {
        if self.refuse_all_fields(adjustments) {
            return None;
        }
        Some(self.fields.iter().map(|(field, _)| field.clone()).collect())
    }

    /// The subset of `proposed` that no rule needs. A drop is refused when the dropped field is
    /// the protected field, its parent, or its child: dropping a parent removes the child, and a
    /// rule that tests a parent object sees its children.
    fn allowed_drops(
        &self,
        proposed: &BTreeSet<FieldPath>,
        adjustments: &mut Vec<Adjustment>,
    ) -> BTreeSet<FieldPath> {
        if self.refuse_all_fields(adjustments) {
            return BTreeSet::new();
        }
        proposed
            .iter()
            .filter(|field| !self.refuse_drop(field, adjustments))
            .cloned()
            .collect()
    }

    fn refuse_drop(&self, field: &FieldPath, adjustments: &mut Vec<Adjustment>) -> bool {
        let conflict = self
            .fields
            .iter()
            .find(|(kept, _)| field.covers(kept) || kept.covers(field));
        let Some((_, rule)) = conflict else {
            return false;
        };
        adjustments.push(Adjustment {
            contract: ContractRule::RuleMatchesForwarded,
            level: Some(Level::Lossless),
            reason: Reason::FieldNeededByRule {
                field: field.clone(),
                rule: rule.clone(),
            },
        });
        true
    }
}

/// Route for L2 and L3: forward the union of what applicable rules could match.
///
/// With no applicable rule, the union is empty and every event goes to summaries. That is
/// exactly L3. Any unbounded rule forces `ForwardAll`.
///
/// Stateful rules need no special case here (ADR 0004): a correlation or frequency rule counts
/// only events its own conditions match, every such event is inside its pre-filter, and the
/// route forwards all of them unchanged and in order.
fn rule_guided_route(
    applicable: &[&RuleRequirements],
    summary_keys: &[FieldPath],
    level: Level,
    adjustments: &mut Vec<Adjustment>,
) -> Route {
    if let Some(rule) = applicable.iter().find(|rule| rule.prefilter.is_always()) {
        adjustments.push(Adjustment {
            contract: ContractRule::RuleMatchesForwarded,
            level: Some(level),
            reason: Reason::UnboundedRule {
                rule: rule.rule.clone(),
            },
        });
        return Route::ForwardAll;
    }
    Route::ForwardMatching {
        prefilter: Predicate::any(applicable.iter().map(|rule| rule.prefilter.clone())),
        summary_keys: summary_keys.to_vec(),
    }
}

#[cfg(test)]
mod tests;
