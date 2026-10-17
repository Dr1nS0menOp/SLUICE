//! The safety contract, enforced.
//!
//! [`guard`] is the only way to get an [`EffectiveRecipe`]. It takes a proposed [`Recipe`] (or
//! none), the template it targets, and the requirements of every loaded rule. It returns what may
//! actually be enforced, plus an [`Adjustment`] for every proposal it refused or narrowed, each
//! tied to the contract rule that required it.
//!
//! Every decision here fails closed. When something is unknown, the event is forwarded in full.

use std::collections::BTreeSet;

use crate::field::FieldPath;
use crate::ids::RuleId;
use crate::predicate::Predicate;
use crate::recipe::{Level, Recipe, Reduction};
use crate::rules::RuleRequirements;

mod model;
mod protection;

use crate::template::{Template, TemplateShape};
pub use model::{
    Adjustment, ContractRule, EffectiveRecipe, GuardContext, GuardrailConfig, Reason, Route,
};
use protection::Protection;

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

    // A rule whose field names cannot be compared with the template's is read as widely as can
    // be (ADR 0018): its pre-filter and field list say nothing about records named otherwise.
    // Widened rules protect identically, so the first one stands for all of them. A rule that
    // also comes mapped onto the template's convention (ADR 0020) is covered by that copy.
    let mapped: BTreeSet<&RuleId> = ctx
        .rules
        .iter()
        .filter(|rule| {
            matches!(template.shape, TemplateShape::Keyset { .. })
                && rule
                    .field_names
                    .is_some_and(|n| template.schema.can_read(n))
        })
        .map(|rule| &rule.rule)
        .collect();
    let renamed_rules: Vec<&RuleRequirements> = ctx
        .rules
        .iter()
        .filter(|rule| {
            renamed(rule, template) && !mapped.contains(&rule.rule) && applies(rule, template)
        })
        .collect();
    let widened: Option<RuleRequirements> = renamed_rules.first().map(|r| r.widened());
    let applicable: Vec<&RuleRequirements> = ctx
        .rules
        .iter()
        .filter(|rule| !renamed(rule, template) && applies(rule, template))
        .chain(&widened)
        .collect();
    let (mut shaped, conditions) = shape(template, recipe, &applicable, true, ctx.rules_complete);
    let keep = Predicate::any(conditions);
    if keep.tests() > MAX_DATA_PLANE_TESTS {
        // Too many rules could read the fields to test them per event: keep them everywhere.
        (shaped, _) = shape(template, recipe, &applicable, false, ctx.rules_complete);
        shaped.adjustments.push(Adjustment {
            contract: ContractRule::RuleMatchesForwarded,
            level: Some(Level::Lossless),
            reason: Reason::ProtectionTooBroad {
                tests: keep.tests(),
            },
        });
    } else if !shaped.drop_fields.is_empty() || shaped.drop_empty_except.is_some() {
        shaped.keep_whole_when = (!keep.is_never()).then_some(keep);
    }
    // One adjustment for all of them: SigmaHQ alone can put hundreds on one template. A rule
    // and its mapped copies count once.
    let rules = renamed_rules
        .iter()
        .map(|rule| &rule.rule)
        .collect::<BTreeSet<_>>()
        .len();
    if let Some((first, rule_names)) = renamed_rules
        .first()
        .and_then(|rule| rule.field_names.map(|names| (rule, names)))
    {
        let reason = match template.shape {
            TemplateShape::Text { .. } => Reason::FieldsParsedFromText {
                rule: first.rule.clone(),
                rules,
            },
            TemplateShape::Keyset { .. } => Reason::FieldNamesDiffer {
                rule: first.rule.clone(),
                rules,
                rule_names,
                data_names: template.schema,
            },
        };
        shaped.adjustments.push(Adjustment {
            contract: ContractRule::RuleMatchesForwarded,
            level: None,
            reason,
        });
    }
    dedup(&mut shaped.adjustments);
    shaped
}

/// The most predicate tests the data plane evaluates per event for one template. Beyond this,
/// a conditional protection or a rule-guided route falls back to the fail-closed choice (keep
/// the fields, forward everything): a union over thousands of rules would cost more per event
/// than it saves, and its VRL would be slow to compile.
const MAX_DATA_PLANE_TESTS: usize = 256;

/// Applies `recipe`'s reductions within what `applicable` rules allow. With `conditional`,
/// fields claimed by selective rules are dropped outside those rules' pre-filters, which are
/// returned; without, every claim holds on every event. Without `rules_complete`, reductions
/// that decide which events are forwarded are refused (ADR 0021).
fn shape(
    template: &Template,
    recipe: &Recipe,
    applicable: &[&RuleRequirements],
    conditional: bool,
    rules_complete: bool,
) -> (EffectiveRecipe, Vec<Predicate>) {
    let mut effective = EffectiveRecipe::passthrough(template.id.clone());
    let protection = Protection::of(template, applicable, conditional);
    let mut conditions: Vec<Predicate> = Vec::new();

    for reduction in recipe.reductions() {
        if reduction.is_routing() && !rules_complete {
            // A rule Sluice was not given could match any event it would not forward.
            effective.adjustments.push(Adjustment {
                contract: ContractRule::RuleMatchesForwarded,
                level: Some(reduction.level()),
                reason: Reason::RulesNotComplete,
            });
            continue;
        }
        match reduction {
            Reduction::DropFields { fields } => {
                effective.drop_fields.extend(protection.allowed_drops(
                    fields,
                    &mut effective.adjustments,
                    &mut conditions,
                ));
            }
            Reduction::DropEmptyFields => {
                effective.drop_empty_except =
                    protection.drop_empty_exceptions(&mut effective.adjustments, &mut conditions);
            }
            Reduction::ForwardMatching { summary_keys } => {
                effective.route = rule_guided_route(
                    applicable,
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
                    applicable,
                    summary_keys,
                    Level::Semantic,
                    &mut effective.adjustments,
                );
            }
        }
    }
    (effective, conditions)
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

/// Removes repeated adjustments (one per field and rule) while keeping their order.
fn dedup(adjustments: &mut Vec<Adjustment>) {
    let mut seen: Vec<Adjustment> = Vec::with_capacity(adjustments.len());
    adjustments.retain(|a| {
        if seen.contains(a) {
            false
        } else {
            seen.push(a.clone());
            true
        }
    });
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
    let prefilter = Predicate::any(applicable.iter().map(|rule| rule.prefilter.clone()));
    if prefilter.tests() > MAX_DATA_PLANE_TESTS {
        adjustments.push(Adjustment {
            contract: ContractRule::RuleMatchesForwarded,
            level: Some(level),
            reason: Reason::ProtectionTooBroad {
                tests: prefilter.tests(),
            },
        });
        return Route::ForwardAll;
    }
    Route::ForwardMatching {
        prefilter,
        summary_keys: summary_keys.to_vec(),
    }
}

/// Whether `rule` can see events of `template`: its log source may apply, and its pre-filter is
/// not ruled out by the template's fixed discriminator values. A rule that requires
/// `EventID: 5805` reads nothing of an `EventID=7036` template, even if it also has keywords.
/// A rule that only sees text lines reads nothing of a JSON template. A rule whose field names
/// cannot be compared with the template's ([`renamed`]) is not ruled out by them: its pre-filter
/// names fields the template may carry under other names.
fn applies(rule: &RuleRequirements, template: &Template) -> bool {
    let (fixed, paths): (&[(FieldPath, String)], _) = match &template.shape {
        TemplateShape::Keyset { .. } if rule.text_lines_only => return false,
        TemplateShape::Keyset {
            discriminators,
            paths,
            ..
        } => (discriminators, Some(paths)),
        TemplateShape::Text { .. } => (&[], None),
    };
    rule.logsource.may_apply_to(&template.logsource)
        && (renamed(rule, template) || rule.prefilter.may_match_with(fixed, paths))
}

/// Whether the fields `rule` tests cannot be compared with `template`'s records. On a JSON key
/// set: the rule names its fields in a convention the records do not follow (ADR 0018). On a
/// text line: the rule tests named fields at all, which exist only once the SIEM has parsed
/// the line (ADR 0020); keyword rules search the line itself and are compared as they are.
fn renamed(rule: &RuleRequirements, template: &Template) -> bool {
    match template.shape {
        TemplateShape::Keyset { .. } => rule
            .field_names
            .is_some_and(|names| !template.schema.can_read(names)),
        TemplateShape::Text { .. } => rule.field_names.is_some() && rule.prefilter.names_fields(),
    }
}
#[cfg(test)]
mod tests;
