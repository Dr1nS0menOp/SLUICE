//! Plain-language descriptions of recipes and guardrail decisions.

use std::collections::BTreeMap;

use sluice_core::field::FieldPath;
use sluice_core::guard::{Adjustment, EffectiveRecipe, Reason, Route};
use sluice_core::logsource::LogSource;
use sluice_core::recipe::{ImpliedValue, Provenance};

pub(crate) fn actions(recipe: &EffectiveRecipe) -> Vec<String> {
    let mut actions = Vec::new();
    if !recipe.drop_fields.is_empty() {
        actions.push(format!("drop {}", list(recipe.drop_fields.iter())));
    }
    if let Some(except) = &recipe.drop_empty_except {
        actions.push(if except.is_empty() {
            "drop null and empty fields".to_owned()
        } else {
            format!(
                "drop null and empty fields, except {} needed by rules",
                except.len()
            )
        });
    }
    if !recipe.drop_implied.is_empty() {
        actions.push(format!(
            "drop values implied by the kind of event or another field (a pipeline tool only, \
             for now): {}",
            implied(&recipe.drop_implied)
        ));
    }
    if let Route::ForwardMatching { summary_keys, .. } = &recipe.route {
        actions.push(format!(
            "forward events a rule could match; summarize the rest by {}",
            list(summary_keys.iter())
        ));
    }
    actions
}

/// The implied values per field: `Keywords`, or `RestrictedAdminMode (when LogonType is 2, 3)`.
pub(crate) fn implied(values: &[ImpliedValue]) -> String {
    let mut fields: BTreeMap<&FieldPath, Vec<&ImpliedValue>> = BTreeMap::new();
    for value in values {
        fields.entry(&value.field).or_default().push(value);
    }
    let described: Vec<String> = fields
        .into_iter()
        .map(|(field, values)| {
            let conditions: BTreeMap<&FieldPath, Vec<String>> = values
                .iter()
                .filter_map(|v| v.when.as_ref())
                .fold(BTreeMap::new(), |mut acc, (on, value)| {
                    acc.entry(on).or_default().push(value.to_string());
                    acc
                });
            if conditions.is_empty() {
                field.to_string()
            } else {
                let when: Vec<String> = conditions
                    .into_iter()
                    .map(|(on, values)| format!("{on} is {}", values.join(", ")))
                    .collect();
                format!("{field} (when {})", when.join("; "))
            }
        })
        .collect();
    described.join(", ")
}

pub(crate) fn adjustment(adjustment: &Adjustment) -> String {
    let what = match &adjustment.reason {
        Reason::NoRecipe => "no recipe: forwarded unchanged".to_owned(),
        Reason::NoArchive => "archiving is off, so nothing is saved".to_owned(),
        Reason::RareTemplate {
            events,
            source_events,
        } => format!(
            "rare ({events} of {source_events} events in its source), so nothing is saved on it"
        ),
        Reason::AllFieldsNeededByRule { rule } => {
            format!("{rule} may read any field, so no field is dropped")
        }
        Reason::FieldNeededByRule { field, rule } => format!("kept {field}: {rule} reads it"),
        Reason::KeptWhereRuleMayMatch { field, rule } => match field {
            Some(field) => format!("{field} kept on events {rule} could match"),
            None => format!("events {rule} could match are kept whole"),
        },
        Reason::ProtectionTooBroad { tests } => {
            format!("kept: {tests} rule tests could apply, too many to check per event")
        }
        Reason::FieldNamesDiffer {
            rule,
            rules,
            rule_names,
            data_names,
        } => {
            let who = match rules {
                1 => format!("{rule} names"),
                n => format!("{n} rules such as {rule} name"),
            };
            format!(
                "{who} fields as {rule_names} does, the records use {data_names}: they may read \
                 any field, so nothing they could read is removed"
            )
        }
        Reason::FieldsParsedFromText { rule, rules } => {
            let who = match rules {
                1 => format!("{rule} tests"),
                n => format!("{n} rules such as {rule} test"),
            };
            format!(
                "{who} fields the SIEM parses out of the line, which Sluice cannot see: every \
                 line they could see is forwarded whole"
            )
        }
        Reason::RulesNotComplete => "not summarized: the rules are not known to be complete \
                                     (fetch them with `sluice rules fetch`, or pass \
                                     --rules-complete)"
            .to_owned(),
        Reason::UnboundedRule { rule } => {
            format!("{rule} could match any event, so every event is forwarded")
        }
        Reason::SemanticOnCoveredTemplate => {
            "rules apply, so summarizing became rule-guided forwarding".to_owned()
        }
        Reason::StatelessRulesChanged => {
            "rolled back: the SIEM's own rules (logtest) judged a reduced event differently"
                .to_owned()
        }
        Reason::DetectionChanged { missing, extra } => {
            format!("rolled back: the proof found {missing} missing and {extra} extra alerts")
        }
    };
    format!("{what} (contract rule {})", adjustment.contract.number())
}

/// Where a saving can run, in plain words; `None` when there is no saving.
pub(crate) fn placements(placements: &[crate::plan::Placement]) -> Option<String> {
    use crate::plan::Placement;
    match placements {
        [] => None,
        [Placement::Pipeline] => Some("needs a pipeline tool such as Vector".to_owned()),
        _ => Some("a pipeline tool, the SIEM's own ingestion, or the agent".to_owned()),
    }
}

pub(crate) fn provenance(provenance: &Provenance) -> String {
    match provenance {
        Provenance::Community { recipe } => format!("community recipe {recipe}"),
        Provenance::Ai { model } => format!("AI ({model})"),
        Provenance::Operator => "operator".to_owned(),
        Provenance::Learned => "values learned from the sample".to_owned(),
    }
}

pub(crate) fn logsource(logsource: &LogSource) -> String {
    let parts: Vec<String> = [
        ("product", &logsource.product),
        ("service", &logsource.service),
        ("category", &logsource.category),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.as_ref().map(|v| format!("{name}={v}")))
    .collect();
    if parts.is_empty() {
        "(any)".to_owned()
    } else {
        parts.join(", ")
    }
}

fn list<'a>(fields: impl Iterator<Item = &'a FieldPath>) -> String {
    fields.map(FieldPath::as_str).collect::<Vec<_>>().join(", ")
}
