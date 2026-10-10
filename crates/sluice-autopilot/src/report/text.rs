//! Plain-language descriptions of recipes and guardrail decisions.

use sluice_core::field::FieldPath;
use sluice_core::guard::{Adjustment, EffectiveRecipe, Reason, Route};
use sluice_core::logsource::LogSource;
use sluice_core::recipe::Provenance;

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
    if let Route::ForwardMatching { summary_keys, .. } = &recipe.route {
        actions.push(format!(
            "forward events a rule could match; summarize the rest by {}",
            list(summary_keys.iter())
        ));
    }
    actions
}

pub(crate) fn adjustment(adjustment: &Adjustment) -> String {
    let what = match &adjustment.reason {
        Reason::NoRecipe => "no recipe: forwarded unchanged".to_owned(),
        Reason::NoArchive => "archiving is off, so nothing may be cut".to_owned(),
        Reason::RareTemplate {
            events,
            source_events,
        } => format!("rare ({events} of {source_events} events in its source), so never cut"),
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

pub(crate) fn provenance(provenance: &Provenance) -> String {
    match provenance {
        Provenance::Community { recipe } => format!("community recipe {recipe}"),
        Provenance::Ai { model } => format!("AI ({model})"),
        Provenance::Operator => "operator".to_owned(),
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
