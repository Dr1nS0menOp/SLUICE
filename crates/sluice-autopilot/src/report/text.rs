//! Plain-language descriptions of recipes and guardrail decisions.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::guard::{Adjustment, EffectiveRecipe, Reason, Route};
use sluice_core::logsource::LogSource;
use sluice_core::recipe::{ImpliedValue, Literal, Provenance};

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
        let fields: BTreeSet<&FieldPath> = recipe.drop_implied.iter().map(|v| &v.field).collect();
        actions.push(format!(
            "drop the value of {} field(s) while it is the one the kind of event or another field \
             implies (each below, with why)",
            fields.len()
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

/// Whether `path` goes as an implied value: the recipe implies it and does not list it.
pub(crate) fn implied(path: &FieldPath, recipe: &EffectiveRecipe) -> bool {
    recipe.drop_implied.iter().any(|v| &v.field == path)
        && !recipe.drop_fields.iter().any(|f| f.covers(path))
}

/// An implied field with more values than this is described by one of them.
const MANY_VALUES: usize = 3;

/// Why `path` may be removed from the template's events: the recipe lists it, its value is
/// implied (and by what), or it was empty.
pub(crate) fn why_removed(path: &FieldPath, recipe: &EffectiveRecipe) -> String {
    if recipe.drop_fields.iter().any(|f| f.covers(path)) {
        return "the recipe removes it: it repeats the event (the recipe's reasoning is below)"
            .to_owned();
    }
    let implied: Vec<&ImpliedValue> = recipe
        .drop_implied
        .iter()
        .filter(|v| &v.field == path)
        .collect();
    if implied.is_empty() {
        return "it was empty (null or \"\"), which says nothing".to_owned();
    }
    // Per value, the values of the fields that imply it: `"-" whenever LogonType is 2 or 3`.
    let mut by_value: BTreeMap<String, BTreeMap<&FieldPath, Vec<String>>> = BTreeMap::new();
    let mut constant = None;
    for value in implied {
        match &value.when {
            None => constant = Some(value.value.to_string()),
            Some((on, when)) => by_value
                .entry(value.value.to_string())
                .or_default()
                .entry(on)
                .or_default()
                .push(when.to_string()),
        }
    }
    if let Some(value) = constant {
        return format!(
            "always {value} on this kind of event, so the kind of event implies it; left out \
             only while it holds that value, and put back from the plan"
        );
    }
    if by_value.len() > MANY_VALUES {
        // A field that pairs with another, such as an account's SID with its name: one pair
        // says what the rest are like.
        let on: BTreeSet<&FieldPath> = by_value
            .values()
            .flat_map(BTreeMap::keys)
            .copied()
            .collect();
        let (value, ons) = by_value
            .iter()
            .next()
            .expect("more than MANY_VALUES entries");
        let (first, whens) = ons
            .iter()
            .next()
            .expect("every value has a field implying it");
        return format!(
            "follows from {}: each of its {} values goes with one value there, such as {value} \
             whenever {first} is {}; left out only while that holds, and put back from the plan",
            list(on.into_iter()),
            by_value.len(),
            whens.join(" or ")
        );
    }
    let parts: Vec<String> = by_value
        .into_iter()
        .map(|(value, ons)| {
            let whens: Vec<String> = ons
                .into_iter()
                .map(|(on, whens)| format!("{on} is {}", whens.join(" or ")))
                .collect();
            format!("{value} whenever {}", whens.join(" or "))
        })
        .collect();
    format!(
        "follows from another field: {}; left out only while that holds, and put back from the \
         plan",
        parts.join("; ")
    )
}

/// Where the removal of `path` can run: a pipeline tool always; with `shared`, also the SIEM's
/// ingestion and the agent, except an implied whole number, which an agent cannot test.
pub(crate) fn where_removed(path: &FieldPath, recipe: &EffectiveRecipe, shared: bool) -> String {
    let whole_number = recipe.drop_implied.iter().any(|v| {
        &v.field == path
            && (matches!(v.value, Literal::Integer(_))
                || v.when
                    .as_ref()
                    .is_some_and(|(_, w)| matches!(w, Literal::Integer(_))))
    }) && !recipe.drop_fields.iter().any(|f| f.covers(path));
    match (shared, whole_number) {
        (false, _) => "Vector (a pipeline tool)".to_owned(),
        (true, false) => "Vector, the SIEM's own ingestion, or the agent".to_owned(),
        (true, true) => {
            "Vector or the SIEM's own ingestion (an agent cannot tell 3 from 3.0)".to_owned()
        }
    }
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
