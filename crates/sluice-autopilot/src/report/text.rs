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

#[cfg(test)]
mod tests {
    use sluice_core::predicate::Predicate;
    use sluice_core::recipe::ImpliedValue;

    use super::*;
    use crate::plan::Placement;

    fn recipe() -> EffectiveRecipe {
        EffectiveRecipe::passthrough("t".into())
    }

    #[test]
    fn each_reduction_is_said_in_plain_words_and_nothing_for_a_passthrough() {
        assert_eq!(actions(&recipe()), Vec::<String>::new());
        let all = EffectiveRecipe {
            drop_fields: ["Message".into(), "Opcode".into()].into(),
            drop_empty_except: Some(["User".into()].into()),
            drop_implied: ["Channel", "Channel", "Keywords"]
                .iter()
                .map(|f| ImpliedValue {
                    field: (*f).into(),
                    value: Literal::Text("x".into()),
                    when: None,
                })
                .collect(),
            route: Route::ForwardMatching {
                prefilter: Predicate::Always,
                summary_keys: vec!["Computer".into()],
            },
            ..recipe()
        };
        assert_eq!(
            actions(&all),
            [
                "drop Message, Opcode",
                "drop null and empty fields, except 1 needed by rules",
                "drop the value of 2 field(s) while it is the one the kind of event or another \
                 field implies (each below, with why)",
                "forward events a rule could match; summarize the rest by Computer",
            ]
        );
        let empties = EffectiveRecipe {
            drop_empty_except: Some(BTreeSet::new()),
            ..recipe()
        };
        assert_eq!(actions(&empties), ["drop null and empty fields"]);
    }

    #[test]
    fn three_values_are_listed_and_a_fourth_makes_one_pair_stand_for_them() {
        let pairs = |n: usize| EffectiveRecipe {
            drop_implied: (0..n)
                .map(|i| ImpliedValue {
                    field: "Sid".into(),
                    value: Literal::Text(format!("S-{i}")),
                    when: Some(("Name".into(), Literal::Text(format!("n{i}")))),
                })
                .collect(),
            ..recipe()
        };
        let three = why_removed(&"Sid".into(), &pairs(3));
        assert!(three.starts_with("follows from another field: \"S-0\" whenever Name is \"n0\";"));
        assert!(three.contains("\"S-2\" whenever Name is \"n2\""), "{three}");
        let four = why_removed(&"Sid".into(), &pairs(4));
        assert!(
            four.starts_with("follows from Name: each of its 4 values"),
            "{four}"
        );
    }

    #[test]
    fn where_a_saving_runs_is_said_only_when_there_is_one() {
        assert_eq!(placements(&[]), None);
        assert_eq!(
            placements(&[Placement::Pipeline]).as_deref(),
            Some("needs a pipeline tool such as Vector")
        );
        assert_eq!(
            placements(&[Placement::Pipeline, Placement::SiemIngest, Placement::Agent]).as_deref(),
            Some("a pipeline tool, the SIEM's own ingestion, or the agent")
        );
    }

    #[test]
    fn each_source_of_a_proposal_is_named() {
        assert_eq!(
            provenance(&Provenance::Community {
                recipe: "microsoft/windows/security".into()
            }),
            "community recipe microsoft/windows/security"
        );
        assert_eq!(
            provenance(&Provenance::Ai {
                model: "claude-opus-5-5".into()
            }),
            "AI (claude-opus-5-5)"
        );
        assert_eq!(provenance(&Provenance::Operator), "operator");
        assert_eq!(
            provenance(&Provenance::Learned),
            "values learned from the sample"
        );
    }
}
