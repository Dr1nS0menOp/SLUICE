//! Spot checks with stateless per-event rules (Wazuh `logtest`).
//!
//! For every template with an enforced recipe, a few forwarded and a few summarized events are
//! checked against the real rules: a forwarded event must fire the same rules as its original,
//! a summarized event must fire none. Any difference rolls back that template's recipe.
//!
//! Events of text sources are checked as the raw line, the way a SIEM reads them from a log file
//! or syslog; JSON sources as JSON. A forwarded text event that lost its line cannot be checked
//! and is treated as a difference (fail closed).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sluice_core::alert::EventRules;
use sluice_core::event::Event;
use sluice_core::guard::{Adjustment, ContractRule, EffectiveRecipe, Reason};
use sluice_core::ids::TemplateId;
use sluice_core::proof::ProofError;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::source::{Source, SourceFormat};

/// Events checked per template and outcome.
const PER_OUTCOME: usize = 5;

/// What a spot check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpotCheck {
    /// Events checked.
    pub checked: usize,
    /// Checked events whose original fired at least one rule. Without these, agreement only
    /// shows that nothing fires, so the report states this number.
    pub fired: usize,
    /// Templates whose recipe changed a rule result, and were rolled back.
    pub rolled_back: BTreeSet<TemplateId>,
}

/// Checks samples of every reducing template; returns the templates that must be rolled back.
pub(crate) fn check(
    rules: &dyn EventRules,
    sources: &[Source],
    events: &[Event],
    assignments: &BTreeMap<sluice_core::ids::EventId, TemplateId>,
    recipes: &[EffectiveRecipe],
    data_plane: &impl Reducer,
) -> Result<SpotCheck, ProofError> {
    let reducing: BTreeSet<&TemplateId> = recipes
        .iter()
        .filter(|r| !r.is_passthrough())
        .map(|r| &r.template)
        .collect();
    let mut taken: BTreeMap<(&TemplateId, bool), usize> = BTreeMap::new();
    let mut result = SpotCheck::default();
    for event in events {
        let Some(template) = assignments.get(&event.id).filter(|t| reducing.contains(t)) else {
            continue;
        };
        if result.rolled_back.contains(template) {
            continue;
        }
        let reduced = data_plane.reduce(event)?;
        let forwarded = matches!(reduced.outcome, Outcome::Forwarded(_));
        let count = taken.entry((template, forwarded)).or_default();
        if *count >= PER_OUTCOME {
            continue;
        }
        *count += 1;
        result.checked += 1;
        let format = sources
            .iter()
            .find(|s| s.id == event.source)
            .map_or(&SourceFormat::Json, |s| &s.format);
        let original = fired(rules, format, &event.fields)?;
        if original.as_ref().is_some_and(|o| !o.is_empty()) {
            result.fired += 1;
        }
        let same = match &reduced.outcome {
            Outcome::Forwarded(body) => {
                original.is_some() && fired(rules, format, body)? == original
            }
            Outcome::Summarized => original.is_some_and(|o| o.is_empty()),
        };
        if !same {
            result.rolled_back.insert(template.clone());
        }
    }
    Ok(result)
}

/// The rules `body` fires in the form the SIEM receives it; `None` if a text event has no line.
fn fired(
    rules: &dyn EventRules,
    format: &SourceFormat,
    body: &Map<String, Value>,
) -> Result<Option<BTreeSet<sluice_core::ids::RuleId>>, ProofError> {
    let result = match format {
        SourceFormat::Json => rules.fired(body),
        SourceFormat::Text { field } => match body.get(field.as_str()).and_then(Value::as_str) {
            Some(line) => rules.fired_line(line),
            None => return Ok(None),
        },
    };
    Ok(Some(result?))
}

/// Rolls back the recipes of `templates`, recording why.
pub(crate) fn roll_back(recipes: &mut [EffectiveRecipe], templates: &BTreeSet<TemplateId>) {
    for recipe in recipes
        .iter_mut()
        .filter(|r| templates.contains(&r.template))
    {
        let mut adjustments = std::mem::take(&mut recipe.adjustments);
        adjustments.push(Adjustment {
            contract: ContractRule::ProvenBeforeEnforced,
            level: None,
            reason: Reason::StatelessRulesChanged,
        });
        *recipe = EffectiveRecipe {
            adjustments,
            ..EffectiveRecipe::passthrough(recipe.template.clone())
        };
    }
}
