//! The shadow proof: safety contract rule 5.
//!
//! A set of recipes is *proven* on a sample when the rules raise exactly the same alerts on the
//! data the SIEM would receive as on the full data, in both directions. Fewer alerts would be a
//! missed detection; extra alerts would mean a rule's exclusion lost its field and now fires on
//! noise. Both are regressions.
//!
//! [`select_proven`] is the autopilot's use of the proof. It starts from every candidate recipe,
//! rolls back the recipes implicated in any regression, and repeats until the proof holds. The
//! result is always proven: in the worst case every recipe is rolled back, and pass-through
//! trivially reproduces the full alert set.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::alert::{Alert, EngineError, RuleEngine};
use crate::event::{Event, encoded_size};
use crate::field::FieldPath;
use crate::guard::{Adjustment, ContractRule, EffectiveRecipe, Reason};
use crate::ids::{EventId, SourceId, TemplateId};
use crate::reduce::{Outcome, ReduceError, Reducer};

/// The proof could not be carried out, so nothing is proven.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The rule engine failed.
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The data plane failed on an event.
    #[error(transparent)]
    Reduce(#[from] ReduceError),
    /// The data plane for a recipe set could not be built.
    #[error("cannot build the data plane: {0}")]
    Build(String),
    /// Even with every recipe rolled back, the alerts differ. Pass-through must reproduce the
    /// full data exactly, so the engine or the data plane is not deterministic.
    #[error(
        "alerts differ with every recipe rolled back: the engine or data plane is not deterministic"
    )]
    Inconsistent,
}

/// Volume through the data plane, for one template or in total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Volume {
    /// Events in.
    pub events: u64,
    /// Events forwarded to the SIEM (in full or reduced).
    pub forwarded: u64,
    /// Events counted into summaries instead.
    pub summarized: u64,
    /// Bytes in (compact JSON).
    pub bytes_in: u64,
    /// Bytes forwarded (compact JSON of the forwarded bodies).
    pub bytes_out: u64,
}

impl Volume {
    fn add(&mut self, bytes_in: usize, outcome: &Outcome) {
        self.events += 1;
        self.bytes_in += to_u64(bytes_in);
        match outcome {
            Outcome::Forwarded(body) => {
                self.forwarded += 1;
                self.bytes_out += to_u64(encoded_size(body));
            }
            Outcome::Summarized => self.summarized += 1,
        }
    }
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The outcome of one proof run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Alerts on the full data.
    pub full_alerts: BTreeSet<Alert>,
    /// Alerts on the forwarded data.
    pub forwarded_alerts: BTreeSet<Alert>,
    /// Alerts on full data that the forwarded data does not raise.
    pub missing: BTreeSet<Alert>,
    /// Alerts the forwarded data raises that full data does not.
    pub extra: BTreeSet<Alert>,
    /// Volume in total.
    pub total: Volume,
    /// Volume per template the data plane classified (`None`: unclassified).
    pub per_template: BTreeMap<Option<TemplateId>, Volume>,
    /// Per template, the fields the data plane removed from forwarded events. This is what a
    /// recipe's removals, "drop null and empty fields" among them, came to on the sample.
    pub removed: BTreeMap<Option<TemplateId>, BTreeMap<FieldPath, Removal>>,
}

/// What removing one field came to on the sample.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Removal {
    /// Forwarded events that lost the field.
    pub events: u64,
    /// Bytes the field took in them, as `"name":value,` in compact JSON.
    pub bytes: u64,
}

impl Proof {
    /// Whether the forwarded data raises exactly the full data's alerts.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.missing.is_empty() && self.extra.is_empty()
    }
}

/// Runs the proof for one data plane.
///
/// # Errors
///
/// Returns [`ProofError`] if the engine or the data plane fails.
pub fn prove(
    events: &[Event],
    engine: &impl RuleEngine,
    data_plane: &impl Reducer,
) -> Result<Proof, ProofError> {
    let full_alerts = engine.alerts(events)?;
    let run = Run::new(events, data_plane)?;
    run.into_proof(full_alerts, engine)
}

/// The data plane's effect on a sample, before rules are evaluated on it. Forwarded events the
/// data plane left unchanged are borrowed from the sample rather than copied: most events are,
/// and a copy of every one doubled the proof's memory.
struct Run<'a> {
    forwarded: Vec<Cow<'a, Event>>,
    templates: BTreeMap<EventId, (SourceId, Option<TemplateId>)>,
    total: Volume,
    per_template: BTreeMap<Option<TemplateId>, Volume>,
    removed: BTreeMap<Option<TemplateId>, BTreeMap<FieldPath, Removal>>,
}

impl<'a> Run<'a> {
    fn new(events: &'a [Event], data_plane: &impl Reducer) -> Result<Self, ProofError> {
        let mut run = Self {
            forwarded: Vec::new(),
            templates: BTreeMap::new(),
            total: Volume::default(),
            per_template: BTreeMap::new(),
            removed: BTreeMap::new(),
        };
        for event in events {
            let reduced = data_plane.reduce(event)?;
            let bytes_in = encoded_size(&event.fields);
            run.total.add(bytes_in, &reduced.outcome);
            run.per_template
                .entry(reduced.template.clone())
                .or_default()
                .add(bytes_in, &reduced.outcome);
            run.templates
                .insert(event.id, (event.source.clone(), reduced.template.clone()));
            if let Outcome::Forwarded(body) = reduced.outcome {
                run.forwarded.push(if body == event.fields {
                    Cow::Borrowed(event)
                } else {
                    let removals = run.removed.entry(reduced.template).or_default();
                    for (path, bytes) in removed_paths(&event.fields, &body) {
                        let removal = removals.entry(path).or_default();
                        removal.events += 1;
                        removal.bytes += to_u64(bytes);
                    }
                    Cow::Owned(Event {
                        fields: body,
                        ..event.clone()
                    })
                });
            }
        }
        Ok(run)
    }

    fn into_proof(
        self,
        full_alerts: BTreeSet<Alert>,
        engine: &impl RuleEngine,
    ) -> Result<Proof, ProofError> {
        let forwarded: Vec<&Event> = self.forwarded.iter().map(AsRef::as_ref).collect();
        let forwarded_alerts = engine.alerts_refs(&forwarded)?;
        Ok(Proof {
            missing: full_alerts.difference(&forwarded_alerts).cloned().collect(),
            extra: forwarded_alerts.difference(&full_alerts).cloned().collect(),
            full_alerts,
            forwarded_alerts,
            total: self.total,
            per_template: self.per_template,
            removed: self.removed,
        })
    }
}

/// The paths of the fields in `before` that `after` no longer has, each with the bytes it took.
/// An object that lost only some of its fields is followed into; one removed whole counts as its
/// own path.
fn removed_paths(
    before: &Map<String, Value>,
    after: &Map<String, Value>,
) -> Vec<(FieldPath, usize)> {
    let mut paths = Vec::new();
    removed_under("", before, after, &mut paths);
    paths
}

fn removed_under(
    prefix: &str,
    before: &Map<String, Value>,
    after: &Map<String, Value>,
    paths: &mut Vec<(FieldPath, usize)>,
) {
    for (key, value) in before {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match (value, after.get(key)) {
            (_, None) => paths.push((FieldPath::new(path), member_size(key, value))),
            (Value::Object(inner), Some(Value::Object(kept))) if inner != kept => {
                removed_under(&path, inner, kept, paths);
            }
            _ => {}
        }
    }
}

/// The bytes `"key":value,` takes in compact JSON, as [`encoded_size`] counts the event.
fn member_size(key: &str, value: &Value) -> usize {
    let mut member = Map::new();
    member.insert(key.to_owned(), value.clone());
    // `{"key":value}` without its two braces, plus the comma before the next member.
    encoded_size(&member).saturating_sub(1)
}

/// The recipes the autopilot may enforce, and the proof that they are safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Every input recipe; those that caused a regression are rolled back to pass-through with
    /// an explaining [`Adjustment`].
    pub recipes: Vec<EffectiveRecipe>,
    /// The proof of the final set. It always holds.
    pub proof: Proof,
    /// How many proof runs it took.
    pub rounds: usize,
}

/// Proves `candidates`, rolling back recipes implicated in regressions until the proof holds.
///
/// `build` turns a recipe set into the data plane that enforces it.
///
/// # Errors
///
/// Returns [`ProofError`] if the engine or data plane fails, or behaves non-deterministically.
pub fn select_proven<R: Reducer>(
    candidates: Vec<EffectiveRecipe>,
    events: &[Event],
    engine: &impl RuleEngine,
    mut build: impl FnMut(&[EffectiveRecipe]) -> Result<R, ProofError>,
) -> Result<Selection, ProofError> {
    let full_alerts = engine.alerts(events)?;
    // Every round but the last rolls back at least one recipe, so more rounds than recipes plus
    // one mean the roll-back is broken: stop rather than loop.
    let max_rounds = candidates.len() + 1;
    let mut recipes = candidates;
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > max_rounds {
            return Err(ProofError::Inconsistent);
        }
        let run = Run::new(events, &build(&recipes)?)?;
        let templates = run.templates.clone();
        let proof = run.into_proof(full_alerts.clone(), engine)?;
        if proof.holds() {
            return Ok(Selection {
                recipes,
                proof,
                rounds,
            });
        }
        if !roll_back(&mut recipes, &proof, &templates) {
            return Err(ProofError::Inconsistent);
        }
    }
}

/// Rolls back the recipes implicated in the proof's regressions. Returns false if there was
/// nothing left to roll back.
fn roll_back(
    recipes: &mut [EffectiveRecipe],
    proof: &Proof,
    templates: &BTreeMap<EventId, (SourceId, Option<TemplateId>)>,
) -> bool {
    let changed: Vec<&Alert> = proof.missing.iter().chain(&proof.extra).collect();
    let located: Vec<&(SourceId, Option<TemplateId>)> = changed
        .iter()
        .filter_map(|a| templates.get(&a.event))
        .collect();
    let reason = Reason::DetectionChanged {
        missing: proof.missing.len(),
        extra: proof.extra.len(),
    };

    // 1. The templates of the events the changed alerts fired on.
    let implicated: BTreeSet<&TemplateId> =
        located.iter().filter_map(|(_, t)| t.as_ref()).collect();
    if revert(recipes, &reason, |r| implicated.contains(&r.template)) {
        return true;
    }
    // 2. Every recipe in those sources: a stateful rule can be shifted by another template.
    let sources: BTreeSet<&SourceId> = located.iter().map(|(s, _)| s).collect();
    let in_sources: BTreeSet<&TemplateId> = templates
        .values()
        .filter(|(s, _)| sources.contains(s))
        .filter_map(|(_, t)| t.as_ref())
        .collect();
    if revert(recipes, &reason, |r| in_sources.contains(&r.template)) {
        return true;
    }
    // 3. Everything.
    revert(recipes, &reason, |_| true)
}

fn revert(
    recipes: &mut [EffectiveRecipe],
    reason: &Reason,
    implicated: impl Fn(&EffectiveRecipe) -> bool,
) -> bool {
    let mut any = false;
    for recipe in recipes
        .iter_mut()
        .filter(|r| !r.is_passthrough() && implicated(r))
    {
        let mut adjustments = std::mem::take(&mut recipe.adjustments);
        adjustments.push(Adjustment {
            contract: ContractRule::ProvenBeforeEnforced,
            level: None,
            reason: reason.clone(),
        });
        *recipe = EffectiveRecipe {
            adjustments,
            ..EffectiveRecipe::passthrough(recipe.template.clone())
        };
        any = true;
    }
    any
}

#[cfg(test)]
mod tests;
