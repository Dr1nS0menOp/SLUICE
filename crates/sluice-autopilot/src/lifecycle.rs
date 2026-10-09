//! Promotion of recipes from proposal to enforcement, and their rollback (ADR 0005).
//!
//! A template's recipe moves `Candidate → Shadow → Enforced` only by being proven on consecutive
//! windows of live traffic for a minimum time. A failed proof demotes it at any stage; for an
//! enforced recipe that is a rollback.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::event::Timestamp;
use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::TemplateId;
use sluice_core::template::Template;

/// When a proven recipe may be enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Minimum time in shadow, in seconds.
    pub shadow_secs: i64,
    /// Minimum consecutive proofs in shadow.
    pub min_proofs: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            shadow_secs: 24 * 3_600,
            min_proofs: 3,
        }
    }
}

/// Where a template's recipe stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Proven on consecutive windows since `since`, but not enforced yet.
    Shadow {
        /// Start of the shadow period.
        since: Timestamp,
        /// Consecutive proofs so far.
        proofs: u32,
    },
    /// Enforced in the data plane since `since`.
    Enforced {
        /// When it was promoted.
        since: Timestamp,
    },
}

/// Something that happened to a template's recipe, for logs, status and alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// A newly proven recipe entered shadow.
    Shadowing(TemplateId),
    /// A recipe completed shadow and is now enforced.
    Promoted(TemplateId),
    /// A recipe in shadow failed a proof and starts over.
    Demoted(TemplateId),
    /// An enforced recipe failed a proof and was removed from the data plane.
    RolledBack(TemplateId),
}

/// The stages of all templates with a proven recipe, and the last proven recipe of every enforced
/// template, which stays deployed through windows in which the template is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lifecycle {
    policy: Policy,
    stages: BTreeMap<TemplateId, Stage>,
    deployed: BTreeMap<TemplateId, (Template, EffectiveRecipe)>,
}

impl Lifecycle {
    /// A lifecycle with nothing in shadow or enforced.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            stages: BTreeMap::new(),
            deployed: BTreeMap::new(),
        }
    }

    /// Records the latest proven recipe of an enforced template.
    pub fn remember(&mut self, template: &Template, recipe: &EffectiveRecipe) {
        if matches!(self.stages.get(&template.id), Some(Stage::Enforced { .. })) {
            self.deployed
                .insert(template.id.clone(), (template.clone(), recipe.clone()));
        }
    }

    /// The recipe to deploy for every enforced template that has one recorded.
    #[must_use]
    pub fn deployed(&self) -> &BTreeMap<TemplateId, (Template, EffectiveRecipe)> {
        &self.deployed
    }

    /// The stage of every tracked template.
    #[must_use]
    pub fn stages(&self) -> &BTreeMap<TemplateId, Stage> {
        &self.stages
    }

    /// Templates whose recipe is enforced.
    #[must_use]
    pub fn enforced(&self) -> BTreeSet<TemplateId> {
        self.stages
            .iter()
            .filter(|(_, stage)| matches!(stage, Stage::Enforced { .. }))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Advances one cycle. `seen` are the templates present in this window, `proven` those whose
    /// recipe was proven on it. A template absent from the window keeps its stage: no traffic is
    /// no evidence either way.
    pub fn advance(
        &mut self,
        now: Timestamp,
        seen: &BTreeSet<TemplateId>,
        proven: &BTreeSet<TemplateId>,
    ) -> Vec<Transition> {
        let mut transitions = Vec::new();
        let failed: Vec<TemplateId> = self
            .stages
            .keys()
            .filter(|t| seen.contains(*t) && !proven.contains(*t))
            .cloned()
            .collect();
        for template in failed {
            self.deployed.remove(&template);
            match self.stages.remove(&template) {
                Some(Stage::Enforced { .. }) => transitions.push(Transition::RolledBack(template)),
                Some(Stage::Shadow { .. }) => transitions.push(Transition::Demoted(template)),
                None => {}
            }
        }
        for template in proven {
            let next = match self.stages.get(template) {
                None => {
                    transitions.push(Transition::Shadowing(template.clone()));
                    Stage::Shadow {
                        since: now,
                        proofs: 1,
                    }
                }
                Some(Stage::Shadow { since, proofs }) => {
                    let proofs = proofs + 1;
                    if now.0 - since.0 >= self.policy.shadow_secs
                        && proofs >= self.policy.min_proofs
                    {
                        transitions.push(Transition::Promoted(template.clone()));
                        Stage::Enforced { since: now }
                    } else {
                        Stage::Shadow {
                            since: *since,
                            proofs,
                        }
                    }
                }
                Some(enforced @ Stage::Enforced { .. }) => *enforced,
            };
            self.stages.insert(template.clone(), next);
        }
        transitions
    }

    /// Rolls back enforced templates whose deployment failed its proof.
    pub fn roll_back(&mut self, templates: &BTreeSet<TemplateId>) -> Vec<Transition> {
        let mut transitions = Vec::new();
        for template in templates {
            if matches!(self.stages.get(template), Some(Stage::Enforced { .. })) {
                self.stages.remove(template);
                self.deployed.remove(template);
                transitions.push(Transition::RolledBack(template.clone()));
            }
        }
        transitions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3_600;

    fn ids(names: &[&str]) -> BTreeSet<TemplateId> {
        names.iter().map(|n| TemplateId::new(*n)).collect()
    }

    /// One cycle in which every template named so far was seen; `proven` of them were proven.
    fn step(l: &mut Lifecycle, at: i64, proven: &[&str]) -> Vec<Transition> {
        let seen = ids(&["a", "b", "c"]);
        l.advance(Timestamp(at), &seen, &ids(proven))
    }

    fn lifecycle() -> Lifecycle {
        Lifecycle::new(Policy {
            shadow_secs: 24 * HOUR,
            min_proofs: 3,
        })
    }

    #[test]
    fn c5_recipe_is_enforced_only_after_shadow_time_and_proofs() {
        let mut l = lifecycle();
        assert_eq!(step(&mut l, 0, &["a"]), [Transition::Shadowing("a".into())]);
        assert_eq!(step(&mut l, 12 * HOUR, &["a"]), []);
        assert!(l.enforced().is_empty(), "two proofs, half the shadow time");
        assert_eq!(
            step(&mut l, 24 * HOUR, &["a"]),
            [Transition::Promoted("a".into())]
        );
        assert_eq!(l.enforced(), ids(&["a"]));
    }

    #[test]
    fn c5_time_alone_does_not_promote() {
        let mut l = lifecycle();
        step(&mut l, 0, &["a"]);
        step(&mut l, 48 * HOUR, &["a"]);
        assert!(l.enforced().is_empty(), "two proofs only");
    }

    #[test]
    fn c5_failed_proof_in_shadow_starts_over() {
        let mut l = lifecycle();
        step(&mut l, 0, &["a"]);
        step(&mut l, HOUR, &["a"]);
        assert_eq!(
            step(&mut l, 2 * HOUR, &[]),
            [Transition::Demoted("a".into())]
        );
        step(&mut l, 30 * HOUR, &["a"]);
        assert!(matches!(
            l.stages()[&TemplateId::new("a")],
            Stage::Shadow { proofs: 1, .. }
        ));
    }

    #[test]
    fn c5_unseen_templates_keep_their_stage() {
        let mut l = lifecycle();
        for hour in [0, 12, 24] {
            step(&mut l, hour * HOUR, &["a"]);
        }
        let quiet = l.advance(Timestamp(30 * HOUR), &ids(&[]), &ids(&[]));
        assert_eq!(quiet, []);
        assert_eq!(l.enforced(), ids(&["a"]));
    }

    #[test]
    fn c5_enforced_recipe_that_fails_is_rolled_back() {
        let mut l = lifecycle();
        for hour in [0, 12, 24] {
            step(&mut l, hour * HOUR, &["a", "b"]);
        }
        assert_eq!(l.enforced(), ids(&["a", "b"]));
        assert_eq!(
            step(&mut l, 25 * HOUR, &["b"]),
            [Transition::RolledBack("a".into())]
        );
        assert_eq!(l.enforced(), ids(&["b"]));
        assert_eq!(
            l.roll_back(&ids(&["b", "c"])),
            [Transition::RolledBack("b".into())]
        );
        assert!(l.enforced().is_empty());
    }
}
