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
    /// Conservative mode: no recipe is enforced without an operator's approval (ADR 0016).
    pub approval: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            shadow_secs: 24 * 3_600,
            min_proofs: 3,
            approval: false,
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
    /// The template became rare in this window, so its recipe stopped (contract rule 4, not a
    /// failed proof). It starts over in shadow once the template is clearly frequent again.
    Paused(TemplateId),
    /// An operator held the template: its recipe stopped and stays stopped until released.
    Held(TemplateId),
}

/// What one window says about the tracked templates.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// Templates present in the window.
    pub seen: &'a BTreeSet<TemplateId>,
    /// Templates whose recipe was proven on it.
    pub proven: &'a BTreeSet<TemplateId>,
    /// Templates below the rarity floor in it: never cut, but nothing failed.
    pub rare: &'a BTreeSet<TemplateId>,
    /// Templates too close to the floor for a new recipe to start
    /// ([`GuardrailConfig::is_near_rare`](sluice_core::guard::GuardrailConfig::is_near_rare)).
    pub near_rare: &'a BTreeSet<TemplateId>,
}

/// The stages of all templates with a proven recipe, and the last proven recipe of every enforced
/// template, which stays deployed through windows in which the template is absent. Operators may
/// hold templates (never cut) and approve recipes (enforced at their next proof).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lifecycle {
    policy: Policy,
    stages: BTreeMap<TemplateId, Stage>,
    deployed: BTreeMap<TemplateId, (Template, EffectiveRecipe)>,
    held: BTreeSet<TemplateId>,
    approved: BTreeSet<TemplateId>,
}

impl Lifecycle {
    /// A lifecycle with nothing in shadow or enforced.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            stages: BTreeMap::new(),
            deployed: BTreeMap::new(),
            held: BTreeSet::new(),
            approved: BTreeSet::new(),
        }
    }

    /// Holds a template: its recipe stops now and does not advance until released. Holding only
    /// ever adds protection. Returns the transition if a recipe was in shadow or enforced.
    pub fn hold(&mut self, template: &TemplateId) -> Option<Transition> {
        self.held.insert(template.clone());
        self.approved.remove(template);
        self.deployed.remove(template);
        self.stages
            .remove(template)
            .map(|_| Transition::Held(template.clone()))
    }

    /// Releases a held template; its recipe starts over in shadow when next proven.
    pub fn release(&mut self, template: &TemplateId) -> bool {
        self.held.remove(template)
    }

    /// Approves the recipe of a template in shadow: it is enforced at the next cycle in which it
    /// is proven, without waiting for the shadow time and proof count. Returns false when the
    /// template is not in shadow.
    pub fn approve(&mut self, template: &TemplateId) -> bool {
        let shadow = matches!(self.stages.get(template), Some(Stage::Shadow { .. }));
        if shadow {
            self.approved.insert(template.clone());
        }
        shadow
    }

    /// The promotion policy.
    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Held templates.
    #[must_use]
    pub fn held(&self) -> &BTreeSet<TemplateId> {
        &self.held
    }

    /// Approved recipes still in shadow.
    #[must_use]
    pub fn approved(&self) -> &BTreeSet<TemplateId> {
        &self.approved
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

    /// Advances one cycle on a window's evidence. A template absent from the window keeps its
    /// stage: no traffic is no evidence either way. A tracked template that was not proven stops:
    /// paused if it became rare, otherwise demoted (shadow) or rolled back (enforced). A new
    /// recipe only enters shadow when its template is clearly above the rarity floor.
    pub fn advance(&mut self, now: Timestamp, evidence: Evidence<'_>) -> Vec<Transition> {
        let mut transitions = Vec::new();
        let stopped: Vec<TemplateId> = self
            .stages
            .keys()
            .filter(|t| evidence.seen.contains(*t) && !evidence.proven.contains(*t))
            .cloned()
            .collect();
        for template in stopped {
            self.approved.remove(&template);
            self.deployed.remove(&template);
            let stage = self.stages.remove(&template);
            match stage {
                Some(_) if evidence.rare.contains(&template) => {
                    transitions.push(Transition::Paused(template));
                }
                Some(Stage::Enforced { .. }) => transitions.push(Transition::RolledBack(template)),
                Some(Stage::Shadow { .. }) => transitions.push(Transition::Demoted(template)),
                None => {}
            }
        }
        for template in evidence.proven {
            if self.held.contains(template) {
                continue;
            }
            let next = match self.stages.get(template) {
                None if evidence.near_rare.contains(template) => continue,
                None => {
                    transitions.push(Transition::Shadowing(template.clone()));
                    Stage::Shadow {
                        since: now,
                        proofs: 1,
                    }
                }
                Some(Stage::Shadow { since, proofs }) => {
                    let proofs = proofs + 1;
                    let waited = now.0 - since.0 >= self.policy.shadow_secs
                        && proofs >= self.policy.min_proofs;
                    let approved = self.approved.contains(template);
                    if approved || (waited && !self.policy.approval) {
                        self.approved.remove(template);
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
        step_with(l, at, proven, &[], &[])
    }

    fn step_with(
        l: &mut Lifecycle,
        at: i64,
        proven: &[&str],
        rare: &[&str],
        near_rare: &[&str],
    ) -> Vec<Transition> {
        let seen = ids(&["a", "b", "c"]);
        l.advance(
            Timestamp(at),
            Evidence {
                seen: &seen,
                proven: &ids(proven),
                rare: &ids(rare),
                near_rare: &ids(near_rare),
            },
        )
    }

    fn lifecycle() -> Lifecycle {
        Lifecycle::new(Policy {
            shadow_secs: 24 * HOUR,
            min_proofs: 3,
            approval: false,
        })
    }

    #[test]
    fn c5_a_held_template_is_never_cut_until_released() {
        let mut l = lifecycle();
        for hour in [0, 12, 24] {
            step(&mut l, hour * HOUR, &["a"]);
        }
        assert_eq!(l.hold(&"a".into()), Some(Transition::Held("a".into())));
        assert!(l.enforced().is_empty() && l.deployed().is_empty());
        assert_eq!(step(&mut l, 25 * HOUR, &["a"]), [], "proven, but held");
        assert!(l.stages().is_empty());
        assert!(l.release(&"a".into()));
        assert_eq!(
            step(&mut l, 26 * HOUR, &["a"]),
            [Transition::Shadowing("a".into())],
            "released: starts over in shadow"
        );
    }

    #[test]
    fn c5_approval_shortens_the_wait_but_never_skips_the_proof() {
        let mut l = lifecycle();
        assert!(!l.approve(&"a".into()), "nothing in shadow yet");
        step(&mut l, 0, &["a"]);
        assert!(l.approve(&"a".into()));
        assert_eq!(step(&mut l, HOUR, &[]), [Transition::Demoted("a".into())]);
        assert!(l.approved().is_empty(), "a failed proof drops the approval");
        step(&mut l, 2 * HOUR, &["a"]);
        l.approve(&"a".into());
        assert_eq!(
            step(&mut l, 3 * HOUR, &["a"]),
            [Transition::Promoted("a".into())]
        );
    }

    #[test]
    fn c5_in_conservative_mode_nothing_is_enforced_without_approval() {
        let mut l = Lifecycle::new(Policy {
            shadow_secs: HOUR,
            min_proofs: 2,
            approval: true,
        });
        for hour in [0, 2, 4, 6] {
            step(&mut l, hour * HOUR, &["a"]);
        }
        assert!(l.enforced().is_empty());
        l.approve(&"a".into());
        step(&mut l, 7 * HOUR, &["a"]);
        assert_eq!(l.enforced(), ids(&["a"]));
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
        let none = ids(&[]);
        let quiet = l.advance(
            Timestamp(30 * HOUR),
            Evidence {
                seen: &none,
                proven: &none,
                rare: &none,
                near_rare: &none,
            },
        );
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

    #[test]
    fn c4_a_template_that_turns_rare_pauses_instead_of_rolling_back() {
        let mut l = lifecycle();
        for hour in [0, 12, 24] {
            step(&mut l, hour * HOUR, &["a"]);
        }
        assert_eq!(
            step_with(&mut l, 25 * HOUR, &[], &["a"], &["a"]),
            [Transition::Paused("a".into())]
        );
        assert!(l.enforced().is_empty(), "rare is never cut");
    }

    #[test]
    fn c4_a_new_recipe_waits_until_its_template_is_clearly_frequent() {
        let mut l = lifecycle();
        // Proven, but just above the floor: it does not enter shadow, so it cannot flap.
        assert_eq!(step_with(&mut l, 0, &["a"], &[], &["a"]), []);
        assert!(l.stages().is_empty());
        assert_eq!(
            step(&mut l, HOUR, &["a"]),
            [Transition::Shadowing("a".into())]
        );
        // Once in shadow, being near the floor does not stop it; being below it does.
        assert_eq!(step_with(&mut l, 2 * HOUR, &["a"], &[], &["a"]), []);
        assert!(matches!(
            l.stages()[&TemplateId::new("a")],
            Stage::Shadow { proofs: 2, .. }
        ));
    }
}
