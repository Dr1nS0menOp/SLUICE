//! Proof and selection tests (safety contract rule 5), with a fake engine and data plane.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;
use crate::field::FieldPath;
use crate::guard::Route;
use crate::predicate::Predicate;
use crate::reduce::Reduced;

/// Rules: `has-a` fires on events with field `a`; `not-f` fires on `kind: x` events *without*
/// field `f` (an exclusion); `third` fires on the third event of source `s2` (stateful).
struct FakeEngine {
    fail: bool,
}

impl RuleEngine for FakeEngine {
    fn alerts(&self, events: &[Event]) -> Result<BTreeSet<Alert>, EngineError> {
        if self.fail {
            return Err(EngineError("boom".into()));
        }
        let mut alerts = BTreeSet::new();
        let mut s2_seen = 0;
        for event in events {
            let mut fire = |rule: &str| {
                alerts.insert(Alert {
                    rule: rule.into(),
                    event: event.id,
                });
            };
            if event.fields.contains_key("a") {
                fire("has-a");
            }
            if event.fields.get("kind") == Some(&json!("x")) && !event.fields.contains_key("f") {
                fire("not-f");
            }
            if event.source.as_str() == "s2" {
                s2_seen += 1;
                if s2_seen == 3 {
                    fire("third");
                }
            }
        }
        Ok(alerts)
    }
}

/// Template = field `t`. Drops fields; any rule-guided route summarizes every event (it ignores
/// the pre-filter, which is what makes recipes unsafe here).
struct FakePlane {
    recipes: Vec<EffectiveRecipe>,
}

impl Reducer for FakePlane {
    fn reduce(&self, event: &Event) -> Result<Reduced, ReduceError> {
        let template = event
            .fields
            .get("t")
            .and_then(Value::as_str)
            .map(TemplateId::new);
        let recipe = self
            .recipes
            .iter()
            .find(|r| Some(&r.template) == template.as_ref());
        let outcome = match recipe {
            Some(r) if r.route != Route::ForwardAll => Outcome::Summarized,
            Some(r) => {
                let mut body = event.fields.clone();
                for field in &r.drop_fields {
                    body.remove(field.as_str());
                }
                Outcome::Forwarded(body)
            }
            None => Outcome::Forwarded(event.fields.clone()),
        };
        Ok(Reduced { template, outcome })
    }
}

fn event(id: u64, source: &str, fields: Value) -> Event {
    let Value::Object(fields) = fields else {
        panic!("fields must be an object")
    };
    Event {
        id: EventId(id),
        timestamp: crate::event::Timestamp(i64::try_from(id).unwrap()),
        source: source.into(),
        fields,
    }
}

fn sample() -> Vec<Event> {
    vec![
        event(0, "s1", json!({"t": "A", "a": 1, "noise": "zzz"})),
        event(1, "s1", json!({"t": "A", "noise": "zzz"})),
        event(
            2,
            "s1",
            json!({"t": "B", "kind": "x", "f": "kept", "noise": "zzz"}),
        ),
        event(3, "s2", json!({"t": "D"})),
        event(4, "s2", json!({"t": "C"})),
        event(5, "s2", json!({"t": "D"})),
        event(6, "s2", json!({"t": "D"})),
    ]
}

fn drop(template: &str, fields: &[&str]) -> EffectiveRecipe {
    EffectiveRecipe {
        drop_fields: fields.iter().map(|f| FieldPath::from(*f)).collect(),
        ..EffectiveRecipe::passthrough(template.into())
    }
}

fn summarize(template: &str) -> EffectiveRecipe {
    EffectiveRecipe {
        route: Route::ForwardMatching {
            prefilter: Predicate::never(),
            summary_keys: vec!["t".into()],
        },
        ..EffectiveRecipe::passthrough(template.into())
    }
}

fn select(candidates: Vec<EffectiveRecipe>) -> Result<Selection, ProofError> {
    select_proven(
        candidates,
        &sample(),
        &FakeEngine { fail: false },
        |recipes| {
            Ok(FakePlane {
                recipes: recipes.to_vec(),
            })
        },
    )
}

fn rolled_back(selection: &Selection, template: &str) -> bool {
    let recipe = selection
        .recipes
        .iter()
        .find(|r| r.template.as_str() == template)
        .unwrap();
    recipe.is_passthrough()
        && recipe
            .adjustments
            .iter()
            .any(|a| a.contract == ContractRule::ProvenBeforeEnforced)
}

#[test]
fn c5_safe_recipe_is_enforced_after_one_round() {
    let selection = select(vec![drop("A", &["noise"])]).unwrap();
    assert!(selection.proof.holds());
    assert_eq!(selection.rounds, 1);
    assert!(!selection.recipes[0].is_passthrough());
    assert!(selection.proof.total.bytes_out < selection.proof.total.bytes_in);
}

#[test]
fn c5_recipe_that_loses_an_alert_is_rolled_back_alone() {
    let selection = select(vec![drop("A", &["a"]), drop("B", &["noise"])]).unwrap();
    assert!(selection.proof.holds());
    assert!(rolled_back(&selection, "A"));
    assert!(
        !selection.recipes[1].is_passthrough(),
        "B's safe recipe survives"
    );
    let reason = &selection.recipes[0].adjustments.last().unwrap().reason;
    assert_eq!(
        reason,
        &Reason::DetectionChanged {
            missing: 1,
            extra: 0
        }
    );
}

#[test]
fn c5_recipe_that_adds_an_alert_is_rolled_back() {
    // Dropping `f` breaks the exclusion of `not-f`: an alert appears that full data never raised.
    let selection = select(vec![drop("B", &["f"])]).unwrap();
    assert!(rolled_back(&selection, "B"));
    let reason = &selection.recipes[0].adjustments.last().unwrap().reason;
    assert_eq!(
        reason,
        &Reason::DetectionChanged {
            missing: 0,
            extra: 1
        }
    );
}

#[test]
fn c5_stateful_alert_shifted_by_another_template_rolls_back_the_source() {
    // Summarizing C makes event 6 instead of 5 the third s2 event. Both alerts are on template D,
    // which has no recipe, so the source-wide fallback must find C.
    let selection = select(vec![summarize("C"), drop("A", &["noise"])]).unwrap();
    assert!(selection.proof.holds());
    assert!(rolled_back(&selection, "C"));
    assert!(
        !selection.recipes[1].is_passthrough(),
        "other sources are untouched"
    );
    assert_eq!(selection.rounds, 2);
}

#[test]
fn c5_engine_failure_is_never_proven() {
    let result = select_proven(
        vec![drop("A", &["noise"])],
        &sample(),
        &FakeEngine { fail: true },
        |recipes| {
            Ok(FakePlane {
                recipes: recipes.to_vec(),
            })
        },
    );
    assert!(matches!(result, Err(ProofError::Engine(_))));
}

#[test]
fn prove_reports_volume_per_template() {
    let plane = FakePlane {
        recipes: vec![summarize("C")],
    };
    let proof = prove(&sample(), &FakeEngine { fail: false }, &plane).unwrap();
    assert_eq!(proof.total.events, 7);
    assert_eq!(proof.total.summarized, 1);
    assert_eq!(proof.per_template[&Some("C".into())].summarized, 1);
    assert_eq!(proof.per_template[&Some("D".into())].forwarded, 3);
}
