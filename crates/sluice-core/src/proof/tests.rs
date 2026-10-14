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
    fn alerts_refs(&self, events: &[&Event]) -> Result<BTreeSet<Alert>, EngineError> {
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

/// A data plane that fails on one event.
struct Failing;

impl Reducer for Failing {
    fn reduce(&self, event: &Event) -> Result<Reduced, ReduceError> {
        Err(ReduceError(format!("event {}", event.id)))
    }
}

/// An engine that raises nothing on its first call and an alert on every later one: no recipe
/// set can make the forwarded data agree with the full data.
struct Flaky {
    calls: std::cell::Cell<u64>,
}

impl RuleEngine for Flaky {
    fn alerts_refs(&self, events: &[&Event]) -> Result<BTreeSet<Alert>, EngineError> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        Ok(events
            .iter()
            .take(usize::from(call > 0))
            .map(|e| Alert {
                rule: "flaky".into(),
                event: e.id,
            })
            .collect())
    }
}

#[test]
fn c5_a_data_plane_failure_is_never_proven() {
    let result = prove(&sample(), &FakeEngine { fail: false }, &Failing);
    assert!(matches!(result, Err(ProofError::Reduce(_))));
}

#[test]
fn c5_a_data_plane_that_cannot_be_built_is_never_proven() {
    let result = select_proven(
        vec![drop("A", &["noise"])],
        &sample(),
        &FakeEngine { fail: false },
        |_| Err::<FakePlane, _>(ProofError::Build("no".into())),
    );
    assert!(matches!(result, Err(ProofError::Build(_))));
}

#[test]
fn c5_a_non_deterministic_engine_is_reported_not_proven() {
    let result = select_proven(
        vec![drop("A", &["noise"])],
        &sample(),
        &Flaky {
            calls: std::cell::Cell::new(0),
        },
        |recipes| {
            Ok(FakePlane {
                recipes: recipes.to_vec(),
            })
        },
    );
    assert!(
        matches!(result, Err(ProofError::Inconsistent)),
        "{result:?}"
    );
}

#[test]
fn an_empty_sample_holds_trivially_with_no_volume() {
    let proof = prove(
        &[],
        &FakeEngine { fail: false },
        &FakePlane { recipes: vec![] },
    )
    .unwrap();
    assert!(proof.holds());
    assert_eq!(proof.full_alerts.len(), 0);
    assert_eq!(proof.total, Volume::default());
}

#[test]
fn pass_through_forwards_every_byte_and_proves() {
    let proof = prove(
        &sample(),
        &FakeEngine { fail: false },
        &FakePlane { recipes: vec![] },
    )
    .unwrap();
    assert!(proof.holds());
    assert_eq!(proof.total.bytes_in, proof.total.bytes_out);
    assert_eq!(proof.total.forwarded, proof.total.events);
    assert_eq!(proof.full_alerts, proof.forwarded_alerts);
}

#[test]
fn volume_counts_events_bytes_and_outcomes() {
    let mut volume = Volume::default();
    let body: serde_json::Map<String, Value> = [("a".to_owned(), json!(1))].into_iter().collect();
    volume.add(100, &Outcome::Forwarded(body));
    volume.add(50, &Outcome::Summarized);
    assert_eq!(
        volume,
        Volume {
            events: 2,
            forwarded: 1,
            summarized: 1,
            bytes_in: 150,
            bytes_out: 7, // {"a":1}
        }
    );
}

#[test]
fn rolling_back_keeps_the_guardrails_adjustments_and_adds_the_proof() {
    let mut recipe = drop("A", &["a"]);
    recipe.adjustments.push(Adjustment {
        contract: ContractRule::RareNeverCut,
        level: None,
        reason: Reason::NoRecipe,
    });
    let selection = select(vec![recipe]).unwrap();
    let adjustments = &selection.recipes[0].adjustments;
    assert_eq!(adjustments.len(), 2);
    assert_eq!(adjustments[0].reason, Reason::NoRecipe);
    assert_eq!(adjustments[1].contract, ContractRule::ProvenBeforeEnforced);
    assert_eq!(selection.recipes[0].drop_fields.len(), 0);
}

#[test]
fn already_passthrough_recipes_are_left_alone() {
    let selection = select(vec![
        EffectiveRecipe::passthrough("A".into()),
        drop("B", &["f"]),
    ])
    .unwrap();
    assert!(
        selection.recipes[0].adjustments.is_empty(),
        "nothing to roll back"
    );
    assert!(rolled_back(&selection, "B"));
}

#[test]
fn missing_and_extra_are_the_two_set_differences() {
    let plane = FakePlane {
        recipes: vec![drop("A", &["a"]), drop("B", &["f"])],
    };
    let proof = prove(&sample(), &FakeEngine { fail: false }, &plane).unwrap();
    let rules = |alerts: &BTreeSet<Alert>| -> Vec<String> {
        alerts.iter().map(|a| a.rule.to_string()).collect()
    };
    assert_eq!(rules(&proof.missing), ["has-a"]);
    assert_eq!(rules(&proof.extra), ["not-f"]);
    assert!(!proof.holds());
}

#[test]
fn c5_the_selection_never_needs_more_rounds_than_recipes_plus_one() {
    // Three unsafe recipes on three templates of one stateful source: each round rolls back
    // some, and the bound leaves room for the worst case.
    let selection = select(vec![drop("A", &["a"]), drop("B", &["f"]), summarize("C")]).unwrap();
    assert!(selection.proof.holds());
    assert!(selection.rounds <= 4, "{} rounds", selection.rounds);
}
