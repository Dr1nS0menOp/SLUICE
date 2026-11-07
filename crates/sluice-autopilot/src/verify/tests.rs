use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use sluice_core::alert::Alert;
use sluice_core::ids::{Engine, EventId, RuleId, TemplateId};

use super::*;

fn volume(events: u64, bytes_in: u64, bytes_out: u64) -> Volume {
    Volume {
        events,
        forwarded: events,
        summarized: 0,
        summaries: 0,
        bytes_in,
        bytes_out,
    }
}

fn fingerprint(rule: &str, digest: &str) -> RuleFingerprint {
    RuleFingerprint {
        rule: rule.to_owned(),
        requirements: format!("sha256:{digest}"),
    }
}

/// A plan of one source with templates `a` (halved by the plan) and `b` (counted), proven with
/// rules `sigma:r1` and `sigma:r2`.
fn plan_json() -> serde_json::Value {
    json!({
        "format": "sluice.plan/1",
        "sluice": "1.0.0",
        "proof": {"holds": true, "alerts_full": 2, "alerts_forwarded": 2,
                  "rules": {"Sigma": 2}, "rules_basis": "fetched"},
        "total": {"events": 20, "forwarded": 20, "summarized": 0, "summaries": 0,
                  "bytes_in": 2000, "bytes_out": 1000},
        "saved_by_mode": {"rules": 1000},
        "problems": [],
        "sources": [{
            "id": "s", "logsource": {}, "schema": "sigma",
            "templates": [
                {"id": "a", "pattern": "", "shape": {"kind": "keyset", "discriminators": [],
                 "paths": [], "variants": [[]]},
                 "volume": {"events": 10, "forwarded": 10, "summarized": 0, "summaries": 0,
                            "bytes_in": 1000, "bytes_out": 500},
                 "runs_in": ["pipeline"]},
                {"id": "b", "pattern": "", "shape": {"kind": "keyset", "discriminators": [],
                 "paths": [], "variants": [[]]},
                 "volume": {"events": 10, "forwarded": 10, "summarized": 0, "summaries": 0,
                            "bytes_in": 1000, "bytes_out": 500},
                 "count_instead": {"forward_when": "always", "keys": []},
                 "runs_in": ["pipeline"]}
            ]
        }],
        "rules": [
            {"rule": "sigma:r1", "requirements": "sha256:1"},
            {"rule": "sigma:r2", "requirements": "sha256:2"}
        ]
    })
}

fn plan() -> RecordedPlan {
    RecordedPlan::parse(&plan_json().to_string()).expect("the plan reads")
}

fn rules_then() -> Vec<RuleFingerprint> {
    vec![fingerprint("sigma:r1", "1"), fingerprint("sigma:r2", "2")]
}

fn alert(rule: &str, event: u64) -> Alert {
    Alert {
        rule: RuleId::of(Engine::Sigma, rule),
        event: EventId(event),
    }
}

/// A proof on a new sample where `a` saves `a_out` of 1000 bytes and 100 bytes fit no template.
fn proof(a_out: u64, forwarded_alerts: BTreeSet<Alert>) -> Proof {
    let full: BTreeSet<Alert> = [alert("r1", 1), alert("r2", 2)].into();
    let per_template = BTreeMap::from([
        (Some(TemplateId::new("a")), volume(10, 1000, a_out)),
        (Some(TemplateId::new("b")), volume(10, 1000, 500)),
        (None, volume(1, 100, 100)),
    ]);
    Proof {
        missing: full.difference(&forwarded_alerts).cloned().collect(),
        extra: forwarded_alerts.difference(&full).cloned().collect(),
        full_alerts: full,
        forwarded_alerts,
        total: volume(21, 2100, a_out + 600),
        per_template,
        removed: BTreeMap::new(),
    }
}

fn same_alerts() -> BTreeSet<Alert> {
    [alert("r1", 1), alert("r2", 2)].into()
}

fn check(
    plan: &RecordedPlan,
    rules: &[RuleFingerprint],
    basis: RulesBasis,
    proof: &Proof,
) -> Verification {
    verify(VerifyInput {
        plan,
        rules,
        basis,
        proof,
        unreduced: &[],
    })
}

#[test]
fn a_plan_whose_rules_and_alerts_are_unchanged_holds() {
    let outcome = check(
        &plan(),
        &rules_then(),
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::Holds, "{:?}", outcome.reasons);
    assert_eq!(outcome.reasons, Vec::<String>::new());
    assert!(outcome.rules.recorded);
    assert_eq!(
        outcome.rules,
        RuleChanges {
            recorded: true,
            ..RuleChanges::default()
        }
    );
    assert_eq!(outcome.templates, Vec::<TemplateDrift>::new());
}

#[test]
fn c5_alerts_that_differ_on_the_new_sample_mean_the_plan_does_not_hold() {
    let lost: BTreeSet<Alert> = [alert("r1", 1)].into();
    let outcome = check(
        &plan(),
        &rules_then(),
        RulesBasis::Fetched,
        &proof(500, lost),
    );
    assert_eq!(outcome.verdict, Verdict::DoesNotHold);
    assert_eq!(outcome.proof.missing, ["sigma:r2 on event #2"]);
    assert!(outcome.reasons[0].contains("a detection would change"));
}

#[test]
fn c5_a_plan_that_says_its_own_proof_failed_does_not_hold() {
    let mut json = plan_json();
    json["proof"]["holds"] = false.into();
    let failed = RecordedPlan::parse(&json.to_string()).expect("reads");
    let outcome = check(
        &failed,
        &rules_then(),
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::DoesNotHold);
}

#[test]
fn c3_a_rule_the_plan_was_not_proven_with_makes_it_out_of_date() {
    let mut now = rules_then();
    now.push(fingerprint("sigma:new", "3"));
    let outcome = check(
        &plan(),
        &now,
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::OutOfDate);
    assert_eq!(outcome.rules.added, ["sigma:new"]);
    assert!(outcome.reasons[0].contains("1 rule is new"));
}

#[test]
fn c3_a_rule_read_differently_makes_it_out_of_date() {
    let now = vec![
        fingerprint("sigma:r1", "1"),
        fingerprint("sigma:r2", "changed"),
    ];
    let outcome = check(
        &plan(),
        &now,
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::OutOfDate);
    assert_eq!(outcome.rules.changed, ["sigma:r2"]);
    assert_eq!(outcome.rules.added, Vec::<String>::new());
}

#[test]
fn a_rule_that_is_gone_is_harmless() {
    let now = vec![fingerprint("sigma:r1", "1")];
    let outcome = check(
        &plan(),
        &now,
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::Holds);
    assert_eq!(outcome.rules.removed, ["sigma:r2"]);
}

#[test]
fn c3_counting_with_rules_not_known_to_be_complete_is_out_of_date() {
    let outcome = check(
        &plan(),
        &rules_then(),
        RulesBasis::NotKnown,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::OutOfDate);
    assert!(outcome.reasons[0].contains("needs every rule"));

    let mut json = plan_json();
    json["sources"][0]["templates"][1]
        .as_object_mut()
        .expect("an object")
        .remove("count_instead");
    let removing_only = RecordedPlan::parse(&json.to_string()).expect("reads");
    let outcome = check(
        &removing_only,
        &rules_then(),
        RulesBasis::NotKnown,
        &proof(500, same_alerts()),
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Holds,
        "removals need no complete rules"
    );
}

#[test]
fn a_plan_that_does_not_record_its_rules_is_out_of_date() {
    let mut json = plan_json();
    json.as_object_mut().expect("an object").remove("rules");
    let old = RecordedPlan::parse(&json.to_string()).expect("a plan without rules still reads");
    let outcome = check(
        &old,
        &rules_then(),
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert_eq!(outcome.verdict, Verdict::OutOfDate);
    assert!(!outcome.rules.recorded);
    assert!(outcome.reasons[0].contains("does not record the rules"));
}

#[test]
fn another_plan_format_is_refused_with_who_wrote_it() {
    let mut json = plan_json();
    json["format"] = "sluice.plan/2".into();
    json["sluice"] = "2.0.0".into();
    let error = RecordedPlan::parse(&json.to_string()).expect_err("another format");
    assert_eq!(
        error,
        PlanReadError::OtherFormat {
            found: "sluice.plan/2".into(),
            by: "2.0.0".into()
        }
    );
    assert!(matches!(
        RecordedPlan::parse("{\"sources\": []}"),
        Err(PlanReadError::NotAPlan(_))
    ));
    assert!(matches!(
        RecordedPlan::parse("not json"),
        Err(PlanReadError::NotAPlan(_))
    ));
}

#[test]
fn fields_a_later_plan_of_the_same_format_adds_are_ignored() {
    let mut json = plan_json();
    json["a_field_added_later"] = json!({"anything": [1, 2]});
    json["sources"][0]["templates"][0]["also_new"] = true.into();
    assert_eq!(
        RecordedPlan::parse(&json.to_string()).expect("reads"),
        plan()
    );
}

#[test]
fn a_kind_of_event_whose_saving_fell_is_listed() {
    let outcome = check(
        &plan(),
        &rules_then(),
        RulesBasis::Fetched,
        &proof(900, same_alerts()),
    );
    assert_eq!(
        outcome.verdict,
        Verdict::Holds,
        "less saving is no reason against the plan"
    );
    assert_eq!(
        outcome.templates,
        [TemplateDrift {
            source: "s".into(),
            template: "a".into(),
            saved_percent_plan: 50.0,
            saved_percent_now: 10.0,
            events_now: 10,
        }]
    );
    assert!(outcome.savings.saved_percent_now < outcome.savings.saved_percent_plan);
}

#[test]
fn bytes_in_no_kind_of_event_the_plan_knows_are_counted_as_unknown() {
    let outcome = check(
        &plan(),
        &rules_then(),
        RulesBasis::Fetched,
        &proof(500, same_alerts()),
    );
    assert!((outcome.savings.unknown_percent_plan - 0.0).abs() < f64::EPSILON);
    assert!((outcome.savings.unknown_percent_now - 4.8).abs() < f64::EPSILON);
    assert_eq!(outcome.savings.absent_templates, 0);
}

#[test]
fn a_kind_of_event_without_events_in_the_new_sample_is_counted_as_absent() {
    let mut new = proof(500, same_alerts());
    new.per_template.remove(&Some(TemplateId::new("b")));
    let outcome = check(&plan(), &rules_then(), RulesBasis::Fetched, &new);
    assert_eq!(outcome.savings.absent_templates, 1);
}
