//! Protection tests: which claims applicable rules make, and what they allow (contract rule 3).

use std::collections::BTreeSet;

use super::*;
use crate::guard::tests::{eq, rule, template};
use crate::template::LineHeader;

fn fields(names: &[&str]) -> BTreeSet<FieldPath> {
    names.iter().map(|n| FieldPath::from(*n)).collect()
}

/// `allowed_drops` with fresh adjustment and condition lists.
fn drops(
    protection: &Protection<'_>,
    proposed: &[&str],
) -> (BTreeSet<FieldPath>, Vec<Adjustment>, Vec<Predicate>) {
    let (mut adjustments, mut conditions) = (Vec::new(), Vec::new());
    let allowed = protection.allowed_drops(&fields(proposed), &mut adjustments, &mut conditions);
    (allowed, adjustments, conditions)
}

/// `drop_empty_exceptions` with fresh lists.
fn empties(
    protection: &Protection<'_>,
) -> (Option<BTreeSet<FieldPath>>, Vec<Adjustment>, Vec<Predicate>) {
    let (mut adjustments, mut conditions) = (Vec::new(), Vec::new());
    let except = protection.drop_empty_exceptions(&mut adjustments, &mut conditions);
    (except, adjustments, conditions)
}

/// A rule bounded to events the 4625 template may or may not hold: `TargetUserName = admin`.
fn bounded(id: &str, reads: &[&str]) -> RuleRequirements {
    rule(id, reads, eq("TargetUserName", "admin"))
}

/// A rule whose pre-filter holds for every event of the 4625 template.
fn everywhere(id: &str, reads: &[&str]) -> RuleRequirements {
    rule(id, reads, eq("EventID", "4625"))
}

// ---------- of ----------

#[test]
fn c3_a_rule_claims_each_field_it_reads() {
    let reader = everywhere("r", &["IpAddress"]);
    let protection = Protection::of(&template(), &[&reader], true);
    let (allowed, adjustments, _) = drops(&protection, &["IpAddress", "Keywords"]);
    assert_eq!(allowed, fields(&["Keywords"]));
    assert!(matches!(
        &adjustments[..],
        [Adjustment { reason: Reason::FieldNeededByRule { field, .. }, .. }] if field.as_str() == "IpAddress"
    ));
}

#[test]
fn c3_a_bare_field_also_claims_its_nested_paths_in_the_template() {
    let mut nested = template();
    nested.fields = fields(&["EventData.ScriptBlockText", "EventData.Path", "EventID"]);
    let reader = everywhere("r", &["ScriptBlockText"]);
    let protection = Protection::of(&nested, &[&reader], true);
    let (allowed, _, _) = drops(&protection, &["EventData", "EventData.Path"]);
    assert_eq!(
        allowed,
        fields(&["EventData.Path"]),
        "the parent of a claimed path is kept"
    );
}

#[test]
fn c3_a_rule_with_unknown_fields_claims_every_field() {
    let mut reader = everywhere("r", &[]);
    reader.fields = RequiredFields::Unknown;
    let protection = Protection::of(&template(), &[&reader], true);
    let (allowed, adjustments, _) = drops(&protection, &["Keywords", "Message"]);
    assert_eq!(allowed.len(), 0);
    assert!(
        adjustments
            .iter()
            .all(|a| matches!(a.reason, Reason::AllFieldsNeededByRule { .. }))
    );
}

#[test]
fn c3_a_raw_text_rule_claims_the_templates_text_fields() {
    let mut reader = everywhere("r", &[]);
    reader.matches_raw_text = true;
    let protection = Protection::of(&template(), &[&reader], true);
    let (allowed, _, _) = drops(&protection, &["Message", "Keywords"]);
    assert_eq!(
        allowed,
        fields(&["Keywords"]),
        "Message is the template's text field"
    );
}

#[test]
fn c3_without_conditional_protection_every_claim_holds_everywhere() {
    let reader = bounded("r", &["IpAddress"]);
    let protection = Protection::of(&template(), &[&reader], false);
    let (allowed, _, conditions) = drops(&protection, &["IpAddress"]);
    assert_eq!(allowed.len(), 0);
    assert_eq!(conditions.len(), 0);
}

#[test]
fn c3_on_a_text_template_nothing_is_fixed_so_a_selective_rule_stays_conditional() {
    let mut text = template();
    text.shape = TemplateShape::Text {
        field: "Message".into(),
        header: LineHeader::None,
        tokens: vec!["x".into()],
    };
    // On the key-set template this rule holds everywhere (EventID is fixed to 4625).
    let reader = everywhere("r", &["IpAddress"]);
    let protection = Protection::of(&text, &[&reader], true);
    let (allowed, _, conditions) = drops(&protection, &["IpAddress"]);
    assert_eq!(allowed, fields(&["IpAddress"]));
    assert_eq!(conditions, [eq("EventID", "4625")]);
}

// ---------- allowed_drops ----------

#[test]
fn c3_a_field_claimed_only_by_bounded_rules_is_dropped_outside_their_prefilters() {
    let (a, b) = (bounded("a", &["IpAddress"]), bounded("b", &["IpAddress"]));
    let protection = Protection::of(&template(), &[&a, &b], true);
    let (allowed, adjustments, conditions) = drops(&protection, &["IpAddress"]);
    assert_eq!(allowed, fields(&["IpAddress"]));
    assert_eq!(conditions.len(), 2, "one condition per claiming rule");
    assert!(
        adjustments
            .iter()
            .all(|a| matches!(a.reason, Reason::KeptWhereRuleMayMatch { .. }))
    );
}

#[test]
fn c3_one_unbounded_claim_outweighs_any_number_of_bounded_ones() {
    let (a, b) = (
        bounded("a", &["IpAddress"]),
        everywhere("b", &["IpAddress"]),
    );
    let protection = Protection::of(&template(), &[&a, &b], true);
    let (allowed, adjustments, conditions) = drops(&protection, &["IpAddress"]);
    assert_eq!(allowed.len(), 0);
    assert_eq!(conditions.len(), 0);
    assert!(matches!(
        &adjustments[..],
        [Adjustment { reason: Reason::FieldNeededByRule { rule, .. }, .. }] if rule.as_str() == "b"
    ));
}

#[test]
fn c3_dropping_a_parent_or_a_child_of_a_claimed_field_is_refused() {
    let reader = everywhere("r", &["process.name"]);
    let protection = Protection::of(&template(), &[&reader], true);
    let (allowed, _, _) = drops(&protection, &["process", "process.name.raw", "processor"]);
    assert_eq!(
        allowed,
        fields(&["processor"]),
        "a sibling with a common prefix is free"
    );
}

#[test]
fn unclaimed_fields_are_dropped_without_conditions() {
    let protection = Protection::of(&template(), &[], true);
    let (allowed, adjustments, conditions) = drops(&protection, &["Keywords", "Message"]);
    assert_eq!(allowed, fields(&["Keywords", "Message"]));
    assert_eq!((adjustments.len(), conditions.len()), (0, 0));
}

#[test]
fn nothing_proposed_allows_nothing() {
    let reader = everywhere("r", &["IpAddress"]);
    let protection = Protection::of(&template(), &[&reader], true);
    let (allowed, adjustments, _) = drops(&protection, &[]);
    assert_eq!((allowed.len(), adjustments.len()), (0, 0));
}

// ---------- drop_empty_exceptions ----------

#[test]
fn c3_an_unbounded_rule_with_unknown_fields_forbids_dropping_empty_fields() {
    let mut reader = everywhere("r", &[]);
    reader.fields = RequiredFields::Unknown;
    let protection = Protection::of(&template(), &[&reader], true);
    let (except, adjustments, _) = empties(&protection);
    assert_eq!(except, None);
    assert!(matches!(
        &adjustments[..],
        [Adjustment {
            reason: Reason::AllFieldsNeededByRule { .. },
            ..
        }]
    ));
}

#[test]
fn c3_fields_claimed_everywhere_are_exempt_from_empty_field_removal() {
    let reader = everywhere("r", &["IpAddress", "LogonType"]);
    let protection = Protection::of(&template(), &[&reader], true);
    let (except, _, conditions) = empties(&protection);
    assert_eq!(except, Some(fields(&["IpAddress", "LogonType"])));
    assert_eq!(conditions.len(), 0);
}

#[test]
fn c3_bounded_claims_become_conditions_not_exceptions() {
    let mut reader = bounded("r", &[]);
    reader.fields = RequiredFields::Unknown;
    let protection = Protection::of(&template(), &[&reader], true);
    let (except, _, conditions) = empties(&protection);
    assert_eq!(except, Some(BTreeSet::new()));
    assert_eq!(conditions, [eq("TargetUserName", "admin")]);
}

#[test]
fn without_rules_every_empty_field_may_go() {
    let protection = Protection::of(&template(), &[], true);
    assert_eq!(empties(&protection).0, Some(BTreeSet::new()));
}
