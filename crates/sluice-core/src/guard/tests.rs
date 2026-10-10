//! Guardrail tests, one group per safety-contract rule. Test names start with the rule number.

use std::collections::BTreeSet;

use super::*;
use crate::logsource::LogSource;
use crate::predicate::{FieldTest, KeywordTest, MatchOp};
use crate::recipe::Provenance;
use crate::rules::RequiredFields;
use crate::template::{TemplateShape, TemplateStats};

fn windows_security() -> LogSource {
    LogSource {
        product: Some("windows".into()),
        service: Some("security".into()),
        category: None,
        complete: false,
    }
}

/// The leaf paths of every event of the test template.
const FIELDS: [&str; 7] = [
    "EventID",
    "TargetUserName",
    "IpAddress",
    "Message",
    "Keywords",
    "LogonType",
    "process.name",
];

fn template() -> Template {
    Template {
        id: "win-4625".into(),
        source: "windows-security".into(),
        logsource: windows_security(),
        pattern: "4625 failed logon".into(),
        shape: TemplateShape::Keyset {
            discriminators: vec![("EventID".into(), "4625".into())],
            paths: FIELDS.into_iter().map(FieldPath::from).collect(),
        },
        fields: FIELDS.into_iter().map(FieldPath::from).collect(),
        text_fields: BTreeSet::from(["Message".into()]),
        stats: TemplateStats {
            events: 50_000,
            bytes: 50_000_000,
            source_events: 100_000,
        },
    }
}

fn eq(field: &str, value: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op: MatchOp::Equals,
        values: vec![value.into()],
        case_sensitive: false,
    })
}

fn rule(id: &str, fields: &[&str], prefilter: Predicate) -> RuleRequirements {
    RuleRequirements {
        rule: id.into(),
        logsource: windows_security(),
        fields: RequiredFields::known(fields.iter().copied().map(FieldPath::from)),
        matches_raw_text: false,
        stateful: false,
        text_lines_only: false,
        prefilter,
    }
}

fn recipe(reductions: Vec<Reduction>) -> Recipe {
    Recipe::new("win-4625".into(), reductions, Provenance::Operator, "test").unwrap()
}

fn drop(fields: &[&str]) -> Reduction {
    Reduction::DropFields {
        fields: fields.iter().copied().map(FieldPath::from).collect(),
    }
}

fn forward_matching() -> Reduction {
    Reduction::ForwardMatching {
        summary_keys: vec!["TargetUserName".into(), "IpAddress".into()],
    }
}

fn ctx(rules: &[RuleRequirements]) -> GuardContext<'_> {
    GuardContext {
        rules,
        config: GuardrailConfig::default(),
        archive_enabled: true,
    }
}

fn contracts(effective: &EffectiveRecipe) -> Vec<ContractRule> {
    effective.adjustments.iter().map(|a| a.contract).collect()
}

// ---------- rule 1: unknown data passes through untouched ----------

#[test]
fn c1_template_without_recipe_passes_through() {
    let effective = guard(&template(), None, ctx(&[]));
    assert!(effective.is_passthrough());
    assert_eq!(contracts(&effective), [ContractRule::UnknownPassesThrough]);
}

// ---------- rule 2: archive before any cut ----------

#[test]
fn c2_without_archive_nothing_is_cut() {
    let recipe = recipe(vec![drop(&["Message"]), Reduction::DropEmptyFields]);
    let context = GuardContext {
        archive_enabled: false,
        ..ctx(&[])
    };
    let effective = guard(&template(), Some(&recipe), context);
    assert!(effective.is_passthrough());
    assert_eq!(contracts(&effective), [ContractRule::ArchiveFirst; 2]);
}

// ---------- rule 3: anything a rule could match is forwarded in full ----------

#[test]
fn c3_fields_referenced_by_rules_are_never_dropped() {
    let rules = [rule(
        "r1",
        &["EventID", "TargetUserName"],
        eq("EventID", "4625"),
    )];
    let recipe = recipe(vec![drop(&["TargetUserName", "Keywords"])]);
    let effective = guard(&template(), Some(&recipe), ctx(&rules));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Keywords".into()]));
    assert!(matches!(
        &effective.adjustments[0].reason,
        Reason::FieldNeededByRule { field, .. } if field.as_str() == "TargetUserName"
    ));
}

#[test]
fn c3_parent_and_child_of_a_referenced_field_are_kept() {
    // The rule covers every event of the template (its EventID), so its claim holds everywhere.
    let rules = [rule("r1", &["process.name"], eq("EventID", "4625"))];
    let recipe = recipe(vec![drop(&["process", "process.name.raw", "other"])]);
    let effective = guard(&template(), Some(&recipe), ctx(&rules));
    assert_eq!(effective.drop_fields, BTreeSet::from(["other".into()]));
    assert_eq!(effective.keep_whole_when, None);
}

#[test]
fn c3_events_a_selective_rule_could_match_are_kept_whole() {
    // The rule matches only some events of the template, so its field may go elsewhere.
    let rules = [rule("r1", &["process.name"], eq("process.name", "x"))];
    let drops = recipe(vec![drop(&["process", "other"])]);
    let effective = guard(&template(), Some(&drops), ctx(&rules));
    assert_eq!(
        effective.drop_fields,
        BTreeSet::from(["other".into(), "process".into()])
    );
    assert_eq!(effective.keep_whole_when, Some(eq("process.name", "x")));

    // A keyword rule over all data, like SigmaHQ's mimikatz keywords: its fields are unknown,
    // so every event it could match is kept whole and the rest lose Message.
    let mut keywords = rule("kw", &[], Predicate::Always);
    keywords.fields = RequiredFields::Unknown;
    keywords.matches_raw_text = true;
    keywords.prefilter = Predicate::Keywords(KeywordTest {
        values: vec!["sekurlsa::".into()],
        case_sensitive: false,
    });
    let effective = guard(
        &template(),
        Some(&recipe(vec![drop(&["Message"])])),
        ctx(&[keywords.clone()]),
    );
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));
    assert_eq!(effective.keep_whole_when, Some(keywords.prefilter));
}

#[test]
fn c3_empty_fields_referenced_by_rules_are_kept() {
    let rules = [rule("r1", &["IpAddress"], eq("EventID", "4625"))];
    let recipe = recipe(vec![Reduction::DropEmptyFields]);
    let effective = guard(&template(), Some(&recipe), ctx(&rules));
    assert_eq!(
        effective.drop_empty_except,
        Some(BTreeSet::from(["IpAddress".into()]))
    );
}

#[test]
fn c3_raw_text_rule_keeps_text_fields() {
    let mut keyword_rule = rule("kw", &[], Predicate::Always);
    keyword_rule.matches_raw_text = true;
    let recipe = recipe(vec![drop(&["Message"])]);
    let effective = guard(&template(), Some(&recipe), ctx(&[keyword_rule]));
    assert!(effective.drop_fields.is_empty());
}

#[test]
fn c3_a_rule_for_another_event_id_protects_nothing_here() {
    // Zerologon-style: an EventID selection and keywords. It cannot fire on 4625 events.
    let mut other = rule("other", &[], eq("EventID", "5805"));
    other.matches_raw_text = true;
    other.fields = RequiredFields::Unknown;
    let recipe = recipe(vec![drop(&["Message"])]);
    let effective = guard(&template(), Some(&recipe), ctx(&[other.clone()]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));

    // The same rule on its own event ID keeps every field.
    other.prefilter = eq("EventID", "4625");
    let effective = guard(&template(), Some(&recipe), ctx(&[other]));
    assert!(effective.drop_fields.is_empty());
}

#[test]
fn c3_a_text_lines_only_rule_protects_nothing_in_json_but_everything_in_text() {
    // A Wazuh `<match>` rule under a syslog program-name decoder, such as `pam`.
    let mut syslog = rule("pam", &[], Predicate::Always);
    syslog.matches_raw_text = true;
    syslog.fields = RequiredFields::Unknown;
    syslog.text_lines_only = true;
    let drops = recipe(vec![drop(&["Message"])]);
    let effective = guard(&template(), Some(&drops), ctx(&[syslog.clone()]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));

    // On a text template the same rule applies and keeps the line.
    let mut text = template();
    text.shape = TemplateShape::Text {
        field: "Message".into(),
        header: crate::template::LineHeader::None,
        tokens: vec!["x".into()],
    };
    let effective = guard(&text, Some(&drops), ctx(&[syslog]));
    assert!(effective.drop_fields.is_empty());
}

#[test]
fn c3_rule_guided_forwards_union_of_rule_prefilters() {
    let rules = [
        rule("r1", &["EventID"], eq("EventID", "4625")),
        rule("r2", &["LogonType"], eq("LogonType", "10")),
    ];
    let effective = guard(
        &template(),
        Some(&recipe(vec![forward_matching()])),
        ctx(&rules),
    );
    let Route::ForwardMatching { prefilter, .. } = effective.route else {
        panic!("expected rule-guided route, got {:?}", effective.route);
    };
    assert_eq!(
        prefilter,
        Predicate::any([eq("EventID", "4625"), eq("LogonType", "10")])
    );
}

#[test]
fn c3_stateful_rule_keeps_every_event_it_could_count() {
    let mut burst = rule("burst", &["TargetUserName"], eq("EventID", "4625"));
    burst.stateful = true;
    let effective = guard(
        &template(),
        Some(&recipe(vec![forward_matching()])),
        ctx(&[burst]),
    );
    // Every event the correlation could count is forwarded; the rest may be summarized (ADR 0004).
    assert_eq!(
        effective.route,
        Route::ForwardMatching {
            prefilter: eq("EventID", "4625"),
            summary_keys: vec!["TargetUserName".into(), "IpAddress".into()],
        }
    );
}

#[test]
fn c3_unbounded_stateful_rule_forwards_everything() {
    let mut frequency = rule("frequency", &["srcip"], Predicate::Always);
    frequency.stateful = true;
    let effective = guard(
        &template(),
        Some(&recipe(vec![forward_matching()])),
        ctx(&[frequency]),
    );
    assert_eq!(effective.route, Route::ForwardAll);
}

#[test]
fn c3_unbounded_rule_forwards_everything() {
    let rules = [rule("wide", &["EventID"], Predicate::Always)];
    let effective = guard(
        &template(),
        Some(&recipe(vec![forward_matching()])),
        ctx(&rules),
    );
    assert_eq!(effective.route, Route::ForwardAll);
}

#[test]
fn c3_opaque_rule_blocks_every_cut() {
    let rules = [RuleRequirements::opaque("unparsed".into())];
    let recipe = recipe(vec![
        drop(&["Message", "Keywords"]),
        Reduction::DropEmptyFields,
        forward_matching(),
    ]);
    let effective = guard(&template(), Some(&recipe), ctx(&rules));
    assert!(effective.is_passthrough());
}

#[test]
fn c3_rule_with_unknown_fields_blocks_unrelated_drops() {
    let mut rule = rule("dynamic", &[], eq("EventID", "4625"));
    rule.fields = RequiredFields::Unknown;
    let effective = guard(
        &template(),
        Some(&recipe(vec![drop(&["Keywords"])])),
        ctx(&[rule]),
    );
    assert!(effective.drop_fields.is_empty());
    assert!(matches!(
        effective.adjustments[0].reason,
        Reason::AllFieldsNeededByRule { .. }
    ));
}

#[test]
fn c3_rules_for_other_sources_do_not_constrain() {
    let mut sysmon = rule("sysmon", &["Message"], Predicate::Always);
    sysmon.logsource.service = Some("sysmon".into());
    sysmon.stateful = true;
    let recipe = recipe(vec![drop(&["Message"]), forward_matching()]);
    let effective = guard(&template(), Some(&recipe), ctx(&[sysmon]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));
    assert_eq!(
        effective.route,
        Route::ForwardMatching {
            prefilter: Predicate::never(),
            summary_keys: vec!["TargetUserName".into(), "IpAddress".into()],
        }
    );
}

#[test]
fn c3_semantic_on_rule_covered_template_becomes_rule_guided() {
    let rules = [rule("r1", &["EventID"], eq("EventID", "4625"))];
    let summarize = Reduction::Summarize {
        summary_keys: vec!["IpAddress".into()],
    };
    let effective = guard(&template(), Some(&recipe(vec![summarize])), ctx(&rules));
    assert_eq!(
        effective.route,
        Route::ForwardMatching {
            prefilter: eq("EventID", "4625"),
            summary_keys: vec!["IpAddress".into()],
        }
    );
    assert!(matches!(
        effective.adjustments[0].reason,
        Reason::SemanticOnCoveredTemplate
    ));
}

// ---------- rule 4: rare is never cut ----------

#[test]
fn c4_template_below_event_floor_is_never_cut() {
    let mut rare = template();
    rare.stats.events = 99;
    let effective = guard(&rare, Some(&recipe(vec![drop(&["Message"])])), ctx(&[]));
    assert!(effective.is_passthrough());
    assert_eq!(contracts(&effective), [ContractRule::RareNeverCut]);
}

#[test]
fn c4_template_below_share_floor_is_never_cut() {
    let mut rare = template();
    rare.stats.events = 999;
    rare.stats.source_events = 1_000_000; // 0.0999 % < 0.1 %
    let effective = guard(&rare, Some(&recipe(vec![drop(&["Message"])])), ctx(&[]));
    assert!(effective.is_passthrough());
}

#[test]
fn c4_template_at_both_floors_may_be_cut() {
    let mut frequent = template();
    frequent.stats.events = 1_000;
    frequent.stats.source_events = 1_000_000; // exactly 0.1 %
    let effective = guard(&frequent, Some(&recipe(vec![drop(&["Message"])])), ctx(&[]));
    assert!(!effective.is_passthrough());
}

// ---------- rule 6: AI proposes; guardrails decide ----------

#[test]
fn c6_ai_recipe_gets_no_extra_trust() {
    let rules = [rule("r1", &["TargetUserName"], eq("EventID", "4625"))];
    let ai = Recipe::new(
        "win-4625".into(),
        vec![drop(&["TargetUserName"])],
        Provenance::Ai {
            model: "any".into(),
        },
        "the model claims this is noise",
    )
    .unwrap();
    let effective = guard(&template(), Some(&ai), ctx(&rules));
    assert!(effective.drop_fields.is_empty());
}
