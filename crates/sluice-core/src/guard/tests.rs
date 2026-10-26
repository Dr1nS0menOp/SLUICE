//! Guardrail tests, one group per safety-contract rule. Test names start with the rule number.

use std::collections::BTreeSet;

use super::*;
use crate::logsource::LogSource;
use crate::predicate::{FieldTest, KeywordTest, MatchOp};
use crate::recipe::Provenance;
use crate::rules::RequiredFields;
use crate::schema::Schema;
use crate::template::{TemplateShape, TemplateStats};

pub(super) fn windows_security() -> LogSource {
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

pub(super) fn template() -> Template {
    Template {
        id: "win-4625".into(),
        source: "windows-security".into(),
        logsource: windows_security(),
        schema: Schema::Sigma,
        pattern: "4625 failed logon".into(),
        shape: TemplateShape::Keyset {
            discriminators: vec![("EventID".into(), "4625".into())],
            paths: FIELDS.into_iter().map(FieldPath::from).collect(),
            variants: vec![FIELDS.into_iter().map(FieldPath::from).collect()],
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

pub(super) fn eq(field: &str, value: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op: MatchOp::Equals,
        values: vec![value.into()],
        case_sensitive: false,
    })
}

pub(super) fn rule(id: &str, fields: &[&str], prefilter: Predicate) -> RuleRequirements {
    RuleRequirements {
        rule: id.into(),
        logsource: windows_security(),
        field_names: Some(Schema::Sigma),
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

pub(super) fn ctx(rules: &[RuleRequirements]) -> GuardContext<'_> {
    GuardContext {
        rules,
        config: GuardrailConfig::default(),
        archive_enabled: true,
        rules_complete: true,
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
        rules_complete: true,
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
fn c3_an_implied_value_a_rule_reads_stays_on_the_events_it_could_match() {
    use crate::recipe::{ImpliedValue, Literal};
    let implied = |field: &str, value: &str| ImpliedValue {
        field: field.into(),
        value: Literal::Text(value.into()),
        when: None,
    };
    let implied_values = recipe(vec![Reduction::DropImplied {
        values: vec![
            implied("Keywords", "Audit Failure"),
            implied("LogonType", "3"),
        ],
    }]);

    // A rule (or a logged query, which joins the inventory as one) over every 4625 reads
    // `Keywords`: that value stays; the other may go.
    let everywhere = [rule("q1", &["EventID", "Keywords"], eq("EventID", "4625"))];
    let effective = guard(&template(), Some(&implied_values), ctx(&everywhere));
    let fields: Vec<&str> = effective
        .drop_implied
        .iter()
        .map(|v| v.field.as_str())
        .collect();
    assert_eq!(fields, ["LogonType"]);
    assert!(matches!(
        &effective.adjustments[0].reason,
        Reason::FieldNeededByRule { field, .. } if field.as_str() == "Keywords"
    ));

    // One that matches only some of them: the value may go elsewhere, never on those.
    let selective = [rule("q2", &["Keywords"], eq("TargetUserName", "admin"))];
    let effective = guard(&template(), Some(&implied_values), ctx(&selective));
    assert_eq!(effective.drop_implied.len(), 2);
    assert_eq!(
        effective.keep_whole_when,
        Some(eq("TargetUserName", "admin"))
    );
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
fn c3_a_raw_text_rule_reads_every_field_of_a_json_record() {
    // Splunk's `_raw` of a JSON event is the whole object: a bare term such as `mimikatz` may
    // match a short value the text-field heuristic does not mark, such as an image path.
    let mut splunk = rule("splunk:kw", &["EventID"], Predicate::Always);
    splunk.matches_raw_text = true;
    let everything = recipe(vec![drop(&["LogonType"]), Reduction::DropEmptyFields]);
    let effective = guard(&template(), Some(&everything), ctx(&[splunk.clone()]));
    assert!(
        effective.drop_fields.is_empty(),
        "{:?}",
        effective.drop_fields
    );
    assert_eq!(effective.drop_empty_except, None);

    // Bounded by its terms, it keeps the events they may match whole and lets the rest go.
    splunk.prefilter = Predicate::Keywords(KeywordTest {
        values: vec!["mimikatz".into()],
        case_sensitive: false,
    });
    let one = recipe(vec![drop(&["LogonType"])]);
    let effective = guard(&template(), Some(&one), ctx(&[splunk.clone()]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["LogonType".into()]));
    assert_eq!(effective.keep_whole_when, Some(splunk.prefilter));
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
fn c3_a_bare_rule_field_protects_the_same_field_nested_in_a_table_column() {
    // Sentinel's WindowsEvent keeps a provider's data under `EventData`; Sigma names it bare.
    let paths = [
        "EventID",
        "EventData.ScriptBlockText",
        "EventData.Path",
        "Computer",
    ];
    let mut nested = template();
    nested.shape = TemplateShape::Keyset {
        discriminators: vec![("EventID".into(), "4104".into())],
        paths: paths.into_iter().map(FieldPath::from).collect(),
        variants: vec![paths.into_iter().map(FieldPath::from).collect()],
    };
    nested.fields = paths.into_iter().map(FieldPath::from).collect();
    let rule = rule(
        "script",
        &["ScriptBlockText"],
        Predicate::Field(FieldTest {
            field: "ScriptBlockText".into(),
            op: MatchOp::Contains,
            values: vec!["Invoke-Mimikatz".into()],
            case_sensitive: false,
        }),
    );
    for proposed in [&["EventData.ScriptBlockText"][..], &["EventData"][..]] {
        let effective = guard(
            &nested,
            Some(&recipe(vec![drop(proposed)])),
            ctx(std::slice::from_ref(&rule)),
        );
        assert_eq!(
            effective.keep_whole_when,
            Some(rule.prefilter.clone()),
            "{proposed:?}: events the rule may match keep the field"
        );
    }
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

// ---------- rule 3, field names (ADR 0018) ----------

/// An ECS template of the same kind of event: the data lives under other names than the rule's.
fn ecs_template() -> Template {
    let mut ecs = template();
    ecs.schema = Schema::Ecs;
    ecs
}

/// A Sigma rule on `Image`, a field the ECS template does not carry under that name.
fn image_rule() -> RuleRequirements {
    rule("image", &["Image"], eq("Image", "x"))
}

#[test]
fn c3_a_rule_in_another_naming_convention_keeps_everything_it_could_read() {
    let proposal = recipe(vec![
        drop(&["Message", "Keywords"]),
        Reduction::DropEmptyFields,
        forward_matching(),
    ]);
    let effective = guard(&ecs_template(), Some(&proposal), ctx(&[image_rule()]));
    assert!(effective.is_passthrough(), "{effective:?}");
    assert!(effective.adjustments.iter().any(|a| matches!(
        &a.reason,
        Reason::FieldNamesDiffer { rule, rules: 1, rule_names: Schema::Sigma, data_names: Schema::Ecs }
            if rule.as_str() == "image"
    )));
}

#[test]
fn c3_a_rule_mapped_onto_the_records_convention_is_used_instead_of_widened() {
    // The same rule mapped through an ECS pipeline (ADR 0020): it reads `process.executable`.
    let mut mapped = rule("image", &["process.name"], eq("process.name", "x"));
    mapped.field_names = Some(Schema::Ecs);
    let rules = [image_rule(), mapped];
    let proposal = recipe(vec![drop(&["Message", "Keywords"])]);
    let effective = guard(&ecs_template(), Some(&proposal), ctx(&rules));
    assert_eq!(
        effective.drop_fields,
        BTreeSet::from(["Keywords".into(), "Message".into()]),
        "the mapped copy reads neither field: {:?}",
        effective.adjustments
    );
    assert!(
        !effective
            .adjustments
            .iter()
            .any(|a| matches!(a.reason, Reason::FieldNamesDiffer { .. }))
    );
    // On records in Sigma's names, the original applies and the mapped copy stays out.
    let effective = guard(&template(), Some(&proposal), ctx(&rules));
    assert_eq!(
        effective.drop_fields,
        BTreeSet::from(["Keywords".into(), "Message".into()])
    );
}

#[test]
fn c3_a_mapped_copy_that_cannot_see_the_template_does_not_stand_in_for_the_rule() {
    // A pipeline that changes the log source (`change_logsource`) moves the mapped copy away
    // from these records, while the rule in Sigma's names may still see them: it is widened.
    let mut mapped = rule("image", &["process.name"], eq("process.name", "x"));
    mapped.field_names = Some(Schema::Ecs);
    mapped.logsource = LogSource {
        product: Some("linux".into()),
        ..LogSource::default()
    };
    let proposal = recipe(vec![drop(&["Message"])]);
    let effective = guard(
        &ecs_template(),
        Some(&proposal),
        ctx(&[image_rule(), mapped]),
    );
    assert!(effective.drop_fields.is_empty(), "{effective:?}");
}

#[test]
fn c3_many_rules_in_another_convention_give_one_reason() {
    let rules: Vec<RuleRequirements> = (0..500)
        .map(|n| rule(&format!("r{n}"), &["Image"], eq("Image", "x")))
        .collect();
    let proposal = recipe(vec![drop(&["Message"]), forward_matching()]);
    let effective = guard(&ecs_template(), Some(&proposal), ctx(&rules));
    assert!(effective.is_passthrough());
    let reasons: Vec<&Reason> = effective
        .adjustments
        .iter()
        .map(|a| &a.reason)
        .filter(|r| matches!(r, Reason::FieldNamesDiffer { .. }))
        .collect();
    assert!(
        matches!(
            reasons.as_slice(),
            [Reason::FieldNamesDiffer { rules: 500, .. }]
        ),
        "{reasons:?}"
    );
    assert!(
        effective.adjustments.len() < 10,
        "{:?}",
        effective.adjustments
    );
}

#[test]
fn c3_an_undeclared_source_is_treated_as_a_different_convention() {
    let mut undeclared = template();
    undeclared.schema = Schema::Undeclared;
    let proposal = recipe(vec![drop(&["Message"]), forward_matching()]);
    let effective = guard(&undeclared, Some(&proposal), ctx(&[image_rule()]));
    assert!(effective.is_passthrough());
    assert!(effective.adjustments.iter().any(|a| matches!(
        a.reason,
        Reason::FieldNamesDiffer {
            data_names: Schema::Undeclared,
            ..
        }
    )));
}

#[test]
fn c3_a_matching_convention_still_scopes_rules_by_what_the_template_carries() {
    // The Sigma template has no `Image`, so a Sigma rule on it cannot match: the cut stands.
    let proposal = recipe(vec![drop(&["Message"])]);
    let effective = guard(&template(), Some(&proposal), ctx(&[image_rule()]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));
    assert!(
        !effective
            .adjustments
            .iter()
            .any(|a| matches!(a.reason, Reason::FieldNamesDiffer { .. }))
    );
}

#[test]
fn c3_rules_that_relate_their_names_themselves_ignore_the_convention() {
    // Wazuh, Sentinel and operator rules declare no convention.
    let mut wazuh = image_rule();
    wazuh.field_names = None;
    wazuh.fields = RequiredFields::known([FieldPath::from("Keywords")]);
    wazuh.prefilter = eq("EventID", "4625");
    let proposal = recipe(vec![drop(&["Message", "Keywords"])]);
    let effective = guard(&ecs_template(), Some(&proposal), ctx(&[wazuh]));
    assert!(!effective.drop_fields.contains(&FieldPath::from("Keywords")));
    assert!(effective.drop_fields.contains(&FieldPath::from("Message")));
}

#[test]
fn c3_a_rule_in_another_convention_does_not_widen_what_its_log_source_excludes() {
    let mut sysmon = image_rule();
    sysmon.logsource.service = Some("sysmon".into());
    let proposal = recipe(vec![drop(&["Message"])]);
    let effective = guard(&ecs_template(), Some(&proposal), ctx(&[sysmon]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));
}

// ---------- rule 3, a complete rule inventory (ADR 0021) ----------

fn incomplete(rules: &[RuleRequirements]) -> GuardContext<'_> {
    GuardContext {
        rules_complete: false,
        ..ctx(rules)
    }
}

#[test]
fn c3_without_a_complete_inventory_nothing_is_summarized() {
    for routing in [
        forward_matching(),
        Reduction::Summarize {
            summary_keys: vec!["TargetUserName".into()],
        },
    ] {
        let level = routing.level();
        let proposal = recipe(vec![drop(&["Keywords"]), routing]);
        let effective = guard(&template(), Some(&proposal), incomplete(&[]));
        assert_eq!(effective.route, Route::ForwardAll, "{effective:?}");
        assert!(
            effective
                .adjustments
                .iter()
                .any(|a| a.reason == Reason::RulesNotComplete
                    && a.level == Some(level)
                    && a.contract == ContractRule::RuleMatchesForwarded)
        );
    }
}

#[test]
fn c3_without_a_complete_inventory_lossless_cuts_still_apply() {
    let proposal = recipe(vec![drop(&["Keywords"]), forward_matching()]);
    let effective = guard(&template(), Some(&proposal), incomplete(&[]));
    assert_eq!(effective.drop_fields, BTreeSet::from(["Keywords".into()]));
}

#[test]
fn c3_with_a_complete_inventory_the_same_proposal_is_routed() {
    let proposal = recipe(vec![forward_matching()]);
    let effective = guard(&template(), Some(&proposal), ctx(&[]));
    assert!(matches!(effective.route, Route::ForwardMatching { .. }));
    assert!(
        !effective
            .adjustments
            .iter()
            .any(|a| a.reason == Reason::RulesNotComplete)
    );
}

// ---------- rule 3, fields parsed out of text lines (ADR 0020) ----------

/// A raw text line, in the given convention: its fields exist only once the SIEM parses it.
fn text_template(schema: Schema) -> Template {
    let mut text = template();
    text.schema = schema;
    text.shape = TemplateShape::Text {
        field: "Message".into(),
        header: crate::template::LineHeader::None,
        tokens: vec!["x".into()],
    };
    text
}

fn keywords(value: &str) -> Predicate {
    Predicate::Keywords(KeywordTest {
        values: vec![value.into()],
        case_sensitive: false,
    })
}

fn parsed_from_text(effective: &EffectiveRecipe) -> Vec<usize> {
    effective
        .adjustments
        .iter()
        .filter_map(|a| match a.reason {
            Reason::FieldsParsedFromText { rules, .. } => Some(rules),
            _ => None,
        })
        .collect()
}

#[test]
fn c3_a_rule_testing_fields_keeps_every_text_line_it_could_see() {
    // A webserver rule on `cs-uri-query` over raw access log lines: the pre-filter can never
    // match the line, yet the SIEM's parser gives the rule its field.
    let proposal = recipe(vec![drop(&["Keywords"]), forward_matching()]);
    let effective = guard(
        &text_template(Schema::Undeclared),
        Some(&proposal),
        ctx(&[image_rule()]),
    );
    assert!(effective.is_passthrough(), "{effective:?}");
    assert_eq!(parsed_from_text(&effective), [1]);
    assert!(
        !effective
            .adjustments
            .iter()
            .any(|a| matches!(a.reason, Reason::FieldNamesDiffer { .. }))
    );
}

#[test]
fn c3_a_rule_testing_fields_keeps_text_lines_whatever_their_convention() {
    // Even a mapped copy in the line's own convention reads parsed fields: one rule, kept.
    let mut mapped = rule("image", &["process.name"], eq("process.name", "x"));
    mapped.field_names = Some(Schema::Ecs);
    let proposal = recipe(vec![forward_matching()]);
    let effective = guard(
        &text_template(Schema::Ecs),
        Some(&proposal),
        ctx(&[image_rule(), mapped]),
    );
    assert!(effective.is_passthrough(), "{effective:?}");
    assert_eq!(parsed_from_text(&effective), [1]);
}

#[test]
fn c3_a_keyword_rule_on_text_lines_is_compared_as_it_is() {
    let failed = rule("failed", &[], keywords("Failed password"));
    let proposal = recipe(vec![forward_matching()]);
    let effective = guard(
        &text_template(Schema::Undeclared),
        Some(&proposal),
        ctx(&[failed]),
    );
    assert_eq!(parsed_from_text(&effective), [0; 0]);
    assert!(
        matches!(&effective.route, Route::ForwardMatching { prefilter, .. }
            if *prefilter == Predicate::any([keywords("Failed password")])),
        "{effective:?}"
    );
}

#[test]
fn c3_a_field_the_siem_parses_from_a_text_line_does_not_bound_the_line() {
    // Wazuh's decoder gives the rule `Image` from the line, which the line itself lacks.
    let mut wazuh = image_rule();
    wazuh.field_names = None;
    let proposal = recipe(vec![forward_matching()]);
    let effective = guard(
        &text_template(Schema::Undeclared),
        Some(&proposal),
        ctx(&[wazuh.clone()]),
    );
    assert_eq!(parsed_from_text(&effective), [0; 0]);
    assert_eq!(effective.route, Route::ForwardAll, "{effective:?}");

    // Its decoder's program name, a keyword test, still bounds it there.
    wazuh.prefilter = Predicate::all([keywords("sshd"), eq("Image", "x")]);
    let effective = guard(
        &text_template(Schema::Undeclared),
        Some(&proposal),
        ctx(&[wazuh.clone()]),
    );
    assert!(
        matches!(&effective.route, Route::ForwardMatching { prefilter, .. }
            if *prefilter == keywords("sshd")),
        "{effective:?}"
    );

    // And it reads the line.
    let drops = recipe(vec![drop(&["Message"])]);
    wazuh.prefilter = eq("Image", "x");
    let effective = guard(
        &text_template(Schema::Undeclared),
        Some(&drops),
        ctx(&[wazuh]),
    );
    assert!(effective.drop_fields.is_empty(), "{effective:?}");
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

// ---------- the per-event test limit, and the order of refusals ----------

/// The 4625 template with `n` extra fields `F0`…, so `n` rules can each test their own field
/// (tests on one field merge into one).
fn wide_template(n: usize) -> Template {
    let mut wide = template();
    let extra: Vec<FieldPath> = (0..n).map(|i| FieldPath::new(format!("F{i}"))).collect();
    wide.fields.extend(extra.iter().cloned());
    if let TemplateShape::Keyset {
        paths, variants, ..
    } = &mut wide.shape
    {
        paths.extend(extra.iter().cloned());
        for variant in variants {
            variant.extend(extra.iter().cloned());
        }
    }
    wide
}

/// `n` rules, each reading `Message` on events whose own field `F<i>` is `x`.
fn many_rules(n: usize) -> Vec<RuleRequirements> {
    (0..n)
        .map(|i| rule(&format!("r{i}"), &["Message"], eq(&format!("F{i}"), "x")))
        .collect()
}

fn too_broad(effective: &EffectiveRecipe) -> bool {
    effective
        .adjustments
        .iter()
        .any(|a| matches!(a.reason, Reason::ProtectionTooBroad { .. }))
}

#[test]
fn c3_a_route_of_exactly_256_tests_is_still_checked_per_event() {
    let rules = many_rules(MAX_DATA_PLANE_TESTS);
    let effective = guard(
        &wide_template(300),
        Some(&recipe(vec![forward_matching()])),
        ctx(&rules),
    );
    assert!(
        matches!(&effective.route, Route::ForwardMatching { prefilter, .. } if prefilter.tests() == 256)
    );
    assert!(!too_broad(&effective));
}

#[test]
fn c3_a_route_of_257_tests_forwards_everything() {
    let rules = many_rules(MAX_DATA_PLANE_TESTS + 1);
    let effective = guard(
        &wide_template(300),
        Some(&recipe(vec![forward_matching()])),
        ctx(&rules),
    );
    assert_eq!(effective.route, Route::ForwardAll);
    assert!(too_broad(&effective));
}

#[test]
fn c3_conditional_protection_of_257_tests_keeps_the_field_on_every_event() {
    let rules = many_rules(MAX_DATA_PLANE_TESTS + 1);
    let effective = guard(
        &wide_template(300),
        Some(&recipe(vec![drop(&["Message"])])),
        ctx(&rules),
    );
    assert_eq!(effective.drop_fields.len(), 0);
    assert_eq!(effective.keep_whole_when, None);
    assert!(too_broad(&effective));
}

#[test]
fn c3_conditional_protection_of_256_tests_drops_the_field_outside_them() {
    let rules = many_rules(MAX_DATA_PLANE_TESTS);
    let effective = guard(
        &wide_template(300),
        Some(&recipe(vec![drop(&["Message"])])),
        ctx(&rules),
    );
    assert_eq!(effective.drop_fields, BTreeSet::from(["Message".into()]));
    assert_eq!(
        effective.keep_whole_when.as_ref().map(Predicate::tests),
        Some(256)
    );
}

#[test]
fn c2_without_an_archive_a_rare_template_is_refused_for_the_archive_first() {
    let mut rare = template();
    rare.stats.events = 1;
    let context = GuardContext {
        archive_enabled: false,
        ..ctx(&[])
    };
    let effective = guard(&rare, Some(&recipe(vec![drop(&["Message"])])), context);
    assert_eq!(contracts(&effective), [ContractRule::ArchiveFirst]);
}

#[test]
fn every_reduction_of_a_refused_recipe_gets_its_own_adjustment() {
    let mut rare = template();
    rare.stats.events = 1;
    let proposal = recipe(vec![
        drop(&["Message"]),
        Reduction::DropEmptyFields,
        forward_matching(),
    ]);
    let effective = guard(&rare, Some(&proposal), ctx(&[]));
    let levels: Vec<Option<Level>> = effective.adjustments.iter().map(|a| a.level).collect();
    assert_eq!(
        levels,
        [
            Some(Level::Lossless),
            Some(Level::Lossless),
            Some(Level::RuleGuided)
        ]
    );
}

#[test]
fn repeated_adjustments_are_reported_once_in_their_first_order() {
    let mut adjustments = vec![
        Adjustment {
            contract: ContractRule::RareNeverCut,
            level: None,
            reason: Reason::NoRecipe,
        },
        Adjustment {
            contract: ContractRule::ArchiveFirst,
            level: None,
            reason: Reason::NoArchive,
        },
        Adjustment {
            contract: ContractRule::RareNeverCut,
            level: None,
            reason: Reason::NoRecipe,
        },
    ];
    dedup(&mut adjustments);
    let reasons: Vec<&Reason> = adjustments.iter().map(|a| &a.reason).collect();
    assert_eq!(reasons, [&Reason::NoRecipe, &Reason::NoArchive]);
}

#[test]
fn c3_semantic_summaries_without_applicable_rules_summarize_everything() {
    let proposal = recipe(vec![Reduction::Summarize {
        summary_keys: vec!["TargetUserName".into()],
    }]);
    let effective = guard(&template(), Some(&proposal), ctx(&[]));
    assert!(
        matches!(&effective.route, Route::ForwardMatching { prefilter, .. } if prefilter.is_never())
    );
    assert!(
        !effective
            .adjustments
            .iter()
            .any(|a| a.reason == Reason::SemanticOnCoveredTemplate),
        "no rule covers it"
    );
}
