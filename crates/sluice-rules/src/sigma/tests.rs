use sluice_core::rules::RequiredFields;

use super::*;

const BASE: &str = r"
title: Failed logon
id: 11111111-0000-4000-8000-000000000001
name: failed_logon
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
";

const CORRELATION: &str = r"
title: Failed logons from many addresses
id: 11111111-0000-4000-8000-000000000002
name: failed_logon_spread
correlation:
  type: value_count
  rules:
    - failed_logon
  group-by:
    - user
  aliases:
    user:
      failed_logon: TargetUserName
  timespan: 5m
  condition:
    gte: 3
    field: IpAddress
";

fn parse(documents: &[&str]) -> SigmaRules {
    SigmaRules::parse([documents.join("\n---\n").as_str()]).expect("valid YAML")
}

fn requirement<'a>(rules: &'a SigmaRules, id: &str) -> &'a RuleRequirements {
    rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == format!("sigma:{id}"))
        .unwrap_or_else(|| panic!("no requirement for {id}: {:?}", rules.requirements()))
}

const BASE_ID: &str = "11111111-0000-4000-8000-000000000001";

#[test]
fn a_rule_keeps_its_log_source_and_sigma_names() {
    let rules = parse(&[BASE]);
    let base = requirement(&rules, BASE_ID);
    assert_eq!(base.logsource.product.as_deref(), Some("windows"));
    assert_eq!(base.logsource.service.as_deref(), Some("security"));
    assert_eq!(base.logsource.category, None);
    assert!(!base.logsource.complete);
    assert_eq!(base.field_names, Some(Schema::Sigma));
    assert!(!base.stateful);
    assert_eq!(base.fields, RequiredFields::known(["EventID".into()]));
}

#[test]
fn c3_a_correlation_adds_its_group_by_through_aliases_and_its_value_field() {
    let rules = parse(&[BASE, CORRELATION]);
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
    let base = requirement(&rules, BASE_ID);
    assert!(base.stateful, "a correlation counts the base rule's events");
    assert_eq!(
        base.fields,
        RequiredFields::known([
            "EventID".into(),
            "IpAddress".into(),
            "TargetUserName".into()
        ])
    );
}

#[test]
fn c3_a_group_by_without_an_alias_is_read_by_its_own_name() {
    let plain = CORRELATION.replace(
        "  aliases:\n    user:\n      failed_logon: TargetUserName\n",
        "",
    );
    let rules = parse(&[BASE, &plain]);
    let base = requirement(&rules, BASE_ID);
    let RequiredFields::Known(fields) = &base.fields else {
        panic!("known fields expected");
    };
    assert!(fields.contains(&FieldPath::new("user")), "{fields:?}");
}

#[test]
fn c3_a_correlation_of_a_correlation_reaches_the_base_rule() {
    let outer = r"
title: Spread then more
id: 11111111-0000-4000-8000-000000000003
correlation:
  type: event_count
  rules:
    - failed_logon_spread
  group-by:
    - Workstation
  timespan: 1h
  condition:
    gte: 2
";
    let rules = parse(&[BASE, CORRELATION, outer]);
    let base = requirement(&rules, BASE_ID);
    let RequiredFields::Known(fields) = &base.fields else {
        panic!("known fields expected");
    };
    assert!(
        fields.contains(&FieldPath::new("Workstation")),
        "{fields:?}"
    );
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
}

#[test]
fn c3_a_correlation_of_a_rule_that_is_not_loaded_blocks_every_saving() {
    let rules = parse(&[CORRELATION]);
    assert_eq!(rules.problems().len(), 1, "{:?}", rules.problems());
    let opaque = requirement(&rules, "11111111-0000-4000-8000-000000000002");
    assert_eq!(opaque.fields, RequiredFields::Unknown);
    assert!(opaque.stateful && opaque.matches_raw_text);
}

#[test]
fn correlations_that_reference_each_other_end() {
    let a = r"
title: A
id: 11111111-0000-4000-8000-00000000000a
name: corr_a
correlation:
  type: event_count
  rules:
    - corr_b
  timespan: 1h
  condition:
    gte: 2
";
    let b = a
        .replace("title: A", "title: B")
        .replace("00a", "00b")
        .replace("name: corr_a", "name: corr_b")
        .replace("- corr_b", "- corr_a");
    let rules = parse(&[a, &b]);
    assert_eq!(rules.requirements().len(), 0, "{:?}", rules.requirements());
}

#[test]
fn names_cover_rules_and_correlations() {
    let rules = parse(&[BASE, CORRELATION]);
    let names = rules.names();
    assert_eq!(names[&rule_id(Some(BASE_ID), "")], "Failed logon");
    assert_eq!(
        names[&rule_id(Some("11111111-0000-4000-8000-000000000002"), "")],
        "Failed logons from many addresses"
    );
}

#[test]
fn rules_that_share_an_id_are_reported_and_each_protects_what_it_reads() {
    let copy = BASE
        .replace("Failed logon", "Failed logon, edited")
        .replace("EventID: 4625", "EventID: 4771");
    let rules = parse(&[BASE, &copy]);
    assert_eq!(
        rules.problems(),
        [Problem::new(
            ProblemKind::SharedId,
            Some(rule_id(Some(BASE_ID), "")),
            format!(
                "2 Sigma rules share the id sigma:{BASE_ID} (Failed logon; Failed logon, \
                 edited): the proof cannot tell their alerts apart; give each its own `id`"
            )
        )]
    );
    assert_eq!(rules.requirements().len(), 2, "both rules still count");
}

#[test]
fn a_rule_without_an_id_is_named_by_its_title() {
    assert_eq!(rule_id(None, "My rule").as_str(), "sigma:My rule");
    assert_eq!(rule_id(Some("x"), "My rule").as_str(), "sigma:x");
}

#[test]
fn rules_read_sigma_names_and_only_the_conventions_a_pipeline_maps_onto() {
    let plain = parse(&[BASE]);
    assert!(plain.reads(Schema::Sigma));
    assert!(!plain.reads(Schema::Ecs));
    assert!(!plain.reads(Schema::Undeclared));

    let ecs = SigmaPipeline::builtin(Schema::Ecs, "ecs_windows").expect("built in");
    let mapped = SigmaRules::parse_with([BASE], &[ecs]).expect("maps");
    assert!(mapped.reads(Schema::Sigma));
    assert!(mapped.reads(Schema::Ecs));
    assert!(!mapped.reads(Schema::Undeclared));
    let ecs_copy = mapped
        .requirements()
        .iter()
        .find(|r| r.field_names == Some(Schema::Ecs))
        .expect("a mapped requirement");
    assert_eq!(ecs_copy.rule, rule_id(Some(BASE_ID), ""));
}

#[test]
fn two_pipelines_for_one_convention_are_refused() {
    let one = SigmaPipeline::builtin(Schema::Ecs, "ecs_windows").expect("built in");
    let two = SigmaPipeline::builtin(Schema::Ecs, "ecs_windows").expect("built in");
    assert!(matches!(
        SigmaRules::parse_with([BASE], &[one, two]),
        Err(RulesError::SigmaPipeline(_))
    ));
}

#[test]
fn files_with_several_documents_and_several_files_all_load() {
    let rules = SigmaRules::parse([BASE, CORRELATION]).expect("valid");
    assert_eq!(
        rules.requirements().len(),
        1,
        "the correlation adds to its base"
    );
    assert_eq!(rules.names().len(), 2);
}

#[test]
fn c3_a_file_that_is_not_yaml_blocks_every_saving() {
    let rules = SigmaRules::parse(["title: [unclosed"]).expect("loads");
    assert_eq!(rules.problems().len(), 1);
    assert!(
        rules.problems()[0].message.contains("YAML"),
        "{:?}",
        rules.problems()
    );
    assert_eq!(
        rules.requirements(),
        [RuleRequirements::opaque(RuleId::new("sigma:unreadable:0"))]
    );
}

#[test]
fn a_filter_adds_its_fields_to_the_rules_it_names_only() {
    let other = BASE
        .replace(
            "11111111-0000-4000-8000-000000000001",
            "11111111-0000-4000-8000-0000000000ff",
        )
        .replace("name: failed_logon", "name: other_rule")
        .replace("title: Failed logon", "title: Other");
    let filter = r"
title: Not the system account
filter:
  rules:
    - failed_logon
  selection:
    SubjectUserName: SYSTEM
  condition: not selection
logsource:
  product: windows
  service: security
";
    // The named rule is not the first, so a lookup that ignores the name cannot pass.
    let rules = parse(&[&other, BASE, filter]);
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
    let RequiredFields::Known(filtered) = &requirement(&rules, BASE_ID).fields else {
        panic!("known fields expected");
    };
    assert!(
        filtered.contains(&FieldPath::new("SubjectUserName")),
        "{filtered:?}"
    );
    let RequiredFields::Known(untouched) =
        &requirement(&rules, "11111111-0000-4000-8000-0000000000ff").fields
    else {
        panic!("known fields expected");
    };
    assert!(
        !untouched.contains(&FieldPath::new("SubjectUserName")),
        "{untouched:?}"
    );
}

#[test]
fn c3_a_keyword_filter_makes_its_rules_read_every_field() {
    let filter = r"
title: Not the scanner
filter:
  rules:
    - failed_logon
  keywords:
    - nessus
  condition: not keywords
logsource:
  product: windows
  service: security
";
    let plain = parse(&[BASE]);
    assert!(!requirement(&plain, BASE_ID).matches_raw_text);
    let rules = parse(&[BASE, filter]);
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
    let base = requirement(&rules, BASE_ID);
    assert!(base.matches_raw_text);
    assert_eq!(base.fields, RequiredFields::Unknown);
}

#[test]
fn c3_a_fieldref_reads_the_field_it_compares_against() {
    let rule = BASE.replace("EventID: 4625", "TargetUserName|fieldref: SubjectUserName");
    let rules = parse(&[&rule]);
    let RequiredFields::Known(fields) = &requirement(&rules, BASE_ID).fields else {
        panic!("known fields expected");
    };
    assert!(
        fields.contains(&FieldPath::new("TargetUserName"))
            && fields.contains(&FieldPath::new("SubjectUserName")),
        "{fields:?}"
    );
}

#[test]
fn c3_an_unresolved_rule_deep_in_a_correlation_chain_is_reported() {
    let outer = r"
title: Outer
id: 11111111-0000-4000-8000-000000000004
correlation:
  type: event_count
  rules:
    - failed_logon_spread
  timespan: 1h
  condition:
    gte: 2
";
    // The inner correlation references a rule that is not loaded.
    let rules = parse(&[CORRELATION, outer]);
    assert_eq!(rules.problems().len(), 2, "{:?}", rules.problems());
    let outer = requirement(&rules, "11111111-0000-4000-8000-000000000004");
    assert_eq!(outer.fields, RequiredFields::Unknown);
}
