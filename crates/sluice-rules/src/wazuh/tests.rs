use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::rules::{RequiredFields, RuleRequirements};

use super::WazuhRules;

fn parse(rules: &str) -> WazuhRules {
    WazuhRules::parse([format!("<group name=\"t,\">{rules}</group>").as_str()]).unwrap()
}

fn only(rules: &WazuhRules) -> &RuleRequirements {
    assert_eq!(rules.requirements().len(), 1);
    &rules.requirements()[0]
}

#[test]
fn literal_field_becomes_contains_test() {
    let rules =
        parse(r#"<rule id="1" level="3"><field name="win.eventdata.user">admin</field></rule>"#);
    let rule = only(&rules);
    assert_eq!(rule.rule.as_str(), "wazuh:1");
    assert_eq!(
        rule.prefilter,
        Predicate::Field(FieldTest {
            field: "win.eventdata.user".into(),
            op: MatchOp::Contains,
            values: vec!["admin".into()],
            case_sensitive: false,
        })
    );
    assert_eq!(
        rule.fields,
        RequiredFields::known(["win.eventdata.user".into()])
    );
    assert!(!rule.stateful && !rule.matches_raw_text);
}

#[test]
fn regex_negated_and_pcre2_values_widen() {
    for field in [
        r#"<field name="x">^4625$</field>"#,
        r#"<field name="x">a\.b</field>"#,
        r#"<field name="x" negate="yes">admin</field>"#,
        r#"<field name="x" type="pcre2">admin</field>"#,
        r"<srcip>10.0.0.0/8</srcip>",
    ] {
        let rules = parse(&format!(r#"<rule id="1" level="3">{field}</rule>"#));
        assert_eq!(only(&rules).prefilter, Predicate::Always, "{field}");
    }
}

#[test]
fn frequency_and_same_options_make_rules_stateful() {
    let rules = parse(
        r#"<rule id="2" level="10" frequency="8" timeframe="120">
             <if_matched_sid>1</if_matched_sid>
             <same_field>TargetUserName</same_field>
             <same_source_ip />
           </rule>"#,
    );
    let rule = only(&rules);
    assert!(rule.stateful);
    assert_eq!(
        rule.fields,
        RequiredFields::known(["TargetUserName".into(), "srcip".into()])
    );
    // No own conditions: the rule could fire on anything its parent matches.
    assert_eq!(rule.prefilter, Predicate::Always);
}

#[test]
fn raw_log_matching_needs_raw_text() {
    let rules = parse(r#"<rule id="3" level="5"><match>Failed password</match></rule>"#);
    let rule = only(&rules);
    assert!(rule.matches_raw_text);
    assert_eq!(rule.prefilter, Predicate::Always);
}

#[test]
fn unknown_tags_fail_closed_and_are_reported() {
    let rules = parse(r#"<rule id="4" level="5"><brand_new_option>x</brand_new_option></rule>"#);
    let rule = only(&rules);
    assert_eq!(rule.fields, RequiredFields::Unknown);
    assert!(rule.matches_raw_text);
    assert_eq!(rules.problems().len(), 1);
}

#[test]
fn rule_without_id_is_opaque() {
    let rules = parse(r#"<rule level="5"><match>x</match></rule>"#);
    assert_eq!(
        only(&rules),
        &RuleRequirements::opaque("wazuh:unknown:0".into())
    );
}

#[test]
fn entities_are_decoded() {
    let rules = parse(r#"<rule id="5" level="5"><field name="x">a&amp;b</field></rule>"#);
    // `&` is not a plain literal, so the condition widens, but the field is still read.
    assert_eq!(only(&rules).prefilter, Predicate::Always);
    assert_eq!(only(&rules).fields, RequiredFields::known(["x".into()]));
}

#[test]
fn malformed_xml_is_an_error() {
    assert!(WazuhRules::parse(["<group><rule id=\"1\"></group>"]).is_err());
}
