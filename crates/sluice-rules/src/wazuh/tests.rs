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
fn regex_and_pcre2_values_widen_to_a_present_field() {
    for (field, name) in [
        (r#"<field name="x">^4625$</field>"#, "x"),
        (r#"<field name="x">a\.b</field>"#, "x"),
        (r#"<field name="x" type="pcre2">admin</field>"#, "x"),
        (r"<srcip>10.0.0.0/8</srcip>", "srcip"),
    ] {
        let rules = parse(&format!(r#"<rule id="1" level="3">{field}</rule>"#));
        assert_eq!(
            only(&rules).prefilter,
            Predicate::present(name.into()),
            "{field}"
        );
    }
}

#[test]
fn negated_values_widen_fully() {
    // A negated match may also pass when the field is missing.
    let rules =
        parse(r#"<rule id="1" level="3"><field name="x" negate="yes">admin</field></rule>"#);
    assert_eq!(only(&rules).prefilter, Predicate::Always);
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
    // `&` is not a plain literal, so the condition widens to "x has a value".
    assert_eq!(only(&rules).prefilter, Predicate::present("x".into()));
    assert_eq!(only(&rules).fields, RequiredFields::known(["x".into()]));
}

#[test]
fn an_unreadable_file_fails_closed() {
    let rules = WazuhRules::parse(["<group><rule id=\"1\"></group>"]).unwrap();
    let opaque = only(&rules);
    assert_eq!(opaque.fields, RequiredFields::Unknown);
    assert_eq!(opaque.prefilter, Predicate::Always);
    assert_eq!(rules.problems().len(), 1);
}

#[test]
fn literal_text_reads_as_wazuh_reads_it() {
    // From the stock ruleset: markup-like regexes and bare ampersands are text to Wazuh.
    let rules = parse(
        r#"<group name="web,"><rule id="31104" level="6">
             <regex>"\S+ /\.\./|</\/\w+\>|\.\.\\|&&</regex>
             <description>Common web attack.</description>
           </rule></group>"#,
    );
    let rule = only(&rules);
    assert!(rule.matches_raw_text);
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
}

const DECODERS: &str = r#"
<decoder name="sshd"><program_name>^sshd</program_name></decoder>
<decoder name="sshd-success"><parent>sshd</parent><prematch>^Accepted</prematch></decoder>
<decoder name="web"><program_name>^apache2|^httpd</program_name></decoder>
<decoder name="json"><prematch>^{\s*"</prematch><plugin_decoder>JSON_Decoder</plugin_decoder></decoder>
"#;

const CHAIN: &str = r#"<group name="sshd,">
  <rule id="5700" level="0"><decoded_as>sshd</decoded_as></rule>
  <rule id="5716" level="5"><if_sid>5700</if_sid><match>^Failed</match></rule>
  <rule id="5720" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5716</if_matched_sid><same_source_ip />
  </rule>
  <rule id="9000" level="3"><if_sid>4242</if_sid><match>orphan</match></rule>
  <rule id="9100" level="3"><decoded_as>json</decoded_as><field name="x">y</field></rule>
</group>"#;

fn keywords(values: &[&str]) -> Predicate {
    Predicate::Keywords(sluice_core::predicate::KeywordTest {
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: false,
    })
}

#[test]
fn decoders_bound_rules_and_chains_pass_bounds_to_children() {
    let rules = WazuhRules::parse_with_decoders([CHAIN], [DECODERS]).unwrap();
    let by_id = |id: &str| {
        rules
            .requirements()
            .iter()
            .find(|r| r.rule.as_str() == format!("wazuh:{id}"))
            .unwrap()
    };
    // The root sees only lines whose program is sshd; its child inherits that.
    assert_eq!(by_id("5700").prefilter, keywords(&["sshd"]));
    assert_eq!(by_id("5716").prefilter, keywords(&["sshd"]));
    assert!(by_id("5716").matches_raw_text);
    // A missing parent adds nothing; a plugin decoder (JSON) bounds nothing.
    assert_eq!(by_id("9000").prefilter, Predicate::Always);
    assert!(matches!(by_id("9100").prefilter, Predicate::Field(_)));
}

#[test]
fn decoders_with_alternatives_and_parents_resolve_to_program_names() {
    let rules = WazuhRules::parse_with_decoders(
        [
            r#"<rule id="1" level="3"><decoded_as>web</decoded_as></rule>
            <rule id="2" level="3"><decoded_as>sshd-success</decoded_as></rule>"#,
        ],
        [DECODERS],
    )
    .unwrap();
    assert_eq!(
        rules.requirements()[0].prefilter,
        keywords(&["apache2", "httpd"])
    );
    // A child decoder's own literal prematch is the tighter bound.
    assert_eq!(rules.requirements()[1].prefilter, keywords(&["Accepted"]));
}

#[test]
fn categories_are_bounded_by_the_decoders_of_that_type() {
    let decoders = r#"
        <decoder name="ossec"><prematch>^ossec: </prematch><type>ossec</type></decoder>
        <decoder name="weird"><prematch>^\d+ x</prematch><type>odd</type></decoder>
    "#;
    let rules = WazuhRules::parse_with_decoders(
        [r#"<rule id="500" level="0"><category>ossec</category><decoded_as>ossec</decoded_as></rule>
            <rule id="501" level="3"><if_sid>500</if_sid><match>Agent started</match></rule>
            <rule id="9" level="3"><category>odd</category></rule>"#],
        [decoders],
    )
    .unwrap();
    let requirements = rules.requirements();
    assert_eq!(requirements[0].prefilter, keywords(&["ossec:"]));
    assert_eq!(
        requirements[1].prefilter,
        keywords(&["ossec:"]),
        "inherited"
    );
    assert_eq!(
        requirements[2].prefilter,
        Predicate::Always,
        "no literal to bound by"
    );
}

#[test]
fn decoders_bound_only_when_every_definition_does() {
    // The stock `su` decoder has two definitions; the second selects by a two-letter prematch.
    let decoders = r#"
        <decoder name="su"><program_name>^su$</program_name></decoder>
        <decoder name="su"><prematch>^SU \S+ \S+ </prematch></decoder>
        <decoder name="sudo"><program_name>^sudo</program_name></decoder>
        <decoder name="sudo"><prematch>^\S+\s+:</prematch></decoder>
    "#;
    let rules = WazuhRules::parse_with_decoders(
        [r#"<rule id="1" level="0"><decoded_as>su</decoded_as></rule>
            <rule id="2" level="0"><decoded_as>sudo</decoded_as></rule>"#],
        [decoders],
    )
    .unwrap();
    assert_eq!(rules.requirements()[0].prefilter, keywords(&["su", "SU"]));
    assert_eq!(rules.requirements()[1].prefilter, Predicate::Always);
}

#[test]
fn first_time_seen_reads_the_decoders_fts_names() {
    let decoders = r#"
        <decoder name="su"><program_name>^su$</program_name><fts>name, srcuser, location</fts></decoder>
        <decoder name="ids"><program_name>^snort</program_name><fts>name, id, srcip, hostname</fts></decoder>
    "#;
    let rule = r#"<rule id="10100" level="4"><if_group>authentication_success</if_group><if_fts /></rule>"#;
    let rules = WazuhRules::parse_with_decoders([rule], [decoders]).unwrap();
    let rule = only(&rules);
    assert!(rule.stateful);
    assert!(
        rule.matches_raw_text,
        "hostname comes from the syslog header"
    );
    assert_eq!(
        rule.fields,
        RequiredFields::known(["id".into(), "srcip".into(), "srcuser".into()])
    );
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
}

#[test]
fn first_time_seen_without_decoders_fails_closed() {
    let rules = parse(r#"<rule id="5403" level="4"><if_sid>5400</if_sid><if_fts /></rule>"#);
    assert_eq!(only(&rules).fields, RequiredFields::Unknown);
}
