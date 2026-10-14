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
fn c3_a_raw_text_rule_reads_the_whole_json_line() {
    // `<match>` sees keys too: dropping an empty `ErrorCode` field silences rule 1002.
    let rules = parse(r#"<rule id="1002" level="2"><match>error|failure</match></rule>"#);
    assert_eq!(only(&rules).fields, RequiredFields::Unknown);

    // Under a syslog decoder the rule never sees JSON; on a text line it reads the line only.
    let rules = WazuhRules::parse_with_decoders([CHAIN], [DECODERS]).unwrap();
    let failed = rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == "wazuh:5716")
        .unwrap();
    assert!(failed.text_lines_only && failed.matches_raw_text);
    assert_eq!(failed.fields, RequiredFields::known([]));
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
        <decoder name="ids"><program_name>^snort</program_name><fts>name, id, srcip</fts></decoder>
    "#;
    let rule = r#"<rule id="10100" level="4"><if_group>authentication_success</if_group><if_fts /></rule>"#;
    let rules = WazuhRules::parse_with_decoders([rule], [decoders]).unwrap();
    let first = only(&rules);
    assert!(first.stateful && !first.matches_raw_text);
    assert_eq!(
        first.fields,
        RequiredFields::known(["id".into(), "srcip".into(), "srcuser".into()])
    );
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());

    // `hostname` comes from the syslog header: raw text, so on JSON every field is kept.
    let with_host = decoders.replace("srcip</fts>", "srcip, hostname</fts>");
    let rules = WazuhRules::parse_with_decoders([rule], [with_host.as_str()]).unwrap();
    assert!(only(&rules).matches_raw_text);
    assert_eq!(only(&rules).fields, RequiredFields::Unknown);
}

#[test]
fn rules_under_program_name_decoders_only_see_text_lines() {
    let rules = WazuhRules::parse_with_decoders([CHAIN], [DECODERS]).unwrap();
    let text_only = |id: &str| {
        rules
            .requirements()
            .iter()
            .find(|r| r.rule.as_str() == format!("wazuh:{id}"))
            .unwrap()
            .text_lines_only
    };
    // sshd tests the program name; its child inherits that through <if_sid>.
    assert!(text_only("5700") && text_only("5716"));
    // The JSON decoder selects by prematch, and a missing parent says nothing.
    assert!(!text_only("9100") && !text_only("9000"));

    // A child decoder inherits its parent's bound. A prematch anchored on a letter cannot match
    // a JSON line's leading `{`; one that starts with `\S` or is unanchored can.
    let decoders = r#"
        <decoder name="sshd"><program_name>^sshd</program_name></decoder>
        <decoder name="sshd-success"><parent>sshd</parent><prematch>^Accepted</prematch></decoder>
        <decoder name="sudo"><program_name/><prematch>^\S+ :</prematch></decoder>
        <decoder name="pam"><program_name>(pam_unix)$</program_name></decoder>
        <decoder name="pam"><program_name></program_name><prematch>^pam_unix|^\(pam_unix\)</prematch></decoder>
        <decoder name="loose"><prematch>pam_unix</prematch></decoder>
    "#;
    let rules = WazuhRules::parse_with_decoders(
        [
            r#"<rule id="1" level="3"><decoded_as>sshd-success</decoded_as></rule>
            <rule id="2" level="3"><decoded_as>sudo</decoded_as></rule>
            <rule id="3" level="3"><decoded_as>pam</decoded_as></rule>
            <rule id="4" level="3"><decoded_as>loose</decoded_as></rule>"#,
        ],
        [decoders],
    )
    .unwrap();
    let text_only: Vec<bool> = rules
        .requirements()
        .iter()
        .map(|r| r.text_lines_only)
        .collect();
    assert_eq!(text_only, [true, false, true, false]);
}

#[test]
fn first_time_seen_without_decoders_fails_closed() {
    let rules = parse(r#"<rule id="5403" level="4"><if_sid>5400</if_sid><if_fts /></rule>"#);
    assert_eq!(only(&rules).fields, RequiredFields::Unknown);
}

#[test]
fn c3_a_program_name_that_is_a_regex_does_not_bound_its_rules() {
    // `program_name` is `osmatch` by default, where `.` is a literal; as `osregex` or `pcre2`
    // `^ssh.` also takes `sshX`, which a keyword test for `ssh.` would miss.
    for kind in ["osregex", "pcre2"] {
        let decoders = format!(
            r#"<decoder name="d"><program_name type="{kind}">^ssh.</program_name></decoder>"#
        );
        let rules = WazuhRules::parse_with_decoders(
            [r#"<rule id="1" level="3"><decoded_as>d</decoded_as></rule>"#],
            [decoders.as_str()],
        )
        .unwrap();
        assert_eq!(only(&rules).prefilter, Predicate::Always, "{kind}");
    }
    let literal = WazuhRules::parse_with_decoders(
        [r#"<rule id="1" level="3"><decoded_as>d</decoded_as></rule>"#],
        [r#"<decoder name="d"><program_name type="osmatch">^sshd</program_name></decoder>"#],
    )
    .unwrap();
    assert!(matches!(only(&literal).prefilter, Predicate::Keywords(_)));
}

#[test]
fn c3_a_regex_program_name_still_never_takes_a_json_line() {
    // Whatever its type, a program name needs a syslog header, which a JSON line lacks.
    let rules = WazuhRules::parse_with_decoders(
        [r#"<rule id="1" level="3"><decoded_as>d</decoded_as></rule>"#],
        [r#"<decoder name="d"><program_name type="pcre2">^ssh.</program_name></decoder>"#],
    )
    .unwrap();
    assert!(only(&rules).text_lines_only);
}

#[test]
fn chains_through_a_cycle_or_a_missing_parent_widen_instead_of_failing() {
    let rules = parse(
        r#"<rule id="1" level="3"><if_sid>2</if_sid><match>a</match></rule>
           <rule id="2" level="3"><if_sid>1</if_sid><match>b</match></rule>
           <rule id="3" level="3"><if_sid>404</if_sid><field name="x">y</field></rule>"#,
    );
    assert_eq!(rules.requirements().len(), 3);
    let orphan = rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == "wazuh:3")
        .unwrap();
    // Its own field test still bounds it; the missing parent adds `Always`, nothing narrower.
    assert!(matches!(orphan.prefilter, Predicate::Field(_)));
}

#[test]
fn a_child_reads_what_its_parents_read() {
    let rules = parse(
        r#"<rule id="10" level="3"><field name="a">1</field></rule>
           <rule id="11" level="3"><if_sid>10</if_sid><field name="b">2</field></rule>"#,
    );
    let child = rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == "wazuh:11")
        .unwrap();
    let RequiredFields::Known(fields) = &child.fields else {
        panic!("known fields");
    };
    assert!(fields.contains("a") && fields.contains("b"));
}

fn rule_of<'a>(rules: &'a WazuhRules, id: &str) -> &'a RuleRequirements {
    rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == format!("wazuh:{id}"))
        .unwrap()
}

#[test]
fn frequency_or_timeframe_alone_makes_a_rule_stateful() {
    for attributes in [r#"frequency="5""#, r#"timeframe="60""#] {
        let rules = parse(&format!(
            r#"<rule id="1" level="3" {attributes}><field name="x">y</field></rule>"#
        ));
        assert!(only(&rules).stateful, "{attributes}");
    }
    let plain = parse(r#"<rule id="1" level="3"><field name="x">y</field></rule>"#);
    assert!(!only(&plain).stateful);
}

#[test]
fn c3_cross_event_options_read_the_field_they_compare() {
    for (option, field) in [
        ("<same_src_port />", "srcport"),
        ("<different_dst_port />", "dstport"),
        ("<not_same_srcuser />", "srcuser"),
        ("<same_dstip />", "dstip"),
        ("<same_source_ip />", "srcip"),
        (
            "<same_field>win.eventdata.user</same_field>",
            "win.eventdata.user",
        ),
    ] {
        let rules = parse(&format!(
            r#"<rule id="1" level="3" frequency="2" timeframe="60">{option}</rule>"#
        ));
        let rule = only(&rules);
        assert!(rule.stateful, "{option}");
        assert_eq!(
            rule.fields,
            RequiredFields::known([field.into()]),
            "{option}"
        );
    }
}

#[test]
fn a_cross_event_option_on_metadata_is_stateful_without_a_field() {
    let rules = parse(r#"<rule id="1" level="3"><same_location /></rule>"#);
    let rule = only(&rules);
    assert!(rule.stateful);
    assert_eq!(rule.fields, RequiredFields::known([]));
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
}

#[test]
fn c3_a_child_of_several_parents_reads_what_each_parent_reads() {
    for list in ["1,2", "1, 2", "1 2", " 1,\n2 "] {
        let rules = parse(&format!(
            r#"<rule id="1" level="3"><field name="a">x</field></rule>
               <rule id="2" level="3"><field name="b">y</field></rule>
               <rule id="3" level="5"><if_sid>{list}</if_sid><field name="c">z</field></rule>"#
        ));
        assert_eq!(
            rule_of(&rules, "3").fields,
            RequiredFields::known(["a".into(), "b".into(), "c".into()]),
            "{list:?}"
        );
    }
}

#[test]
fn rule_names_are_their_descriptions() {
    let rules = parse(
        r#"<rule id="7" level="3"><description>  Logon failure </description></rule>
           <rule id="8" level="3"><field name="x">y</field></rule>"#,
    );
    assert_eq!(rules.names().len(), 1);
    assert_eq!(rules.names()[&"wazuh:7".into()], "Logon failure");
}

#[test]
fn c3_an_unreadable_rule_file_blocks_every_saving_and_names_its_position() {
    let rules = WazuhRules::parse([
        r#"<group name="ok,"><rule id="1" level="3"><field name="x">y</field></rule></group>"#,
        "<group><rule id=",
    ])
    .unwrap();
    assert_eq!(rules.problems().len(), 1);
    assert!(
        rules.problems()[0].contains("file 1"),
        "{:?}",
        rules.problems()
    );
    assert_eq!(
        rule_of(&rules, "unreadable:1"),
        &RuleRequirements::opaque("wazuh:unreadable:1".into())
    );
}
