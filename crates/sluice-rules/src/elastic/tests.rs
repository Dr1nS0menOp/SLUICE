use sluice_core::predicate::{FieldTest, MatchOp};

use super::*;

const EXPORT: &str = r#"{"rule_id":"r-kql","name":"Logon","type":"query","language":"kuery","index":["logs-system.security*"],"query":"event.code : \"4624\" and winlog.logon.type : Network"}
{"rule_id":"r-eql","name":"Spawn","type":"eql","language":"eql","query":"process where process.parent.name == \"winword.exe\""}
{"rule_id":"r-thr","name":"Brute force","type":"threshold","language":"kuery","query":"event.code : 4625","threshold":{"field":["source.ip"],"value":10}}
{"rule_id":"r-ml","name":"Rare process","type":"machine_learning","machine_learning_job_id":"x"}
{"exported_count":4,"exported_rules_count":4,"missing_rules":[]}
"#;

fn rule<'a>(rules: &'a ElasticRules, id: &str) -> &'a RuleRequirements {
    rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str().ends_with(id))
        .unwrap_or_else(|| panic!("no rule {id}"))
}

fn known(rule: &RuleRequirements) -> Vec<&str> {
    match &rule.fields {
        RequiredFields::Known(fields) => fields.iter().map(FieldPath::as_str).collect(),
        RequiredFields::Unknown => panic!("{} may read anything", rule.rule),
    }
}

#[test]
fn an_export_is_read_rule_by_rule_and_its_summary_line_skipped() {
    let rules = ElasticRules::parse([("rules.ndjson", EXPORT)]);
    assert_eq!(rules.requirements().len(), 4);
    assert_eq!(rules.queries().len(), 3);
    assert_eq!(
        rules
            .names()
            .get(&RuleId::new("elastic:r-kql"))
            .map(String::as_str),
        Some("Logon")
    );
    let kql = rule(&rules, "r-kql");
    assert_eq!(known(kql), ["event.code", "winlog.logon.type"]);
    assert_eq!(kql.field_names, Some(Schema::Ecs));
    assert!(!kql.stateful && !kql.prefilter.is_always());
    assert_eq!(known(rule(&rules, "r-eql")), ["process.parent.name"]);
}

#[test]
fn c3_a_threshold_rule_counts_events_and_reads_what_it_groups_by() {
    let rules = ElasticRules::parse([("rules.ndjson", EXPORT)]);
    let threshold = rule(&rules, "r-thr");
    assert!(threshold.stateful);
    assert_eq!(known(threshold), ["event.code", "source.ip"]);
}

#[test]
fn c3_a_machine_learning_rule_may_read_anything() {
    let rules = ElasticRules::parse([("rules.ndjson", EXPORT)]);
    let ml = rule(&rules, "r-ml");
    assert_eq!(ml.fields, RequiredFields::Unknown);
    assert!(ml.prefilter.is_always() && ml.matches_raw_text);
    assert!(
        rules
            .problems()
            .iter()
            .any(|p| p.contains("machine learning"))
    );
}

#[test]
fn c3_unreadable_and_unparsed_rules_fail_closed() {
    let rules = ElasticRules::parse([(
        "broken.ndjson",
        "{\"rule_id\":\"a\",\"type\":\"query\",\"query\":\"(x : 1\"}\nnot json\n",
    )]);
    assert_eq!(rules.requirements().len(), 2);
    for r in rules.requirements() {
        assert_eq!(r.fields, RequiredFields::Unknown, "{}", r.rule);
        assert!(r.prefilter.is_always());
    }
    assert_eq!(rules.problems().len(), 2, "{:?}", rules.problems());
}

#[test]
fn json_lists_and_find_answers_are_read_too() {
    let one = r#"{"rule_id":"a","type":"query","query":"user.name : root"}"#;
    let list = format!("[{one}]");
    let find = format!(r#"{{"page":1,"total":1,"data":[{one}]}}"#);
    for text in [one.to_owned(), list, find] {
        let rules = ElasticRules::parse([("rules.json", text.as_str())]);
        assert_eq!(rules.requirements().len(), 1, "{text}");
        assert_eq!(known(&rules.requirements()[0]), ["user.name"]);
    }
}

#[test]
fn esql_reads_its_names_and_lucene_everything() {
    let rules = ElasticRules::parse([(
        "rules.ndjson",
        "{\"rule_id\":\"q\",\"type\":\"esql\",\"language\":\"esql\",\"query\":\"FROM logs-* | WHERE event.code == \\\"4625\\\" | STATS n = COUNT(*) BY user.name | WHERE n > 5\"}\n\
         {\"rule_id\":\"l\",\"type\":\"query\",\"language\":\"lucene\",\"query\":\"event.code:4625 AND mimikatz\"}\n",
    )]);
    let esql = rule(&rules, ":q");
    assert!(esql.stateful);
    // Only events its first `WHERE` keeps reach the `STATS`; the later one tests a count.
    assert_eq!(
        esql.prefilter,
        Predicate::Field(FieldTest {
            field: "event.code".into(),
            op: MatchOp::Equals,
            values: vec!["4625".into()],
            case_sensitive: false,
        })
    );
    let fields = known(esql);
    assert!(
        fields.contains(&"event.code") && fields.contains(&"user.name"),
        "{fields:?}"
    );
    assert!(!fields.iter().any(|f| f.starts_with("logs")), "{fields:?}");
    assert_eq!(rule(&rules, ":l").fields, RequiredFields::Unknown);
}

#[test]
fn c3_an_esql_rule_matches_what_its_first_where_keeps() {
    let rules = ElasticRules::parse([(
        "r.ndjson",
        "{\"rule_id\":\"q\",\"type\":\"esql\",\"query\":\"from logs-windows.* | where event.code == \\\"4688\\\" | keep *\"}\n",
    )]);
    let esql = &rules.requirements()[0];
    assert!(!esql.prefilter.is_always(), "{:?}", esql.prefilter);
    assert_eq!(
        esql.fields,
        RequiredFields::Unknown,
        "`keep *` reads every field"
    );
}

#[test]
fn c3_only_rules_that_run_count_the_newest_version_and_not_disabled_ones() {
    let rules = ElasticRules::parse([
        (
            "a_1.json",
            r#"{"rule_id":"a","version":1,"type":"query","query":"old.field : x"}"#,
        ),
        (
            "a_2.json",
            r#"{"rule_id":"a","version":2,"type":"query","query":"new.field : x"}"#,
        ),
        (
            "b.json",
            r#"{"rule_id":"b","enabled":false,"type":"query","query":"b : x"}"#,
        ),
    ]);
    assert_eq!(rules.requirements().len(), 1);
    assert_eq!(known(&rules.requirements()[0]), ["new.field"]);
    assert!(
        rules
            .problems()
            .iter()
            .any(|p| p.starts_with("1 Elastic rules are disabled")),
        "{:?}",
        rules.problems()
    );
}

#[test]
fn c3_a_rule_applies_to_the_sources_its_indices_read() {
    let rules = ElasticRules::parse([(
        "r.ndjson",
        "{\"rule_id\":\"aws\",\"type\":\"query\",\"query\":\"a : b\",\"index\":[\"logs-aws.cloudtrail-*\"]}\n\
         {\"rule_id\":\"two\",\"type\":\"query\",\"query\":\"a : b\",\"index\":[\"winlogbeat-*\",\"logs-endpoint.events.*\"]}\n\
         {\"rule_id\":\"any\",\"type\":\"query\",\"query\":\"a : b\",\"index\":[\"logs-*\",\"winlogbeat-*\"]}\n\
         {\"rule_id\":\"q\",\"type\":\"esql\",\"query\":\"from logs-okta* | stats n = count(*)\"}\n",
    )]);
    let products = |id: &str| -> Vec<Option<&str>> {
        rules
            .requirements()
            .iter()
            .filter(|r| r.rule.as_str() == format!("elastic:{id}"))
            .map(|r| r.logsource.product.as_deref())
            .collect()
    };
    assert_eq!(products("aws"), [Some("aws")]);
    assert_eq!(products("two"), [Some("elastic_defend"), Some("windows")]);
    assert_eq!(products("any"), [None]);
    assert_eq!(products("q"), [Some("okta")]);
}

#[test]
fn c3_a_rule_on_alerts_keeps_what_it_reads_on_every_event() {
    let rules = ElasticRules::parse([(
        "r.ndjson",
        "{\"rule_id\":\"a\",\"type\":\"esql\",\"query\":\"from .alerts-security.* | where kibana.alert.risk_score >= 73 and user.name is not null | stats v = values(message) by user.name\"}\n",
    )]);
    let rule = &rules.requirements()[0];
    assert!(rule.prefilter.is_always(), "{:?}", rule.prefilter);
    assert!(known(rule).contains(&"message"));
}

#[test]
fn deprecated_rules_no_longer_run() {
    let rules = ElasticRules::parse([(
        "r.json",
        r#"{"attributes":{"deprecated":true,"name":"old","rule_id":"x","version":3},"type":"security-rule"}"#,
    )]);
    assert_eq!(rules.requirements(), &[] as &[RuleRequirements]);
    let wrapped = ElasticRules::parse([(
        "r.json",
        r#"{"attributes":{"rule_id":"x","type":"query","query":"a : b"},"type":"security-rule"}"#,
    )]);
    assert_eq!(wrapped.requirements().len(), 1);
}

#[test]
fn c3_a_prefilter_matches_the_rules_events() {
    let rules = ElasticRules::parse([("rules.ndjson", EXPORT)]);
    let Predicate::All(parts) = &rule(&rules, "r-kql").prefilter else {
        panic!("a conjunction");
    };
    // A number: its digits, or an exponent.
    assert!(parts.contains(&Predicate::Field(FieldTest {
        field: "event.code".into(),
        op: MatchOp::Contains,
        values: vec!["4624".into(), "e".into()],
        case_sensitive: false,
    })));
}
