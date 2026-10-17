use std::fmt::Write as _;

use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};

use super::*;

const SEARCHES: &str = r"
[default]
enableSched = 0

[Brute Force]
search = `wineventlog_security` EventCode=4625 \
| stats count by TargetUserName | where count > 10
enableSched = 1

[Report]
search = index=main | top user

[Disabled Alert]
search = a=1
enableSched = 1
disabled = 1

[Correlation]
search = `process(rundll32.exe)` | `filter`
action.correlationsearch.enabled = 1

[Unknown Macro]
search = `nobody_knows` a=1
enableSched = 1
";

const MACROS: &str = r#"
[wineventlog_security]
definition = (index=wineventlog OR sourcetype=XmlWinEventLog) source="*Security"

[process(1)]
args = name
definition = Image="*\\$name$"

[filter]
definition = search *
"#;

fn rules() -> SplunkRules {
    SplunkRules::parse([("savedsearches.conf", SEARCHES), ("macros.conf", MACROS)])
}

fn rule<'a>(rules: &'a SplunkRules, name: &str) -> Option<&'a RuleRequirements> {
    rules
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == format!("splunk:{name}"))
}

#[test]
fn only_searches_that_run_on_their_own_count() {
    let rules = rules();
    assert!(rule(&rules, "Brute Force").is_some());
    assert!(rule(&rules, "Correlation").is_some());
    assert!(rule(&rules, "Report").is_none());
    assert!(rule(&rules, "Disabled Alert").is_none());
    assert_eq!(rules.requirements().len(), 3);
}

#[test]
fn macros_are_expanded_before_the_search_is_read() {
    let rules = rules();
    let brute = rule(&rules, "Brute Force").expect("the brute force rule");
    assert!(brute.stateful);
    assert_eq!(brute.field_names, Some(Schema::Splunk));
    assert_eq!(
        brute.fields,
        RequiredFields::known(["EventCode", "TargetUserName", "by", "count"].map(FieldPath::new))
    );
    assert_eq!(
        brute.prefilter,
        Predicate::Field(FieldTest {
            field: FieldPath::new("EventCode"),
            op: MatchOp::Contains,
            values: vec!["4625".to_owned(), "e".to_owned()],
            case_sensitive: false,
        })
    );
    let correlation = rule(&rules, "Correlation").expect("the correlation search");
    assert!(!correlation.matches_raw_text);
    assert_eq!(
        correlation.prefilter,
        Predicate::Field(FieldTest {
            field: FieldPath::new("Image"),
            op: MatchOp::Contains,
            values: vec!["\\rundll32.exe".to_owned()],
            case_sensitive: false,
        })
    );
}

#[test]
fn a_search_with_an_unknown_macro_may_read_anything() {
    let rules = rules();
    assert_eq!(
        rule(&rules, "Unknown Macro"),
        Some(&RuleRequirements::opaque(RuleId::new(
            "splunk:Unknown Macro"
        )))
    );
    assert!(
        rules
            .problems()
            .iter()
            .any(|p| p.contains("`nobody_knows`"))
    );
    assert_eq!(
        rules.names()[&RuleId::new("splunk:Unknown Macro")],
        "Unknown Macro"
    );
}

#[test]
fn rest_answers_read_like_conf_files() {
    let rules = SplunkRules::parse([
        (
            "saved-searches.json",
            r#"{"entry": [{"name": "x", "content": {"search": "`m(b, 1)`",
                "is_scheduled": true}}]}"#,
        ),
        (
            "macros.json",
            r#"{"entry": [{"name": "m(2)", "content": {"definition": "$f$=$v$",
                "args": "f, v"}}]}"#,
        ),
    ]);
    let x = rule(&rules, "x").expect("the REST search");
    assert_eq!(x.fields, RequiredFields::known([FieldPath::new("b")]));
}

#[test]
fn a_file_that_is_no_rest_answer_is_reported() {
    let rules = SplunkRules::parse([("x.json", "{}")]);
    assert_eq!(rules.requirements(), []);
    assert_eq!(rules.problems().len(), 1);
}

#[test]
fn macros_that_call_themselves_fail_closed() {
    let rules = SplunkRules::parse([(
        "x.conf",
        "[loop]\ndefinition = `loop`\n[s]\nsearch = `loop`\nenableSched = 1\n",
    )]);
    assert_eq!(
        rules.requirements(),
        [RuleRequirements::opaque(RuleId::new("splunk:s"))]
    );
}

#[test]
fn a_generating_search_is_reported_as_one_whatever_its_macros() {
    let rules = SplunkRules::parse([(
        "x.conf",
        "[s]\nsearch = | tstats count from datamodel=Endpoint.Processes | `elsewhere(Processes)`\n\
         enableSched = 1\n",
    )]);
    assert_eq!(
        rules.requirements(),
        [RuleRequirements::opaque(RuleId::new("splunk:s"))]
    );
    assert!(rules.problems()[0].contains("a generating command"));
}

#[test]
fn comments_are_no_macro_calls() {
    assert_eq!(
        without_comments("a=1 ```keep `x` out``` | stats count ```two```"),
        "a=1   | stats count  "
    );
    assert_eq!(without_comments("a=1 ```open"), "a=1 ```open");
    let rules = SplunkRules::parse([(
        "x.conf",
        "[s]\nsearch = a=1 ```why``` | table a\nenableSched = 1\n",
    )]);
    assert_eq!(rules.problems(), [] as [String; 0]);
}

#[test]
fn macro_arguments_split_outside_quotes_and_parentheses() {
    assert_eq!(
        arguments(r#"a, "b, c", f(d, e)"#),
        ["a", "\"b, c\"", "f(d, e)"]
    );
    assert_eq!(arguments(""), Vec::<String>::new());
}

/// Saved search `s` calling `m0`, which calls `m1`, … `m{n-1}`, which is `a=1`.
fn macro_chain(n: usize) -> SplunkRules {
    let mut conf = String::from("[s]\nsearch = `m0`\nenableSched = 1\n");
    for i in 0..n {
        let definition = if i + 1 == n {
            "a=1".to_owned()
        } else {
            format!("`m{}`", i + 1)
        };
        let _ = write!(conf, "[m{i}]\ndefinition = {definition}\n");
    }
    SplunkRules::parse([("x.conf", conf.as_str())])
}

#[test]
fn macros_nest_up_to_the_limit() {
    let within = macro_chain(MAX_MACRO_DEPTH + 1);
    assert_eq!(within.problems(), [] as [String; 0]);
    let beyond = macro_chain(MAX_MACRO_DEPTH + 2);
    assert!(
        beyond.problems()[0].contains("deeper"),
        "{:?}",
        beyond.problems()
    );
}

#[test]
fn a_search_that_may_read_any_field_reads_the_raw_event() {
    let rules = SplunkRules::parse([("x.conf", "[s]\nsearch = Event*=1\nenableSched = 1\n")]);
    let r = rule(&rules, "s").expect("the search");
    assert_eq!(r.fields, RequiredFields::Unknown);
    assert!(r.matches_raw_text);
}

#[test]
fn macro_arguments_keep_parentheses_and_quotes_together() {
    assert_eq!(arguments(r#""(", ")", z"#), [r#""(""#, r#"")""#, "z"]);
    assert_eq!(arguments("f(a, b), c"), ["f(a, b)", "c"]);
    assert_eq!(arguments(r#"")", x"#), [r#"")""#, "x"]);
}
