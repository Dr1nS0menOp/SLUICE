use rsigma_parser::parse_sigma_yaml;
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use super::{glob_match, rule_prefilter};

fn prefilter(detection: &str) -> Predicate {
    let yaml = format!("title: t\nlogsource:\n    product: x\ndetection:\n{detection}");
    let collection = parse_sigma_yaml(&yaml).unwrap();
    assert!(collection.errors.is_empty(), "{:?}", collection.errors);
    rule_prefilter(&collection.rules[0].detection)
}

fn test(field: &str, op: MatchOp, value: &str, case_sensitive: bool) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op,
        values: if op == MatchOp::Exists {
            vec![]
        } else {
            vec![value.into()]
        },
        case_sensitive,
    })
}

#[test]
fn exclusions_are_dropped_not_negated() {
    let p = prefilter(
        "    selection:\n        EventID: 4625\n    filter:\n        TargetUserName|endswith: '$'\n    condition: selection and not filter\n",
    );
    assert_eq!(p, test("EventID", MatchOp::Equals, "4625", false));
}

#[test]
fn edge_wildcards_fold_into_the_comparison() {
    let p = prefilter(
        "    a:\n        X: '*mimi*'\n    b:\n        Y: 'pre*'\n    c:\n        Z: '*\\evil.exe'\n    condition: a or b or c\n",
    );
    assert_eq!(
        p,
        Predicate::any([
            test("X", MatchOp::Contains, "mimi", false),
            test("Y", MatchOp::StartsWith, "pre", false),
            test("Z", MatchOp::EndsWith, "\\evil.exe", false),
        ])
    );
}

#[test]
fn inner_wildcards_and_unsupported_modifiers_widen() {
    assert_eq!(
        prefilter("    s:\n        X: 'a*b'\n    condition: s\n"),
        Predicate::Always
    );
    assert_eq!(
        prefilter("    s:\n        X: 'a?b'\n    condition: s\n"),
        Predicate::Always
    );
    assert_eq!(
        prefilter("    s:\n        X|base64: 'abc'\n    condition: s\n"),
        Predicate::Always
    );
    assert_eq!(
        prefilter("    s:\n        X|cidr: '10.0.0.0/8'\n    condition: s\n"),
        Predicate::Always
    );
}

#[test]
fn keywords_become_free_text_tests() {
    assert_eq!(
        prefilter("    keywords:\n        - 'evil'\n        - '*bad*'\n    condition: keywords\n"),
        Predicate::Keywords(KeywordTest {
            values: vec!["evil".into(), "bad".into()],
            case_sensitive: false,
        })
    );
    assert_eq!(
        prefilter("    keywords:\n        - 'a*b'\n    condition: keywords\n"),
        Predicate::Always
    );
}

#[test]
fn quantified_selectors_follow_their_quantifier() {
    let detection = "    selection_a:\n        A: '1'\n    selection_b:\n        B: '2'\n";
    let a = test("A", MatchOp::Equals, "1", false);
    let b = test("B", MatchOp::Equals, "2", false);
    assert_eq!(
        prefilter(&format!("{detection}    condition: all of selection_*\n")),
        Predicate::all([a.clone(), b.clone()])
    );
    assert_eq!(
        prefilter(&format!("{detection}    condition: 1 of selection_*\n")),
        Predicate::any([a, b])
    );
}

#[test]
fn case_rules_follow_sigma() {
    assert_eq!(
        prefilter("    s:\n        X|cased: 'Abc'\n    condition: s\n"),
        test("X", MatchOp::Equals, "Abc", true)
    );
    assert_eq!(
        prefilter("    s:\n        X|re: '^a.c$'\n    condition: s\n"),
        test("X", MatchOp::Regex, "^a.c$", true)
    );
    assert_eq!(
        prefilter("    s:\n        X|re|i: '^a.c$'\n    condition: s\n"),
        test("X", MatchOp::Regex, "^a.c$", false)
    );
}

#[test]
fn exists_true_is_a_field_test_exists_false_is_unbounded() {
    assert_eq!(
        prefilter("    s:\n        X|exists: true\n    condition: s\n"),
        test("X", MatchOp::Exists, "", false)
    );
    assert_eq!(
        prefilter("    s:\n        X|exists: false\n    condition: s\n"),
        Predicate::Always
    );
}

#[test]
fn glob_matches_sigma_selector_patterns() {
    assert!(glob_match("selection_*", "selection_img"));
    assert!(glob_match("*_main", "filter_main"));
    assert!(glob_match("sel*_x*", "selection_x2"));
    assert!(!glob_match("selection_*", "filter"));
    assert!(glob_match("exact", "exact"));
}
