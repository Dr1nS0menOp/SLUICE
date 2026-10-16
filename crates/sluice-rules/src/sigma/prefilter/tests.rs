use rsigma_parser::ast::Modifier;
use rsigma_parser::parse_sigma_yaml;
use rsigma_parser::value::{SigmaString, SigmaValue};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use super::{
    Base, base, glob_match, present_unless_null, rule_prefilter, value_test, wildcard_superset,
};

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
fn all_modifier_requires_every_value() {
    let p = prefilter(
        "    s:\n        ScriptBlockText|contains|all:\n            - 'Net.WebClient'\n            - 'DownloadString'\n    condition: s\n",
    );
    assert_eq!(
        p,
        Predicate::all([
            test("ScriptBlockText", MatchOp::Contains, "Net.WebClient", false),
            test(
                "ScriptBlockText",
                MatchOp::Contains,
                "DownloadString",
                false
            ),
        ])
    );
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
fn unsupported_modifiers_widen_to_a_present_field() {
    // Not expressible, but a match needs a value in X: that is all the pre-filter keeps.
    assert_eq!(
        prefilter("    s:\n        X|base64: 'abc'\n    condition: s\n"),
        Predicate::present("X".into())
    );
    assert_eq!(
        prefilter("    s:\n        X|cidr: '10.0.0.0/8'\n    condition: s\n"),
        Predicate::present("X".into())
    );
}

#[test]
fn inner_wildcards_bound_by_their_literal_pieces() {
    // A value matching `cmd*evil.exe` starts with `cmd`, ends with `evil.exe` and contains it.
    assert_eq!(
        prefilter("    s:\n        X: 'cmd*evil.exe'\n    condition: s\n"),
        Predicate::all([
            test("X", MatchOp::StartsWith, "cmd", false),
            test("X", MatchOp::EndsWith, "evil.exe", false),
            test("X", MatchOp::Contains, "evil.exe", false),
        ])
    );
    assert_eq!(
        prefilter("    s:\n        X|contains: 'chown root*chmod 4777'\n    condition: s\n"),
        test("X", MatchOp::Contains, "chmod 4777", false)
    );
    // Keywords: the value contains the longest piece; pieces too short say nothing.
    assert_eq!(
        prefilter("    keywords:\n        - 'ghost_* -v '\n    condition: keywords\n"),
        Predicate::Keywords(KeywordTest {
            values: vec!["ghost_".into()],
            case_sensitive: false,
        })
    );
}

#[test]
fn keywords_with_all_require_every_keyword() {
    let p = prefilter(
        "    keywords:\n        '|all':\n            - 'bash -c /bin/bash'\n            - '&/dev/tcp/'\n    condition: keywords\n",
    );
    let kw = |v: &str| {
        Predicate::Keywords(KeywordTest {
            values: vec![v.into()],
            case_sensitive: false,
        })
    };
    assert_eq!(
        p,
        Predicate::all([kw("bash -c /bin/bash"), kw("&/dev/tcp/")])
    );
}

#[test]
fn keywords_become_free_text_tests() {
    assert_eq!(
        prefilter("    keywords:\n        - 'evil'\n        - '*bad*'\n    condition: keywords\n"),
        Predicate::Keywords(KeywordTest {
            values: vec!["bad".into(), "evil".into()],
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

/// One selection `s` with `item` as its only line, and `condition: s`.
fn item(item: &str) -> Predicate {
    prefilter(&format!("    s:\n        {item}\n    condition: s\n"))
}

fn present(field: &str) -> Predicate {
    Predicate::present(field.into())
}

#[test]
fn c3_each_inexpressible_modifier_widens_to_a_present_field() {
    for (modifier, value) in [
        ("windash", "'-a'"),
        ("cidr", "'10.0.0.0/8'"),
        ("base64offset|contains", "'abc'"),
        ("base64|contains", "'abc'"),
        ("wide|base64offset|contains", "'abc'"),
        ("gt", "1"),
        ("lte", "1"),
        ("fieldref", "'Y'"),
        ("re|m", "'a'"),
    ] {
        let p = item(&format!("X|{modifier}: {value}"));
        assert_eq!(p, present("X"), "{modifier}");
    }
}

#[test]
fn explicit_edge_modifiers_anchor_one_end() {
    assert_eq!(
        item("X|startswith: 'pre'"),
        test("X", MatchOp::StartsWith, "pre", false)
    );
    assert_eq!(
        item("X|endswith: 'post'"),
        test("X", MatchOp::EndsWith, "post", false)
    );
}

#[test]
fn c3_what_rsigma_refuses_still_widens_here() {
    // rsigma 0.24 refuses these rules when it parses them (one operator per field, string
    // modifiers on strings only); should a parser ever accept them, they widen.
    assert_eq!(base(&[Modifier::Contains, Modifier::StartsWith]), None);
    assert_eq!(
        value_test("EventID", Base::Contains, false, &SigmaValue::Integer(46)),
        present("EventID")
    );
    assert!(present_unless_null("X", &[SigmaValue::Null]).is_always());
    assert!(present_unless_null("X", &[]).is_always());
    let wild = SigmaString::new("abc*def");
    assert!(wildcard_superset("X", Base::Regex, true, &wild).is_always());
    assert!(wildcard_superset("X", Base::Exists, true, &wild).is_always());
}

#[test]
fn a_field_less_mapping_without_modifiers_is_keywords() {
    assert_eq!(
        prefilter("    keywords:\n        '':\n            - 'evil'\n    condition: keywords\n"),
        Predicate::Keywords(KeywordTest {
            values: vec!["evil".into()],
            case_sensitive: false,
        })
    );
}

#[test]
fn regexes_are_case_sensitive_unless_i() {
    assert_eq!(item("X|re: 'a.b'"), test("X", MatchOp::Regex, "a.b", true));
    assert_eq!(
        item("X|re|i: 'a.b'"),
        test("X", MatchOp::Regex, "a.b", false)
    );
}

#[test]
fn a_regex_value_is_kept_whole_even_with_wildcard_characters() {
    // In a regex `*` is a quantifier, not a Sigma wildcard.
    assert_eq!(item("X|re: 'a*b'"), test("X", MatchOp::Regex, "a*b", true));
}

#[test]
fn c3_null_and_empty_value_lists_are_unbounded() {
    assert!(item("X: null").is_always());
    assert!(item("X:\n            - 'a'\n            - null").is_always());
}

#[test]
fn integers_compare_as_text_and_only_by_equality() {
    assert_eq!(
        item("EventID: 4625"),
        test("EventID", MatchOp::Equals, "4625", false)
    );
    assert_eq!(
        item("EventID|contains: '46'"),
        test("EventID", MatchOp::Contains, "46", false)
    );
}

#[test]
fn booleans_and_floats_need_a_present_field() {
    assert_eq!(item("Elevated: true"), present("Elevated"));
    assert_eq!(item("Ratio: 1.5"), present("Ratio"));
}

#[test]
fn a_lone_wildcard_or_question_mark_needs_only_a_value() {
    assert_eq!(item("X: '*'"), test("X", MatchOp::Exists, "", false));
    assert_eq!(
        item("X|contains: '*'"),
        test("X", MatchOp::Exists, "", false)
    );
    assert_eq!(item("X: '?'"), present("X"));
}

#[test]
fn an_empty_string_is_an_exact_empty_value() {
    assert_eq!(item("X: ''"), test("X", MatchOp::Equals, "", false));
}

#[test]
fn a_value_list_is_any_of_its_values() {
    let p = item("X:\n            - 'a'\n            - 'b'");
    assert_eq!(
        p,
        Predicate::Field(FieldTest {
            field: "X".into(),
            op: MatchOp::Equals,
            values: vec!["a".into(), "b".into()],
            case_sensitive: false,
        })
    );
}

#[test]
fn keywords_with_short_inner_pieces_or_non_text_widen() {
    let keywords = |line: &str| {
        prefilter(&format!(
            "    keywords:\n        - {line}\n    condition: keywords\n"
        ))
    };
    assert!(
        keywords("'a*b'").is_always(),
        "pieces shorter than three letters"
    );
    assert_eq!(
        keywords("'abc*xy'"),
        Predicate::Keywords(KeywordTest {
            values: vec!["abc".into()],
            case_sensitive: false,
        })
    );
    assert!(keywords("true").is_always());
    assert_eq!(
        keywords("4625"),
        Predicate::Keywords(KeywordTest {
            values: vec!["4625".into()],
            case_sensitive: false,
        })
    );
}

#[test]
fn a_selector_that_matches_nothing_or_an_unknown_identifier_is_unbounded() {
    // rsigma refuses a selector or identifier with no detection, so these come in through the
    // AST only: build the condition by hand.
    let yaml = "title: t\nlogsource:\n    product: x\ndetection:\n    selection:\n        A: '1'\n    condition: selection\n";
    let mut detections = parse_sigma_yaml(yaml).unwrap().rules[0].detection.clone();
    detections.conditions = vec![rsigma_parser::ast::ConditionExpr::Identifier(
        "undefined".into(),
    )];
    assert!(rule_prefilter(&detections).is_always());
    detections.conditions.clear();
    assert!(
        rule_prefilter(&detections).is_always(),
        "no condition at all"
    );
}

#[test]
fn all_of_them_leaves_underscore_selections_out_and_one_of_them_takes_them_in() {
    let detection = "    selection:\n        A: '1'\n    _helper:\n        B: '2'\n";
    let all = prefilter(&format!("{detection}    condition: all of them\n"));
    assert_eq!(all, test("A", MatchOp::Equals, "1", false));
    let any = prefilter(&format!("{detection}    condition: 1 of them\n"));
    assert_eq!(
        any,
        Predicate::any([
            test("A", MatchOp::Equals, "1", false),
            test("B", MatchOp::Equals, "2", false)
        ])
    );
}

#[test]
fn several_conditions_are_any_of_them() {
    let yaml = "title: t\nlogsource:\n    product: x\ndetection:\n    a:\n        A: '1'\n    b:\n        B: '2'\n    condition:\n        - a\n        - b\n";
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(
        rule_prefilter(&collection.rules[0].detection),
        Predicate::any([
            test("A", MatchOp::Equals, "1", false),
            test("B", MatchOp::Equals, "2", false)
        ])
    );
}

#[test]
fn glob_patterns_with_several_stars_and_non_ascii_names() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("sel*_*x", "sel_a_b_x"));
    assert!(!glob_match("sel*_*x", "sel_a_b_y"));
    assert!(glob_match("sél*", "sélection"));
    assert!(glob_match("*ç", "façadeç"));
    assert!(!glob_match("a", "ab"));
}
