//! Predicate tests: building, simplifying, and deciding against a template's fixed values.

use super::*;

#[test]
fn c3_on_a_text_line_field_tests_hold_and_keyword_tests_stay() {
    let field = eq("user", "admin");
    let words = Predicate::Keywords(KeywordTest {
        values: vec!["sshd".into()],
        case_sensitive: false,
    });
    assert_eq!(field.on_text_line(), Predicate::Always);
    assert_eq!(words.on_text_line(), words);
    assert_eq!(
        Predicate::all([field.clone(), words.clone()]).on_text_line(),
        words
    );
    assert_eq!(
        Predicate::any([field, words]).on_text_line(),
        Predicate::Always
    );
    assert_eq!(Predicate::never().on_text_line(), Predicate::never());
}

fn eq(field: &str, value: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op: MatchOp::Equals,
        values: vec![value.into()],
        case_sensitive: false,
    })
}

#[test]
fn always_absorbs_disjunction() {
    assert_eq!(
        Predicate::any([eq("a", "1"), Predicate::Always]),
        Predicate::Always
    );
}

#[test]
fn always_is_neutral_in_conjunction() {
    assert_eq!(
        Predicate::all([eq("a", "1"), Predicate::Always]),
        eq("a", "1")
    );
    assert_eq!(Predicate::all([]), Predicate::Always);
}

#[test]
fn nested_disjunctions_flatten_and_dedupe() {
    let nested = Predicate::any([eq("a", "1"), Predicate::any([eq("b", "2"), eq("a", "1")])]);
    assert_eq!(nested, Predicate::Any(vec![eq("a", "1"), eq("b", "2")]));
}

#[test]
fn a_fixed_value_rules_out_only_conflicting_tests() {
    let fixed = [(FieldPath::from("EventID"), "7036".to_owned())];
    let zerologon = Predicate::all([
        Predicate::any([eq("EventID", "5805"), eq("EventID", "5723")]),
        Predicate::Keywords(KeywordTest {
            values: vec!["mimikatz".into()],
            case_sensitive: false,
        }),
    ]);
    assert!(!zerologon.may_match_with(&fixed, None));
    assert!(eq("EventID", "7036").may_match_with(&fixed, None));
    assert!(
        eq("Image", "x").may_match_with(&fixed, None),
        "other fields are unknown"
    );
    assert!(Predicate::any([eq("EventID", "1"), Predicate::Always]).may_match_with(&fixed, None));
    let regex = Predicate::Field(FieldTest {
        field: "EventID".into(),
        op: MatchOp::Regex,
        values: vec!["^5".into()],
        case_sensitive: false,
    });
    assert!(
        regex.may_match_with(&fixed, None),
        "regex is never decided here"
    );
    let case = [(FieldPath::from("Channel"), "System".to_owned())];
    assert!(eq("Channel", "system").may_match_with(&case, None));

    // A JSON template's exact key set rules out tests on fields it lacks.
    let paths: BTreeSet<FieldPath> = ["EventID", "process.name"]
        .into_iter()
        .map(Into::into)
        .collect();
    assert!(!eq("CommandLine", "x").may_match_with(&[], Some(&paths)));
    assert!(
        eq("process", "x").may_match_with(&[], Some(&paths)),
        "a parent is present"
    );
    assert!(
        eq("process.name.raw", "x").may_match_with(&[], Some(&paths)),
        "inside a leaf"
    );
    assert_eq!(
        zerologon.may_match_with(&[], Some(&paths)),
        zerologon.may_match_with(&[], None)
    );
    assert!(!Predicate::present("CommandLine".into()).may_match_with(&[], Some(&paths)));
    let exists = Predicate::Field(FieldTest {
        field: "g".into(),
        op: MatchOp::Exists,
        values: vec![],
        case_sensitive: false,
    });
    assert!(
        exists.may_match_with(&[], Some(&paths)),
        "`g` may be an empty object"
    );
}

#[test]
fn keyword_tests_in_a_disjunction_merge_by_case_sensitivity() {
    let kw = |values: &[&str], case_sensitive| {
        Predicate::Keywords(KeywordTest {
            values: values.iter().map(|v| (*v).to_owned()).collect(),
            case_sensitive,
        })
    };
    let merged = Predicate::any([
        kw(&["b", "a"], false),
        eq("x", "1"),
        kw(&["c", "a"], false),
        kw(&["Z"], true),
    ]);
    assert_eq!(
        merged,
        Predicate::Any(vec![
            eq("x", "1"),
            kw(&["Z"], true),
            kw(&["a", "b", "c"], false),
        ])
    );
    assert_eq!(
        Predicate::any([kw(&["a"], false), kw(&["b"], false)]),
        kw(&["a", "b"], false)
    );
}

#[test]
fn empty_disjunction_matches_nothing() {
    assert_eq!(Predicate::any([]), Predicate::never());
    assert!(!Predicate::never().is_always());
}

// ---------- helpers ----------

fn test(field: &str, op: MatchOp, values: &[&str], case_sensitive: bool) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive,
    })
}

fn keywords(values: &[&str]) -> Predicate {
    Predicate::Keywords(KeywordTest {
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: false,
    })
}

fn fixed(field: &str, value: &str) -> Vec<(FieldPath, String)> {
    vec![(field.into(), value.to_owned())]
}

fn paths(paths: &[&str]) -> BTreeSet<FieldPath> {
    paths.iter().map(|p| FieldPath::from(*p)).collect()
}

// ---------- never, is_never, is_always ----------

#[test]
fn never_matches_nothing_and_is_not_always() {
    let never = Predicate::never();
    assert!(never.is_never());
    assert!(!never.is_always());
    assert_eq!(never.tests(), 0);
    assert!(!never.may_match_with(&[], None));
    assert!(!never.holds_for_all_with(&[]));
}

#[test]
fn only_an_empty_disjunction_is_never() {
    assert!(!Predicate::All(Vec::new()).is_never());
    assert!(!Predicate::Always.is_never());
    assert!(!Predicate::Any(vec![eq("a", "1")]).is_never());
}

// ---------- any ----------

#[test]
fn any_of_one_is_that_one() {
    assert_eq!(Predicate::any([eq("a", "1")]), eq("a", "1"));
}

#[test]
fn any_of_nevers_is_never() {
    assert!(Predicate::any([Predicate::never(), Predicate::never()]).is_never());
}

#[test]
fn c3_always_nested_in_a_hand_built_disjunction_absorbs_it() {
    // `Any` built directly, not through `any`, may hold `Always`; a rule with such a
    // pre-filter is unbounded and must be recognized as such.
    let hand_built = Predicate::Any(vec![eq("a", "1"), Predicate::Always]);
    assert!(Predicate::any([hand_built, eq("b", "2")]).is_always());
}

#[test]
fn any_merges_field_tests_that_differ_only_in_values() {
    let merged = Predicate::any([eq("a", "2"), eq("a", "1"), eq("a", "1")]);
    assert_eq!(merged, test("a", MatchOp::Equals, &["1", "2"], false));
}

#[test]
fn any_keeps_tests_apart_that_differ_in_operator_case_or_field() {
    let parts = [
        test("a", MatchOp::Equals, &["1"], false),
        test("a", MatchOp::Equals, &["1"], true),
        test("a", MatchOp::Contains, &["1"], false),
        test("b", MatchOp::Equals, &["1"], false),
    ];
    let Predicate::Any(merged) = Predicate::any(parts.clone()) else {
        panic!("a disjunction of four");
    };
    assert_eq!(merged.len(), 4);
}

#[test]
fn any_never_merges_exists_tests_into_value_tests() {
    let exists = test("a", MatchOp::Exists, &[], false);
    let Predicate::Any(parts) = Predicate::any([exists.clone(), eq("a", "1")]) else {
        panic!("a disjunction of two");
    };
    assert!(parts.contains(&exists));
}

// ---------- all ----------

#[test]
fn all_of_one_is_that_one_and_all_of_none_is_always() {
    assert_eq!(Predicate::all([eq("a", "1")]), eq("a", "1"));
    assert!(Predicate::all(std::iter::empty()).is_always());
    assert!(Predicate::all([Predicate::Always, Predicate::Always]).is_always());
}

#[test]
fn all_flattens_and_dedups_nested_conjunctions() {
    let nested = Predicate::all([eq("a", "1"), Predicate::all([eq("b", "2"), eq("a", "1")])]);
    assert_eq!(nested, Predicate::All(vec![eq("a", "1"), eq("b", "2")]));
}

#[test]
fn all_drops_always_nested_in_a_hand_built_conjunction() {
    let hand_built = Predicate::All(vec![Predicate::Always, eq("a", "1")]);
    assert_eq!(Predicate::all([hand_built]), eq("a", "1"));
}

#[test]
fn all_with_never_matches_nothing() {
    let conjunction = Predicate::all([Predicate::never(), eq("a", "1")]);
    assert!(!conjunction.may_match_with(&[], None));
}

// ---------- tests ----------

#[test]
fn tests_counts_field_and_keyword_tests_at_any_depth() {
    assert_eq!(Predicate::Always.tests(), 0);
    assert_eq!(eq("a", "1").tests(), 1);
    assert_eq!(keywords(&["x"]).tests(), 1);
    let nested = Predicate::All(vec![
        eq("a", "1"),
        Predicate::Any(vec![eq("b", "1"), keywords(&["x"]), Predicate::Always]),
    ]);
    assert_eq!(nested.tests(), 3);
}

// ---------- present, names_fields ----------

#[test]
fn present_is_a_regex_that_matches_any_value() {
    let present = Predicate::present("CommandLine".into());
    assert_eq!(present, test("CommandLine", MatchOp::Regex, &[""], true));
    assert!(present.may_match_with(&fixed("CommandLine", "anything"), None));
    assert!(present.names_fields());
}

#[test]
fn names_fields_looks_through_nesting_and_ignores_keywords() {
    assert!(!Predicate::Always.names_fields());
    assert!(!keywords(&["x"]).names_fields());
    assert!(!Predicate::never().names_fields());
    assert!(
        Predicate::All(vec![keywords(&["x"]), Predicate::Any(vec![eq("a", "1")])]).names_fields()
    );
}

// ---------- may_match_with ----------

#[test]
fn c3_a_fixed_value_rules_out_each_operator_only_when_it_cannot_pass() {
    let value = fixed("Action", "Logon-Failed");
    for (op, holds, fails) in [
        (MatchOp::Equals, "logon-failed", "logon"),
        (MatchOp::Contains, "ON-FAI", "success"),
        (MatchOp::StartsWith, "logon", "failed"),
        (MatchOp::EndsWith, "failed", "logon"),
    ] {
        assert!(
            test("Action", op, &[holds], false).may_match_with(&value, None),
            "{op:?}"
        );
        assert!(
            !test("Action", op, &[fails], false).may_match_with(&value, None),
            "{op:?}"
        );
    }
}

#[test]
fn a_case_sensitive_test_is_ruled_out_by_another_case() {
    let value = fixed("Channel", "System");
    assert!(!test("Channel", MatchOp::Equals, &["system"], true).may_match_with(&value, None));
    assert!(test("Channel", MatchOp::Equals, &["System"], true).may_match_with(&value, None));
}

#[test]
fn c3_non_ascii_values_are_never_ruled_out_case_insensitively() {
    // Engines fold `É` and `é` (Unicode); ASCII lower-casing does not. Deciding here would
    // rule out a rule the engine fires, and its fields could be removed.
    let value = fixed("Action", "ÉCHEC");
    assert!(test("Action", MatchOp::Equals, &["échec"], false).may_match_with(&value, None));
    let ascii_test_on_non_ascii_value = test("Action", MatchOp::StartsWith, &["x"], false);
    assert!(ascii_test_on_non_ascii_value.may_match_with(&value, None));
    // Case-sensitive tests compare bytes, which is exact for any script.
    assert!(!test("Action", MatchOp::Equals, &["échec"], true).may_match_with(&value, None));
}

#[test]
fn a_test_with_several_values_may_match_if_any_value_may() {
    let value = fixed("EventID", "4625");
    assert!(
        test("EventID", MatchOp::Equals, &["4624", "4625"], false).may_match_with(&value, None)
    );
    assert!(
        !test("EventID", MatchOp::Equals, &["4624", "4634"], false).may_match_with(&value, None)
    );
    assert!(
        !test("EventID", MatchOp::Equals, &[], false).may_match_with(&value, None),
        "no value can equal nothing"
    );
}

#[test]
fn a_fixed_value_of_another_field_decides_nothing() {
    let value = fixed("EventID", "4625");
    assert!(eq("TargetUserName", "admin").may_match_with(&value, None));
}

#[test]
fn a_key_set_rules_out_absent_fields_but_not_nested_or_existence_tests() {
    let keys = paths(&["EventID", "EventData.ScriptBlockText"]);
    assert!(!eq("Image", "x").may_match_with(&[], Some(&keys)));
    assert!(
        eq("ScriptBlockText", "x").may_match_with(&[], Some(&keys)),
        "stored nested"
    );
    assert!(test("Image", MatchOp::Exists, &[], false).may_match_with(&[], Some(&keys)));
    assert!(keywords(&["x"]).may_match_with(&[], Some(&paths(&[]))));
}

#[test]
fn a_conjunction_is_ruled_out_by_any_part_and_a_disjunction_only_by_all() {
    let value = fixed("EventID", "4625");
    let wrong = eq("EventID", "1");
    let right = eq("EventID", "4625");
    assert!(!Predicate::All(vec![right.clone(), wrong.clone()]).may_match_with(&value, None));
    assert!(Predicate::Any(vec![right, wrong.clone()]).may_match_with(&value, None));
    assert!(!Predicate::Any(vec![wrong.clone(), wrong]).may_match_with(&value, None));
}

// ---------- holds_for_all_with ----------

#[test]
fn holds_for_all_only_for_equality_on_a_fixed_field() {
    let value = fixed("EventID", "4625");
    assert!(Predicate::Always.holds_for_all_with(&value));
    assert!(eq("EventID", "4625").holds_for_all_with(&value));
    assert!(!eq("EventID", "4624").holds_for_all_with(&value));
    assert!(
        !eq("TargetUserName", "x").holds_for_all_with(&value),
        "not fixed"
    );
    assert!(!keywords(&["4625"]).holds_for_all_with(&value));
    for op in [
        MatchOp::Contains,
        MatchOp::StartsWith,
        MatchOp::EndsWith,
        MatchOp::Regex,
        MatchOp::Exists,
    ] {
        assert!(
            !test("EventID", op, &["4625"], false).holds_for_all_with(&value),
            "{op:?}"
        );
    }
}

#[test]
fn holds_for_all_respects_case_sensitivity() {
    let value = fixed("Channel", "System");
    assert!(test("Channel", MatchOp::Equals, &["SYSTEM"], false).holds_for_all_with(&value));
    assert!(!test("Channel", MatchOp::Equals, &["SYSTEM"], true).holds_for_all_with(&value));
}

#[test]
fn holds_for_all_combines_like_the_connectives() {
    let value = fixed("EventID", "4625");
    let yes = eq("EventID", "4625");
    let no = eq("EventID", "1");
    assert!(Predicate::Any(vec![no.clone(), yes.clone()]).holds_for_all_with(&value));
    assert!(!Predicate::All(vec![no, yes]).holds_for_all_with(&value));
    assert!(Predicate::All(Vec::new()).holds_for_all_with(&value));
}

// ---------- serialization ----------

#[test]
fn predicates_round_trip_through_json() {
    let predicate = Predicate::All(vec![
        Predicate::Any(vec![eq("EventID", "4625"), keywords(&["mimikatz"])]),
        Predicate::present("CommandLine".into()),
    ]);
    let json = serde_json::to_string(&predicate).expect("serializes");
    assert_eq!(
        serde_json::from_str::<Predicate>(&json).expect("parses"),
        predicate
    );
}
