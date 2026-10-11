use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use super::compile;

fn test(field: &str, op: MatchOp, values: &[&str], case_sensitive: bool) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive,
    })
}

#[test]
fn field_tests_need_a_value_and_widen_on_structures() {
    let kql = compile(&test("EventID", MatchOp::Equals, &["4624"], false), &[]);
    assert!(kql.starts_with("(isnotnull(['EventID']) and "), "{kql}");
    assert!(
        kql.contains(
            r#"gettype(['EventID']) in ("array", "dictionary", "real", "bool", "datetime""#
        )
    );
    assert!(kql.contains(r#"tostring(['EventID']) =~ "4624""#));
    // Case-insensitive tests widen on non-ASCII text, where case folding may differ.
    assert!(kql.contains("matches regex"));

    let exact = compile(&test("a.b", MatchOp::Contains, &["X"], true), &[]);
    assert!(
        exact.contains(r#"tostring(['a']['b']) contains_cs "X""#),
        "{exact}"
    );
    assert!(
        !exact.contains("matches regex"),
        "ordinal comparisons need no guard"
    );
}

#[test]
fn what_kql_cannot_decide_alike_widens_to_true() {
    for widened in [
        test("x", MatchOp::Regex, &["^a.*b$"], false),
        test("x", MatchOp::Exists, &[], false),
        test("x", MatchOp::Equals, &["straße"], false),
        test("x", MatchOp::Equals, &["a\u{1}b"], true),
        test("x", MatchOp::Equals, &[], false),
    ] {
        assert_eq!(compile(&widened, &[]), "true", "{widened:?}");
    }
    // A widened part widens only itself.
    let mixed = Predicate::All(vec![
        test("x", MatchOp::Regex, &["a"], false),
        test("y", MatchOp::Equals, &["b"], false),
    ]);
    assert!(compile(&mixed, &[]).starts_with("(true and "));
}

#[test]
fn keywords_scan_every_column() {
    let keywords = Predicate::Keywords(KeywordTest {
        values: vec!["mimikatz".into()],
        case_sensitive: false,
    });
    let kql = compile(&keywords, &["Message", "CommandLine"]);
    assert!(kql.contains(
        r#"strcat_delim("\n", tostring(['Message']), tostring(['CommandLine'])) contains "mimikatz""#
    ));
    assert_eq!(compile(&keywords, &[]), "true", "no columns known");
    let none = Predicate::Keywords(KeywordTest {
        values: vec![],
        case_sensitive: false,
    });
    assert_eq!(compile(&none, &["Message"]), "false");
}

#[test]
fn boolean_structure_is_balanced() {
    assert_eq!(compile(&Predicate::Always, &[]), "true");
    assert_eq!(compile(&Predicate::never(), &[]), "false");
    let many = Predicate::Any(
        (0..1000)
            .map(|n| test("EventID", MatchOp::Equals, &[&n.to_string()], true))
            .collect(),
    );
    let kql = compile(&many, &[]);
    let mut depth = 0usize;
    let mut deepest = 0usize;
    for c in kql.chars() {
        match c {
            '(' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    assert!(deepest < 40, "depth {deepest}");
}
