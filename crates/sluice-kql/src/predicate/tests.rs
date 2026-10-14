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

#[test]
fn a_field_or_column_name_kql_cannot_quote_widens_to_true() {
    let odd = compile(&test("a\u{7}b", MatchOp::Equals, &["x"], true), &[]);
    assert_eq!(odd, "true");
    let keywords = Predicate::Keywords(KeywordTest {
        values: vec!["x".into()],
        case_sensitive: true,
    });
    assert_eq!(compile(&keywords, &["Message", "bad\u{1}"]), "true");
    let newline = compile(&test("a\nb", MatchOp::Equals, &["x"], true), &[]);
    assert!(newline.contains(r"['a\nb']"), "{newline}");
}

#[test]
fn many_columns_nest_their_concatenation() {
    let columns: Vec<String> = (0..200).map(|n| format!("c{n}")).collect();
    let names: Vec<&str> = columns.iter().map(String::as_str).collect();
    let keywords = Predicate::Keywords(KeywordTest {
        values: vec!["x".into()],
        case_sensitive: true,
    });
    let kql = compile(&keywords, &names);
    for name in &names {
        assert!(
            kql.contains(&format!("tostring(['{name}'])")),
            "{name} missing"
        );
    }
    // No strcat_delim call takes more than STRCAT_MAX arguments.
    for call in kql.split("strcat_delim(").skip(1) {
        let mut depth = 1usize;
        let mut arguments = 1usize;
        for c in call.chars() {
            match c {
                '(' => depth += 1,
                ')' if depth == 1 => break,
                ')' => depth -= 1,
                ',' if depth == 1 => arguments += 1,
                _ => {}
            }
        }
        assert!(arguments <= 60, "{arguments} arguments");
    }
}

#[test]
fn case_sensitive_non_ascii_values_are_compared_not_widened() {
    let kql = compile(&test("x", MatchOp::Equals, &["straße"], true), &[]);
    assert!(kql.contains(r#"tostring(['x']) == "straße""#), "{kql}");
}

#[test]
fn every_operator_has_its_case_sensitive_and_insensitive_form() {
    for (op, insensitive, sensitive) in [
        (MatchOp::Equals, "=~", "=="),
        (MatchOp::Contains, "contains", "contains_cs"),
        (MatchOp::StartsWith, "startswith", "startswith_cs"),
        (MatchOp::EndsWith, "endswith", "endswith_cs"),
    ] {
        let folded = compile(&test("x", op, &["v"], false), &[]);
        assert!(
            folded.contains(&format!(" {insensitive} \"v\"")),
            "{folded}"
        );
        let exact = compile(&test("x", op, &["v"], true), &[]);
        assert!(exact.contains(&format!(" {sensitive} \"v\"")), "{exact}");
    }
}

#[test]
fn several_values_are_alternatives() {
    let kql = compile(&test("x", MatchOp::Equals, &["a", "b"], true), &[]);
    assert!(kql.contains(r#"== "a""#) && kql.contains(r#"== "b""#) && kql.contains(" or "));
    let empty_all = Predicate::All(vec![]);
    assert_eq!(compile(&empty_all, &[]), "true");
}
