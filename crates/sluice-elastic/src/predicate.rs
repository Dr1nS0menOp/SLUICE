//! Superset pre-filters as one Painless boolean expression over `ctx`.
//!
//! The VRL compilation (`sluice-vector`) defines what a predicate means; this module matches at
//! least as much. A field test is `true` on an array, object or float value and `false` on a
//! missing or null field, as in VRL, and otherwise compares the value's text (`String.valueOf`
//! renders strings, integers and booleans as VRL's `to_string` does). These widen to `true`:
//!
//! - `exists`, and a test without values (VRL takes that as `true` too);
//! - regular expressions: Java's engine is not Rust's, and Painless limits regexes;
//! - case-insensitive tests on non-ASCII text or values: Java and Rust fold case differently.
//!
//! Keywords search every leaf value of the document, as VRL's scan of `flatten(.)` does.

use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::painless;

/// Compiles `predicate` to a Painless expression that is true on at least every document the
/// VRL that Vector runs matches.
#[must_use]
pub fn compile(predicate: &Predicate) -> String {
    match predicate {
        Predicate::Always => "true".to_owned(),
        Predicate::Any(parts) => balanced(&parts.iter().map(compile).collect::<Vec<_>>(), " || "),
        Predicate::All(parts) => balanced(&parts.iter().map(compile).collect::<Vec<_>>(), " && "),
        Predicate::Field(test) => field(test),
        Predicate::Keywords(test) => keywords(test),
    }
}

fn field(test: &FieldTest) -> String {
    let op = match test.op {
        MatchOp::Equals => 0,
        MatchOp::Contains => 1,
        MatchOp::StartsWith => 2,
        MatchOp::EndsWith => 3,
        MatchOp::Regex | MatchOp::Exists => return "true".to_owned(),
    };
    let Some(values) = values(&test.values, test.case_sensitive) else {
        return "true".to_owned();
    };
    format!(
        "sluiceTest(sluiceGet(ctx, {}), {op}, {}, {values})",
        painless::segments(&test.field),
        test.case_sensitive
    )
}

fn keywords(test: &KeywordTest) -> String {
    if test.values.is_empty() {
        return "false".to_owned();
    }
    let Some(values) = values(&test.values, test.case_sensitive) else {
        return "true".to_owned();
    };
    format!("sluiceDocWords(ctx, {}, {values})", test.case_sensitive)
}

/// The values as a list literal, lowercased for a case-insensitive test; `None` where the test
/// must widen: no values, or a case-insensitive one that is not ASCII.
fn values(values: &[String], case_sensitive: bool) -> Option<String> {
    if values.is_empty() || (!case_sensitive && values.iter().any(|v| !v.is_ascii())) {
        return None;
    }
    let values: Vec<String> = values
        .iter()
        .map(|v| {
            if case_sensitive {
                v.clone()
            } else {
                v.to_ascii_lowercase()
            }
        })
        .collect();
    Some(painless::list(values.iter().map(String::as_str)))
}

/// Joins `parts` as a balanced tree of parentheses, so thousands of rule tests stay shallow for
/// Painless's parser. Nothing joined is the operator's neutral element.
fn balanced(parts: &[String], operator: &str) -> String {
    match parts {
        [] => if operator.contains("||") {
            "false"
        } else {
            "true"
        }
        .to_owned(),
        [one] => one.clone(),
        _ => {
            let (left, right) = parts.split_at(parts.len() / 2);
            format!(
                "({}{operator}{})",
                balanced(left, operator),
                balanced(right, operator)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(field: &str, op: MatchOp, values: &[&str], case_sensitive: bool) -> Predicate {
        Predicate::Field(FieldTest {
            field: field.into(),
            op,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
            case_sensitive,
        })
    }

    #[test]
    fn a_field_test_reads_the_path_and_lowercases_insensitive_values() {
        assert_eq!(
            compile(&test(
                "process.name",
                MatchOp::EndsWith,
                &["CMD.exe"],
                false
            )),
            "sluiceTest(sluiceGet(ctx, ['process', 'name']), 3, false, ['cmd.exe'])"
        );
        assert_eq!(
            compile(&test("User", MatchOp::Equals, &["Bob"], true)),
            "sluiceTest(sluiceGet(ctx, ['User']), 0, true, ['Bob'])"
        );
    }

    #[test]
    fn superset_what_painless_cannot_decide_like_vrl_is_true() {
        for widened in [
            test("a", MatchOp::Regex, &["x.*"], true),
            test("a", MatchOp::Exists, &[], true),
            test("a", MatchOp::Equals, &[], false),
            test("a", MatchOp::Equals, &["Straße"], false),
            Predicate::Keywords(KeywordTest {
                values: vec!["É".into()],
                case_sensitive: false,
            }),
        ] {
            assert_eq!(compile(&widened), "true", "{widened:?}");
        }
        assert_eq!(
            compile(&test("a", MatchOp::Equals, &["Straße"], true)),
            "sluiceTest(sluiceGet(ctx, ['a']), 0, true, ['Straße'])",
            "case-sensitive non-ASCII compares exactly"
        );
    }

    #[test]
    fn connectives_and_their_empty_forms() {
        let a = test("a", MatchOp::Equals, &["1"], true);
        let b = test("b", MatchOp::Equals, &["2"], true);
        let c = test("c", MatchOp::Equals, &["3"], true);
        let any = compile(&Predicate::Any(vec![a.clone(), b.clone(), c]));
        assert!(
            any.starts_with("(sluiceTest") && any.matches(" || ").count() == 2,
            "{any}"
        );
        assert_eq!(compile(&Predicate::Any(vec![])), "false");
        assert_eq!(compile(&Predicate::All(vec![])), "true");
        assert_eq!(compile(&Predicate::Always), "true");
        assert!(compile(&Predicate::All(vec![a, b])).contains(" && "));
    }

    #[test]
    fn keywords_search_the_document_and_none_match_nothing() {
        assert_eq!(
            compile(&Predicate::Keywords(KeywordTest {
                values: vec!["Mimikatz".into()],
                case_sensitive: false,
            })),
            "sluiceDocWords(ctx, false, ['mimikatz'])"
        );
        assert_eq!(
            compile(&Predicate::Keywords(KeywordTest {
                values: vec![],
                case_sensitive: false,
            })),
            "false"
        );
    }

    #[test]
    fn hostile_values_stay_literals() {
        assert_eq!(
            compile(&test(
                "a'b",
                MatchOp::Equals,
                &["x'); ctx.clear(); ('", "back\\slash"],
                true
            )),
            r"sluiceTest(sluiceGet(ctx, ['a\'b']), 0, true, ['x\'); ctx.clear(); (\'', 'back\\slash'])"
        );
    }

    #[test]
    fn many_tests_nest_logarithmically() {
        let parts: Vec<Predicate> = (0..1024)
            .map(|n| test("a", MatchOp::Equals, &[&n.to_string()], true))
            .collect();
        let compiled = compile(&Predicate::Any(parts));
        let mut depth = 0usize;
        let mut deepest = 0usize;
        for c in compiled.chars() {
            match c {
                '(' => {
                    depth += 1;
                    deepest = deepest.max(depth);
                }
                ')' => depth -= 1,
                _ => {}
            }
        }
        assert!(deepest < 20, "{deepest}");
    }
}
