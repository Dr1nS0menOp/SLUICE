//! Superset pre-filters as one Painless boolean expression over `ctx`.
//!
//! The VRL compilation (`sluice-vector`) defines what a predicate means; this module matches at
//! least as much. As in VRL, a field test is `true` on an object, on a float when a value could
//! be a number's text, and `false` on a missing or null field; an array matches when a member
//! does; otherwise it compares the value's text (`String.valueOf` renders strings, integers and
//! booleans as VRL's `to_string` does). These widen to `true`:
//!
//! - a test without values (VRL takes that as `true` too);
//! - regular expressions: Java's engine is not Rust's, and Painless limits regexes;
//! - case-insensitive tests on non-ASCII text or values: Java and Rust fold case differently.
//!
//! Keywords search every leaf value of the document, as VRL's scan of `flatten(.)` does.

use sluice_core::codegen::{balanced, float_may_match, folded_values};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::painless;

/// Compiles `predicate` to a Painless expression that is true on at least every document the
/// VRL that Vector runs matches.
#[must_use]
pub fn compile(predicate: &Predicate) -> String {
    let all = |parts: &[Predicate]| parts.iter().map(compile).collect::<Vec<_>>();
    match predicate {
        Predicate::Always => "true".to_owned(),
        Predicate::Any(parts) => balanced(&all(parts), " || ", "false"),
        Predicate::All(parts) => balanced(&all(parts), " && ", "true"),
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
        // VRL's `exists`: the path is there, null or not.
        MatchOp::Exists => {
            return format!("sluiceHas(ctx, {})", painless::segments(&test.field));
        }
        MatchOp::Regex => return "true".to_owned(),
    };
    let Some(values) = values(&test.values, test.case_sensitive) else {
        return "true".to_owned();
    };
    format!(
        "sluiceTest(sluiceGet(ctx, {}), {op}, {}, {}, {values})",
        painless::segments(&test.field),
        test.case_sensitive,
        float_may_match(&test.values)
    )
}

fn keywords(test: &KeywordTest) -> String {
    if test.values.is_empty() {
        return "false".to_owned();
    }
    let Some(values) = values(&test.values, test.case_sensitive) else {
        return "true".to_owned();
    };
    format!(
        "sluiceDocWords(ctx, {}, {}, {values})",
        test.case_sensitive,
        float_may_match(&test.values)
    )
}

/// The [`folded_values`] as a list literal; `None` where the test must widen.
fn values(values: &[String], case_sensitive: bool) -> Option<String> {
    let values = folded_values(values, case_sensitive)?;
    Some(painless::list(values.iter().map(String::as_str)))
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
            "sluiceTest(sluiceGet(ctx, ['process', 'name']), 3, false, false, ['cmd.exe'])"
        );
        assert_eq!(
            compile(&test("User", MatchOp::Equals, &["Bob"], true)),
            "sluiceTest(sluiceGet(ctx, ['User']), 0, true, false, ['Bob'])"
        );
    }

    #[test]
    fn superset_what_painless_cannot_decide_like_vrl_is_true() {
        for widened in [
            test("a", MatchOp::Regex, &["x.*"], true),
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
            "sluiceTest(sluiceGet(ctx, ['a']), 0, true, false, ['Straße'])",
            "case-sensitive non-ASCII compares exactly"
        );
    }

    #[test]
    fn exists_is_the_path_being_there() {
        assert_eq!(
            compile(&test("file.hash", MatchOp::Exists, &[], false)),
            "sluiceHas(ctx, ['file', 'hash'])"
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
            "sluiceDocWords(ctx, false, false, ['mimikatz'])"
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
            r"sluiceTest(sluiceGet(ctx, ['a\'b']), 0, true, false, ['x\'); ctx.clear(); (\'', 'back\\slash'])"
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
