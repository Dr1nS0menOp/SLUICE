//! Superset pre-filters as one Lua boolean expression over the record `r`.
//!
//! The VRL compilation (`sluice-vector`) defines what a predicate means; this module matches at
//! least as much (see [`crate::lua::FUNCTIONS`] for what each test does where Lua cannot tell a
//! float from an integer or an object from an array). These widen to `true`:
//!
//! - a test without values (VRL takes that as `true` too);
//! - regular expressions: Lua's patterns are no regular expressions;
//! - case-insensitive tests on non-ASCII text or values: Lua lowercases ASCII only.
//!
//! Keywords search every leaf value of the record, as VRL's scan of `flatten(.)` does.

use sluice_core::codegen::{balanced, float_may_match};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::lua;

/// Compiles `predicate` to a Lua expression that is true on at least every record the VRL that
/// Vector runs matches.
#[must_use]
pub fn compile(predicate: &Predicate) -> String {
    let all = |parts: &[Predicate]| parts.iter().map(compile).collect::<Vec<_>>();
    match predicate {
        Predicate::Always => "true".to_owned(),
        Predicate::Any(parts) => balanced(&all(parts), " or ", "false"),
        Predicate::All(parts) => balanced(&all(parts), " and ", "true"),
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
        MatchOp::Exists => return format!("sluice_has(r, {})", lua::segments(&test.field)),
        MatchOp::Regex => return "true".to_owned(),
    };
    let Some(values) = values(&test.values, test.case_sensitive) else {
        return "true".to_owned();
    };
    format!(
        "sluice_test(sluice_get(r, {}), {op}, {}, {}, {values})",
        lua::segments(&test.field),
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
        "sluice_doc_words(r, {}, {}, {values})",
        test.case_sensitive,
        float_may_match(&test.values)
    )
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
    Some(lua::list(values.iter().map(String::as_str)))
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
            r#"sluice_test(sluice_get(r, {"process", "name"}), 3, false, false, {"cmd.exe"})"#
        );
        assert_eq!(
            compile(&test("EventID", MatchOp::Equals, &["4625"], true)),
            r#"sluice_test(sluice_get(r, {"EventID"}), 0, true, true, {"4625"})"#
        );
    }

    #[test]
    fn superset_what_lua_cannot_decide_like_vrl_is_true() {
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
    }

    #[test]
    fn exists_connectives_and_keywords() {
        assert_eq!(
            compile(&test("file.hash", MatchOp::Exists, &[], false)),
            r#"sluice_has(r, {"file", "hash"})"#
        );
        assert_eq!(compile(&Predicate::Any(vec![])), "false");
        assert_eq!(compile(&Predicate::All(vec![])), "true");
        let a = test("a", MatchOp::Equals, &["1"], true);
        let b = test("b", MatchOp::Equals, &["2"], true);
        assert!(compile(&Predicate::All(vec![a.clone(), b.clone()])).contains(" and "));
        assert!(compile(&Predicate::Any(vec![a, b])).contains(" or "));
        assert_eq!(
            compile(&Predicate::Keywords(KeywordTest {
                values: vec!["Mimikatz".into()],
                case_sensitive: false,
            })),
            r#"sluice_doc_words(r, false, false, {"mimikatz"})"#
        );
    }

    #[test]
    fn hostile_values_stay_literals() {
        assert_eq!(
            compile(&test(
                "a\"b",
                MatchOp::Equals,
                &["x\") os.exit() (\""],
                true
            )),
            r#"sluice_test(sluice_get(r, {"a\"b"}), 0, true, false, {"x\") os.exit() (\""})"#
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
