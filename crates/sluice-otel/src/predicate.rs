//! Superset pre-filters as one OTTL condition over a log record's map (`log.body`).
//!
//! The VRL compilation (`sluice-vector`) defines what a predicate means; this module matches at
//! least as much, and every test is guarded by type checks, so a condition never fails on a
//! value of another type. The collector's JSON parser makes every number a double, so a whole
//! number is compared as an integer's text and, when a value could be a float's, is true too.
//! These widen to `true`:
//!
//! - a test without values (VRL takes that as `true` too), and regular expressions: RE2 is not
//!   Rust's engine;
//! - a test on an object or an array: OTTL cannot look through an array's members;
//! - a number past 2^53, whose text the collector may have changed;
//! - case-insensitive tests on non-ASCII text or values: Go and Rust fold case differently;
//! - keywords on a record with an array that may hold an object or an array, which VRL lets
//!   match;
//! - keywords Go's JSON writer escapes (`"`, `\`, `<`, `>`, `&`, control and non-ASCII
//!   characters), as keywords search the record's JSON text, keys included.

use sluice_core::codegen::{balanced, float_may_match, folded_values};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::ottl;

/// Compiles `predicate` to an OTTL condition on the map at `root` (`log.body`) that is true on
/// at least every record the VRL that Vector runs matches.
#[must_use]
pub fn compile(predicate: &Predicate, root: &str) -> String {
    match predicate {
        Predicate::Always => "true".to_owned(),
        Predicate::Any(parts) => balanced(
            &parts.iter().map(|p| compile(p, root)).collect::<Vec<_>>(),
            " or ",
            "false",
        ),
        Predicate::All(parts) => balanced(
            &parts.iter().map(|p| compile(p, root)).collect::<Vec<_>>(),
            " and ",
            "true",
        ),
        Predicate::Field(test) => guarded(root, &test.field, &field(test, root)),
        Predicate::Keywords(test) => keywords(test, root),
    }
}

fn field(test: &FieldTest, root: &str) -> String {
    let x = ottl::path(root, &test.field);
    let (start, end) = match test.op {
        MatchOp::Equals => ("^", "$"),
        MatchOp::Contains => ("", ""),
        MatchOp::StartsWith => ("^", ""),
        MatchOp::EndsWith => ("", "$"),
        MatchOp::Exists => return exists(test, root),
        MatchOp::Regex => return "true".to_owned(),
    };
    let Some(pattern) = pattern(&test.values, test.case_sensitive, start, end) else {
        return "true".to_owned();
    };
    let pattern = ottl::string(&pattern);
    let on_string = if test.case_sensitive {
        format!("IsMatch({x}, {pattern})")
    } else {
        format!("(IsMatch({x}, \"[^\\\\x00-\\\\x7f]\") or IsMatch({x}, {pattern}))")
    };
    let number = if float_may_match(&test.values) {
        "true".to_owned()
    } else {
        format!(
            "({x} >= 9007199254740992 or {x} <= -9007199254740992 or IsMatch(String({x}), \
             {pattern}))"
        )
    };
    format!(
        "(IsMap({x}) or IsList({x}) or (IsString({x}) and {on_string}) or ((IsDouble({x}) or \
         IsInt({x})) and {number}) or (IsBool({x}) and IsMatch(String({x}), {pattern})))"
    )
}

/// VRL's `exists`: the path is there, null or not. OTTL reads a null as `nil`, so a null one is
/// found in the parent's JSON text (`"key":null`, anywhere in it: a superset); a key Go's JSON
/// writer escapes widens to `true`.
fn exists(test: &FieldTest, root: &str) -> String {
    let x = ottl::path(root, &test.field);
    let segments: Vec<&str> = test.field.segments().collect();
    let Some((last, parents)) = segments.split_last() else {
        return "true".to_owned();
    };
    if last
        .chars()
        .any(|c| !c.is_ascii() || c.is_control() || "\"\\<>&".contains(c))
    {
        return "true".to_owned();
    }
    let parent = parents.iter().fold(root.to_owned(), |at, s| {
        format!("{at}[{}]", ottl::string(s))
    });
    let null = ottl::string(&ottl::quote_meta(&format!("\"{last}\":null")));
    format!("({x} != nil or IsMatch(String({parent}), {null}))")
}

fn keywords(test: &KeywordTest, root: &str) -> String {
    if test.values.is_empty() {
        return "false".to_owned();
    }
    let escaped = |v: &String| {
        v.chars()
            .any(|c| !c.is_ascii() || c.is_control() || "\"\\<>&".contains(c))
    };
    if test.values.iter().any(escaped) {
        return "true".to_owned();
    }
    let Some(pattern) = pattern(&test.values, test.case_sensitive, "", "") else {
        return "true".to_owned();
    };
    // VRL lets an array member that is an object or an array match; no pattern can find one
    // exactly in JSON text, so any `[` with a `{` or `[` after it counts.
    format!(
        "(IsMatch(String({root}), {}) or IsMatch(String({root}), \"(?s)\\\\[.*[\\\\[{{]\"))",
        ottl::string(&pattern)
    )
}

/// `condition` on the value at `field`, behind tests that each map on the way is one: indexing
/// a string or a list into is an error in OTTL, and the conditions are evaluated in order.
fn guarded(root: &str, field: &sluice_core::field::FieldPath, condition: &str) -> String {
    let segments: Vec<&str> = field.segments().collect();
    if segments.len() < 2 || condition == "true" {
        return condition.to_owned();
    }
    let mut at = root.to_owned();
    let mut parts = Vec::new();
    for segment in &segments[..segments.len() - 1] {
        at = format!("{at}[{}]", ottl::string(segment));
        parts.push(format!("IsMap({at})"));
    }
    parts.push(condition.to_owned());
    format!("({})", parts.join(" and "))
}

/// The RE2 pattern matching any of the [`folded_values`] between `start` and `end` anchors;
/// `None` where the test must widen.
fn pattern(values: &[String], case_sensitive: bool, start: &str, end: &str) -> Option<String> {
    let values = folded_values(values, case_sensitive)?;
    let alternatives: Vec<String> = values.iter().map(|v| ottl::quote_meta(v)).collect();
    let flags = if case_sensitive { "(?s)" } else { "(?is)" };
    Some(format!("{flags}{start}(?:{}){end}", alternatives.join("|")))
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
    fn a_field_test_is_guarded_by_types_and_matches_literally() {
        let out = compile(
            &test("process.name", MatchOp::EndsWith, &["CMD.exe"], false),
            "log.body",
        );
        assert!(
            out.contains(r#"IsString(log.body["process"]["name"])"#),
            "{out}"
        );
        assert!(out.contains(r#""(?is)(?:cmd\\.exe)$""#), "{out}");
        assert!(out.contains("x7f"), "non-ASCII text widens: {out}");
        let number = compile(
            &test("EventID", MatchOp::Equals, &["4625"], true),
            "log.body",
        );
        assert!(
            number.contains("IsInt(log.body[\"EventID\"])) and true)"),
            "{number}"
        );
    }

    #[test]
    fn superset_what_ottl_cannot_decide_like_vrl_is_true() {
        for widened in [
            test("a", MatchOp::Regex, &["x.*"], true),
            test("a", MatchOp::Equals, &[], false),
            test("a", MatchOp::Equals, &["Straße"], false),
            Predicate::Keywords(KeywordTest {
                values: vec!["<script>".into()],
                case_sensitive: true,
            }),
            Predicate::Keywords(KeywordTest {
                values: vec!["É".into()],
                case_sensitive: true,
            }),
        ] {
            assert_eq!(compile(&widened, "log.body"), "true", "{widened:?}");
        }
    }

    #[test]
    fn exists_connectives_and_keywords() {
        assert_eq!(
            compile(&test("file.hash", MatchOp::Exists, &[], false), "log.body"),
            r#"(IsMap(log.body["file"]) and (log.body["file"]["hash"] != nil or IsMatch(String(log.body["file"]), "\"hash\":null")))"#
        );
        assert_eq!(compile(&Predicate::Any(vec![]), "log.body"), "false");
        assert_eq!(compile(&Predicate::All(vec![]), "log.body"), "true");
        assert_eq!(
            compile(
                &Predicate::Keywords(KeywordTest {
                    values: vec!["Mimikatz".into()],
                    case_sensitive: false,
                }),
                "log.body"
            ),
            r#"(IsMatch(String(log.body), "(?is)(?:mimikatz)") or IsMatch(String(log.body), "(?s)\\[.*[\\[{]"))"#
        );
    }

    #[test]
    fn hostile_values_stay_literals() {
        let out = compile(
            &test("a\"b", MatchOp::Equals, &["x\") or true or (\""], true),
            "log.body",
        );
        assert!(out.contains(r#"log.body["a\"b"]"#), "{out}");
        assert!(
            out.contains(r#""(?s)^(?:x\"\\) or true or \\(\")$""#),
            "{out}"
        );
    }
}
