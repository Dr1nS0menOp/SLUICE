//! Superset pre-filters as one KQL boolean expression over the column model.
//!
//! The VRL compilation (`sluice-vector`) defines what a predicate means; this module matches at
//! least as much. A field test is `true` on an array, object, float or boolean value (as in VRL,
//! plus floats and booleans, whose text KQL renders differently), `false` on a missing or null
//! field, and otherwise compares the value's text. These widen to `true`:
//!
//! - `exists`: a null column and a missing one look the same;
//! - regular expressions: KQL's engine (RE2) is not VRL's;
//! - case-insensitive tests on non-ASCII text: KQL and Rust fold case differently;
//! - values a KQL literal here does not carry (control characters).
//!
//! Keywords test the text of every column, joined: that also sees object keys and booleans, so
//! it matches more than VRL's scan of values, never less.

use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::syntax;

/// Types whose test widens to `true`: VRL matches inside arrays and objects, and floats,
/// booleans, dates, timespans and GUIDs render as different text in the two engines (KQL turns
/// an ISO 8601 string into a `datetime` and prints it back without fractional zeros).
const WIDENED_TYPES: &str =
    r#"("array", "dictionary", "real", "bool", "datetime", "timespan", "guid")"#;

/// Most arguments `strcat_delim` takes (the delimiter included).
const STRCAT_MAX: usize = 60;

/// True when the text holds a non-ASCII character, where case folding may differ.
const NON_ASCII: &str = r#""[^\\x00-\\x7f]""#;

/// Compiles `predicate` to a KQL expression over the columns of the column model. `columns` is
/// every top-level field of the source, which keyword tests scan.
#[must_use]
pub fn compile(predicate: &Predicate, columns: &[&str]) -> String {
    match predicate {
        Predicate::Always => "true".to_owned(),
        Predicate::Any(parts) if parts.is_empty() => "false".to_owned(),
        Predicate::All(parts) if parts.is_empty() => "true".to_owned(),
        Predicate::Any(parts) => balanced(
            &parts
                .iter()
                .map(|p| compile(p, columns))
                .collect::<Vec<_>>(),
            " or ",
        ),
        Predicate::All(parts) => balanced(
            &parts
                .iter()
                .map(|p| compile(p, columns))
                .collect::<Vec<_>>(),
            " and ",
        ),
        Predicate::Field(test) => field(test),
        Predicate::Keywords(test) => keywords(test, columns),
    }
}

fn field(test: &FieldTest) -> String {
    if test.op == MatchOp::Exists || test.values.is_empty() {
        return "true".to_owned();
    }
    let Some(value) = syntax::path(&test.field) else {
        return "true".to_owned();
    };
    let rendered = format!("tostring({value})");
    let comparisons: Option<Vec<String>> = test
        .values
        .iter()
        .map(|v| comparison(&rendered, test.op, v, test.case_sensitive))
        .collect();
    let Some(comparisons) = comparisons else {
        return "true".to_owned();
    };
    let mut alternatives = vec![format!("gettype({value}) in {WIDENED_TYPES}")];
    if !test.case_sensitive {
        alternatives.push(format!("{rendered} matches regex {NON_ASCII}"));
    }
    alternatives.extend(comparisons);
    format!(
        "(isnotnull({value}) and {})",
        balanced(&alternatives, " or ")
    )
}

fn keywords(test: &KeywordTest, columns: &[&str]) -> String {
    if test.values.is_empty() {
        return "false".to_owned();
    }
    if columns.is_empty() {
        return "true".to_owned();
    }
    let Some(names) = columns
        .iter()
        .map(|c| syntax::quoted_name(c))
        .collect::<Option<Vec<String>>>()
    else {
        return "true".to_owned();
    };
    let rendered = joined(
        &names
            .iter()
            .map(|n| format!("tostring({n})"))
            .collect::<Vec<_>>(),
    );
    let comparisons: Option<Vec<String>> = test
        .values
        .iter()
        .map(|v| comparison(&rendered, MatchOp::Contains, v, test.case_sensitive))
        .collect();
    let Some(comparisons) = comparisons else {
        return "true".to_owned();
    };
    let mut alternatives: Vec<String> = names
        .iter()
        .map(|n| format!("gettype({n}) in {WIDENED_TYPES}"))
        .collect();
    if !test.case_sensitive {
        alternatives.push(format!("{rendered} matches regex {NON_ASCII}"));
    }
    alternatives.extend(comparisons);
    balanced(&alternatives, " or ")
}

/// `texts` joined with newlines, nesting `strcat_delim` where it would take too many arguments.
fn joined(texts: &[String]) -> String {
    match texts {
        [] => r#""""#.to_owned(),
        [one] => one.clone(),
        _ if texts.len() < STRCAT_MAX => format!(r#"strcat_delim("\n", {})"#, texts.join(", ")),
        _ => joined(&texts.chunks(STRCAT_MAX - 1).map(joined).collect::<Vec<_>>()),
    }
}

/// One comparison of `text` with `value`, or `None` where the test must widen.
fn comparison(text: &str, op: MatchOp, value: &str, case_sensitive: bool) -> Option<String> {
    if !case_sensitive && !value.is_ascii() {
        return None;
    }
    let literal = syntax::string(value)?;
    let operator = match (op, case_sensitive) {
        (MatchOp::Equals, false) => "=~",
        (MatchOp::Equals, true) => "==",
        (MatchOp::Contains, false) => "contains",
        (MatchOp::Contains, true) => "contains_cs",
        (MatchOp::StartsWith, false) => "startswith",
        (MatchOp::StartsWith, true) => "startswith_cs",
        (MatchOp::EndsWith, false) => "endswith",
        (MatchOp::EndsWith, true) => "endswith_cs",
        (MatchOp::Regex | MatchOp::Exists, _) => return None,
    };
    Some(format!("{text} {operator} {literal}"))
}

/// Joins `parts` as a balanced tree of parentheses, so thousands of rule tests stay shallow.
fn balanced(parts: &[String], operator: &str) -> String {
    match parts {
        [] => if operator.contains("or") {
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
mod tests;
