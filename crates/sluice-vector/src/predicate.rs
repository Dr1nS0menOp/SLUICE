//! Superset pre-filters as VRL.
//!
//! A [`Predicate`] compiles to VRL statements that each compute one field test into a variable,
//! plus a boolean expression over those variables. Tests become separate statements rather than
//! nested blocks, because a `{ … }` inside an expression can parse as an object literal.
//!
//! Every place where VRL cannot express a test exactly *widens* it to `true`:
//!
//! - an array or object value (a Sigma engine may match its members);
//! - a regex that VRL's engine (Rust `regex`) cannot compile, or cannot quote.
//!
//! Missing and null fields make a test false, as they do in Sigma.

use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::syntax;

/// A predicate compiled to VRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledPredicate {
    /// Statements to run first, in order.
    pub(crate) statements: Vec<String>,
    /// A boolean expression over the variables the statements set.
    pub(crate) expression: String,
}

/// Compiles a predicate. Variables are prefixed with `prefix`, so several predicates can share
/// one program.
pub(crate) fn compile(predicate: &Predicate, prefix: &str) -> CompiledPredicate {
    let mut compiler = Compiler {
        prefix,
        statements: Vec::new(),
        next: 0,
    };
    let expression = compiler.expression(predicate);
    CompiledPredicate {
        statements: compiler.statements,
        expression,
    }
}

struct Compiler<'a> {
    prefix: &'a str,
    statements: Vec<String>,
    next: usize,
}

impl Compiler<'_> {
    fn expression(&mut self, predicate: &Predicate) -> String {
        match predicate {
            Predicate::Always => "true".to_owned(),
            Predicate::Any(parts) if parts.is_empty() => "false".to_owned(),
            Predicate::All(parts) if parts.is_empty() => "true".to_owned(),
            Predicate::Any(parts) => self.join(parts, " || "),
            Predicate::All(parts) => self.join(parts, " && "),
            Predicate::Field(test) => self.test(test),
            Predicate::Keywords(test) => self.keywords(test),
        }
    }

    /// Emits a scan over every leaf value of the event for any of the keywords.
    ///
    /// `flatten` makes nested objects leaves; an array leaf may hold a matching member, and a
    /// float's decimal text may differ between engines, so both widen to true. Integers are
    /// compared as their decimal text and strings directly, as Sigma engines do. Booleans and
    /// nulls never match.
    fn keywords(&mut self, test: &KeywordTest) -> String {
        let var = format!("{}{}", self.prefix, self.next);
        self.next += 1;
        if test.values.is_empty() {
            self.statements.push(format!("{var} = false"));
            return var;
        }
        let value = format!("{var}_v");
        let rendered = format!("{var}_s");
        let checks = keyword_checks(&rendered, test);
        self.statements.push(format!("{var} = false"));
        self.statements.push(format!(
            "for_each(values(flatten(.))) -> |_index, {value}| {{\n  \
               if is_array({value}) || is_float({value}) {{ {var} = true }} \
               else if is_string({value}) || is_integer({value}) {{\n    \
                 {rendered} = to_string!({value})\n    \
                 if {checks} {{ {var} = true }}\n  \
               }}\n}}"
        ));
        var
    }

    fn join(&mut self, parts: &[Predicate], operator: &str) -> String {
        let parts: Vec<String> = parts.iter().map(|p| self.expression(p)).collect();
        balanced(&parts, operator)
    }

    /// Emits the statements for one field test and returns the variable holding its result.
    fn test(&mut self, test: &FieldTest) -> String {
        let var = format!("{}{}", self.prefix, self.next);
        self.next += 1;
        let path = syntax::path(&test.field);

        if test.op == MatchOp::Exists {
            self.statements.push(format!("{var} = exists({path})"));
            return var;
        }
        let value = format!("{var}_v");
        let rendered = format!("{var}_s");
        if let Some(alternation) = literal_alternation(&rendered, test) {
            self.statements.push(format!("{var} = false"));
            self.statements.push(format!("{value} = {path}"));
            self.statements.push(format!(
                "if is_array({value}) || is_object({value}) {{ {var} = true }} \
                 else if !is_null({value}) {{ {rendered} = to_string!({value}); {var} = {alternation} }}"
            ));
            return var;
        }
        let comparisons: Option<Vec<String>> = test
            .values
            .iter()
            .map(|v| comparison(&rendered, test.op, v, test.case_sensitive))
            .collect();
        let Some(comparisons) = comparisons.filter(|c| !c.is_empty()) else {
            self.statements.push(format!("{var} = true"));
            return var;
        };
        let matches = balanced(&comparisons, " || ");
        self.statements.push(format!("{var} = false"));
        self.statements.push(format!("{value} = {path}"));
        self.statements.push(format!(
            "if is_array({value}) || is_object({value}) {{ {var} = true }} \
             else if !is_null({value}) {{ {rendered} = to_string!({value}); {var} = {matches} }}"
        ));
        var
    }
}

/// A field test with many literal values as one anchored alternation over the value, lowercased
/// once for case-insensitive tests (what `downcase(…) ==` and `contains(…, case_sensitive:
/// false)` do per value); `None` for few values, regexes, or a pattern VRL cannot take.
fn literal_alternation(rendered: &str, test: &FieldTest) -> Option<String> {
    let (prefix, suffix) = match test.op {
        MatchOp::Equals => ("^", "$"),
        MatchOp::Contains => ("", ""),
        MatchOp::StartsWith => ("^", ""),
        MatchOp::EndsWith => ("", "$"),
        MatchOp::Regex | MatchOp::Exists => return None,
    };
    if test.values.len() < KEYWORD_REGEX_MIN {
        return None;
    }
    alternation(rendered, &test.values, test.case_sensitive, prefix, suffix)
}

/// `match(text, r'prefix(?:v1|v2|…)suffix')` over escaped literals, lowercasing both sides
/// when case-insensitive.
fn alternation(
    text: &str,
    values: &[String],
    case_sensitive: bool,
    prefix: &str,
    suffix: &str,
) -> Option<String> {
    let literals: Vec<String> = values
        .iter()
        .map(|v| {
            regex::escape(&if case_sensitive {
                v.clone()
            } else {
                v.to_lowercase()
            })
        })
        .collect();
    let pattern = format!("{prefix}(?:{}){suffix}", literals.join("|"));
    regex::Regex::new(&pattern).ok()?;
    let quoted = syntax::regex(&pattern)?;
    let haystack = if case_sensitive {
        text.to_owned()
    } else {
        format!("downcase({text})")
    };
    Some(format!("match({haystack}, {quoted})"))
}

/// Above this many keywords, one regex alternation replaces a `contains` per keyword.
const KEYWORD_REGEX_MIN: usize = 5;

/// The test of the rendered value in `text` against the keywords: `contains` calls for a few,
/// one alternation of escaped literals for many (Rust's regex runs it as a single `Aho-Corasick`
/// scan). Case-insensitive alternations lowercase value and literals, exactly as
/// `contains(…, case_sensitive: false)` does, so both forms decide alike.
fn keyword_checks(rendered: &str, test: &KeywordTest) -> String {
    let contains = || {
        balanced(
            &test
                .values
                .iter()
                .map(|k| call("contains", rendered, k, test.case_sensitive))
                .collect::<Vec<_>>(),
            " || ",
        )
    };
    if test.values.len() < KEYWORD_REGEX_MIN {
        return contains();
    }
    alternation(rendered, &test.values, test.case_sensitive, "", "").unwrap_or_else(contains)
}

/// Joins `parts` with a binary `operator` as a balanced tree of parentheses. VRL parses and
/// type-checks `a || b || c …` recursively, one level per operand, so a pre-filter over the
/// thousands of `SigmaHQ` rules overflowed the stack; halving keeps the depth logarithmic.
fn balanced(parts: &[String], operator: &str) -> String {
    match parts {
        [] => unreachable_empty(operator),
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

/// Callers never join nothing; should one, the neutral element keeps the program valid.
fn unreachable_empty(operator: &str) -> String {
    if operator.contains("||") {
        "false"
    } else {
        "true"
    }
    .to_owned()
}

/// One comparison of the stringified field value in variable `text` with `value`, or `None` if
/// it cannot be expressed (the caller widens).
fn comparison(text: &str, op: MatchOp, value: &str, case_sensitive: bool) -> Option<String> {
    let insensitive = !case_sensitive;
    Some(match op {
        MatchOp::Equals if insensitive => {
            format!(
                "downcase({text}) == {}",
                syntax::string(&value.to_lowercase())
            )
        }
        MatchOp::Equals => format!("{text} == {}", syntax::string(value)),
        MatchOp::Contains => call("contains", text, value, case_sensitive),
        MatchOp::StartsWith => call("starts_with", text, value, case_sensitive),
        MatchOp::EndsWith => call("ends_with", text, value, case_sensitive),
        MatchOp::Regex => {
            let pattern = if insensitive {
                format!("(?i){value}")
            } else {
                value.to_owned()
            };
            // VRL compiles regex literals with the `regex` crate; check with the same engine.
            regex::Regex::new(&pattern).ok()?;
            format!("match({text}, {})", syntax::regex(&pattern)?)
        }
        MatchOp::Exists => return None,
    })
}

fn call(function: &str, text: &str, value: &str, case_sensitive: bool) -> String {
    format!(
        "{function}({text}, {}, case_sensitive: {case_sensitive})",
        syntax::string(value)
    )
}

#[cfg(test)]
mod tests;
