//! Superset pre-filters as VRL.
//!
//! A [`Predicate`] compiles to VRL statements that leave its truth in one variable. A connective
//! keeps one variable per nesting level and tests its parts in turn, each inside an `if` that
//! skips it once the answer is known (`Any` stops at the first true part, `All` at the first
//! false one). One variable per test made VRL's type checker, which copies its state of every
//! variable at each step, quadratic in the number of tests: 400 tests took seconds to compile,
//! where now they take milliseconds.
//!
//! An array matches when one of its members does, as in Sigma engines. Every place where VRL
//! cannot express a test exactly *widens* it to `true`:
//!
//! - an object value, or an array member that is itself an object or array;
//! - a float value, when a tested value could be part of a number's text (`4625`, `1e21`,
//!   `nan`): its decimal text differs between engines, so `4625.0` may equal `4625`, but no
//!   engine writes a number as `cmd.exe`;
//! - a regex that VRL's engine (Rust `regex`) cannot compile, or cannot quote.
//!
//! Missing and null fields make a test false, as they do in Sigma.

use sluice_core::codegen::{balanced, float_may_match};
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
    let compiler = Compiler { prefix };
    CompiledPredicate {
        statements: compiler.emit(predicate, 0),
        expression: compiler.result(0),
    }
}

struct Compiler<'a> {
    prefix: &'a str,
}

impl Compiler<'_> {
    /// The variable holding the truth of a predicate nested `depth` connectives deep.
    fn result(&self, depth: usize) -> String {
        format!("{}{depth}", self.prefix)
    }

    /// A scratch variable, shared by every test: tests run one after another.
    fn scratch(&self, name: &str) -> String {
        format!("{}_{name}", self.prefix)
    }

    /// Statements that leave the truth of `predicate` in [`Self::result`] for `depth`.
    fn emit(&self, predicate: &Predicate, depth: usize) -> Vec<String> {
        let target = self.result(depth);
        match predicate {
            Predicate::Always => vec![format!("{target} = true")],
            Predicate::Any(parts) => self.connective(parts, depth, false),
            Predicate::All(parts) => self.connective(parts, depth, true),
            Predicate::Field(test) => self.test(test, &target),
            Predicate::Keywords(test) => self.keywords(test, &target),
        }
    }

    /// `All` (`all`) or `Any` of `parts`: start from the neutral value and evaluate each part
    /// only while it can still change the answer.
    fn connective(&self, parts: &[Predicate], depth: usize, all: bool) -> Vec<String> {
        let target = self.result(depth);
        let mut statements = vec![format!("{target} = {all}")];
        let undecided = if all {
            target.clone()
        } else {
            format!("!{target}")
        };
        for part in parts {
            let body = if matches!(part, Predicate::Any(_) | Predicate::All(_)) {
                let mut nested = self.emit(part, depth + 1);
                nested.push(format!("{target} = {}", self.result(depth + 1)));
                nested
            } else {
                self.emit(part, depth)
            };
            statements.push(format!("if {undecided} {{\n{}\n}}", indent(&body)));
        }
        statements
    }

    /// A scan over every leaf value of the event for any of the keywords.
    ///
    /// `flatten` makes nested objects leaves. Integers are compared as their decimal text and
    /// strings directly, as Sigma engines do, and so are the members of an array; a member that
    /// is itself an object or array widens to true. A float's decimal text may differ between
    /// engines, so it widens too, unless no keyword could be part of a number's text at all.
    /// Booleans and nulls never match.
    fn keywords(&self, test: &KeywordTest, target: &str) -> Vec<String> {
        if test.values.is_empty() {
            return vec![format!("{target} = false")];
        }
        let value = self.scratch("kv");
        let member = self.scratch("km");
        let rendered = self.scratch("ks");
        let checks = keyword_checks(&rendered, test);
        let floats = float_may_match(&test.values);
        let member_float = if floats {
            format!(" || is_float({member})")
        } else {
            String::new()
        };
        let float_branch = if floats {
            format!(" else if is_float({value}) {{ {target} = true }}")
        } else {
            String::new()
        };
        vec![
            format!("{target} = false"),
            format!(
                "for_each(values(flatten(.))) -> |_index, {value}| {{\n  \
                   if is_array({value}) {{\n    \
                     for_each(array!({value})) -> |_member, {member}| {{\n      \
                       if is_array({member}) || is_object({member}){member_float} {{ {target} = true }} \
                       else if is_string({member}) || is_integer({member}) {{\n        \
                         {rendered} = to_string!({member})\n        \
                         if {checks} {{ {target} = true }}\n      \
                       }}\n    \
                     }}\n  \
                   }}{float_branch} \
                   else if is_string({value}) || is_integer({value}) {{\n    \
                     {rendered} = to_string!({value})\n    \
                     if {checks} {{ {target} = true }}\n  \
                   }}\n}}"
            ),
        ]
    }

    /// The statements of one field test, leaving its result in `target`.
    fn test(&self, test: &FieldTest, target: &str) -> Vec<String> {
        let path = syntax::path(&test.field);
        if test.op == MatchOp::Exists {
            return vec![format!("{target} = exists({path})")];
        }
        let value = self.scratch("v");
        let rendered = self.scratch("s");
        let matches = if let Some(alternation) = literal_alternation(&rendered, test) {
            alternation
        } else {
            let comparisons: Option<Vec<String>> = test
                .values
                .iter()
                .map(|v| comparison(&rendered, test.op, v, test.case_sensitive))
                .collect();
            match comparisons.filter(|c| !c.is_empty()) {
                Some(comparisons) => balanced(&comparisons, " || ", "false"),
                None => return vec![format!("{target} = true")],
            }
        };
        // A float's text may differ between engines (`4625.0` may be `4625`): it widens unless no
        // value could be part of a number's text. A regex may match anything.
        let floats = test.op == MatchOp::Regex || float_may_match(&test.values);
        let float = |v: &str| {
            if floats {
                format!(" || is_float({v})")
            } else {
                String::new()
            }
        };
        let member = self.scratch("m");
        let member_float = float(&member);
        let value_float = float(&value);
        vec![
            format!("{target} = false"),
            format!("{value} = {path}"),
            // An array matches when a member does, as in Sigma engines.
            format!(
                "if is_array({value}) {{\n  \
                   for_each(array!({value})) -> |_member, {member}| {{\n    \
                     if is_array({member}) || is_object({member}){member_float} {{ {target} = true }} \
                     else if !is_null({member}) && !is_float({member}) {{ {rendered} = to_string!({member}); if {matches} {{ {target} = true }} }}\n  \
                   }}\n\
                 }} else if is_object({value}){value_float} {{ {target} = true }} \
                 else if !is_null({value}) && !is_float({value}) {{ {rendered} = to_string!({value}); {target} = {matches} }}"
            ),
        ]
    }
}

fn indent(statements: &[String]) -> String {
    statements
        .iter()
        .flat_map(|s| s.lines())
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
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

/// From this many values on (keywords, or a field test's), one regex alternation replaces a
/// `contains` or comparison per value.
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
            "false",
        )
    };
    if test.values.len() < KEYWORD_REGEX_MIN {
        return contains();
    }
    alternation(rendered, &test.values, test.case_sensitive, "", "").unwrap_or_else(contains)
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
