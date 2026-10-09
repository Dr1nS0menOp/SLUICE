//! The superset pre-filter language.
//!
//! A [`Predicate`] describes which events a set of rules *could* match. It is deliberately a
//! superset: rule parts that cannot be expressed (exclusions, unsupported modifiers) widen it
//! instead of narrowing it, so an event a rule would alert on is never filtered out.
//!
//! Core only builds and inspects predicates. Executing one is the job of the compiled VRL, so
//! there is exactly one implementation of the matching semantics.

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;

/// How a field value is compared with the predicate's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
    /// The field equals one of the values.
    Equals,
    /// The field contains one of the values.
    Contains,
    /// The field starts with one of the values.
    StartsWith,
    /// The field ends with one of the values.
    EndsWith,
    /// The field matches one of the values as a regular expression.
    Regex,
    /// The field is present (values are ignored).
    Exists,
}

/// A single test on one field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldTest {
    /// Field to test.
    pub field: FieldPath,
    /// Comparison to apply.
    pub op: MatchOp,
    /// Values to compare against. The test passes if any value matches.
    pub values: Vec<String>,
    /// Whether comparison is case-sensitive. Sigma defaults to case-insensitive.
    pub case_sensitive: bool,
}

/// A free-text test: some value anywhere in the event contains one of `values`.
///
/// "Value" means every string, and every number as its decimal text, at any depth, including
/// array members. Booleans and nulls never match. That is Sigma keyword semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeywordTest {
    /// Substrings to look for. The test passes if any value contains any of them.
    pub values: Vec<String>,
    /// Whether comparison is case-sensitive. Sigma keywords are case-insensitive.
    pub case_sensitive: bool,
}

/// A boolean expression over field tests.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// Matches every event. Used wherever a rule part cannot be bounded.
    Always,
    /// Matches if any child matches. An empty `Any` matches nothing.
    Any(Vec<Predicate>),
    /// Matches if all children match. An empty `All` matches everything.
    All(Vec<Predicate>),
    /// A test on one field.
    Field(FieldTest),
    /// A free-text test over every value of the event.
    Keywords(KeywordTest),
}

impl Predicate {
    /// A predicate that matches no event.
    #[must_use]
    pub fn never() -> Self {
        Self::Any(Vec::new())
    }

    /// Builds a disjunction, simplified: nested `Any` is flattened and `Always` absorbs the rest.
    #[must_use]
    pub fn any(children: impl IntoIterator<Item = Predicate>) -> Self {
        let mut flat = Vec::new();
        for child in children {
            match child {
                Self::Always => return Self::Always,
                Self::Any(grandchildren) => flat.extend(grandchildren),
                other => flat.push(other),
            }
        }
        flat.sort();
        flat.dedup();
        if flat.len() == 1 {
            flat.pop().unwrap_or_else(Self::never)
        } else {
            Self::Any(flat)
        }
    }

    /// Builds a conjunction, simplified: nested `All` is flattened and `Always` is dropped.
    #[must_use]
    pub fn all(children: impl IntoIterator<Item = Predicate>) -> Self {
        let mut flat = Vec::new();
        for child in children {
            match child {
                Self::Always => {}
                Self::All(grandchildren) => flat.extend(grandchildren),
                other => flat.push(other),
            }
        }
        flat.sort();
        flat.dedup();
        match flat.len() {
            0 => Self::Always,
            1 => flat.pop().unwrap_or(Self::Always),
            _ => Self::All(flat),
        }
    }

    /// Returns true if this predicate trivially matches every event.
    #[must_use]
    pub fn is_always(&self) -> bool {
        matches!(self, Self::Always)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn empty_disjunction_matches_nothing() {
        assert_eq!(Predicate::any([]), Predicate::never());
        assert!(!Predicate::never().is_always());
    }
}
