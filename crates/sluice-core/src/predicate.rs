//! The superset pre-filter language.
//!
//! A [`Predicate`] describes which events a set of rules *could* match. It is deliberately a
//! superset: rule parts that cannot be expressed (exclusions, unsupported modifiers) widen it
//! instead of narrowing it, so an event a rule would alert on is never filtered out.
//!
//! Core only builds and inspects predicates. Executing one is the job of the compiled VRL, so
//! there is exactly one implementation of the matching semantics.

use std::collections::BTreeSet;

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
        let flat = merge_alternatives(flat);
        if flat.len() == 1 {
            flat.into_iter().next().unwrap_or_else(Self::never)
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

    /// Returns true if this predicate matches no event (an empty disjunction).
    #[must_use]
    pub fn is_never(&self) -> bool {
        matches!(self, Self::Any(parts) if parts.is_empty())
    }

    /// The number of field and keyword tests, which is what the data plane evaluates per event.
    #[must_use]
    pub fn tests(&self) -> usize {
        match self {
            Self::Always => 0,
            Self::Any(parts) | Self::All(parts) => parts.iter().map(Self::tests).sum(),
            Self::Field(_) | Self::Keywords(_) => 1,
        }
    }

    /// A test that passes on any present, non-null value of `field`: the superset of every
    /// value comparison on it (a regex, a CIDR, an encoding), for rule parts the pre-filter
    /// language cannot express. Unlike `exists`, it fails on an empty object, which no value
    /// comparison matches either, so a template's key set can rule it out.
    #[must_use]
    pub fn present(field: FieldPath) -> Self {
        Self::Field(FieldTest {
            field,
            op: MatchOp::Regex,
            values: vec![String::new()],
            case_sensitive: true,
        })
    }

    /// Returns true if this predicate trivially matches every event.
    #[must_use]
    pub fn is_always(&self) -> bool {
        matches!(self, Self::Always)
    }

    /// Returns false only if no event of a template can match: its discriminators (`fixed`,
    /// such as `EventID=7036`) rule out a test that requires another value of the same field,
    /// or its exact key set (`paths`, for JSON templates) lacks a field a test needs. A field
    /// test only passes on a present field (`null` and `exists: false` checks are never field
    /// tests: pre-filters widen them). Keywords and regular expressions never rule anything
    /// out, so the answer errs towards "may match" (fail closed).
    #[must_use]
    pub fn may_match_with(
        &self,
        fixed: &[(FieldPath, String)],
        paths: Option<&BTreeSet<FieldPath>>,
    ) -> bool {
        match self {
            Self::Always | Self::Keywords(_) => true,
            Self::Any(children) => children.iter().any(|c| c.may_match_with(fixed, paths)),
            Self::All(children) => children.iter().all(|c| c.may_match_with(fixed, paths)),
            Self::Field(test) => {
                // `exists` also passes on an empty object, which a key set does not list.
                let present = test.op == MatchOp::Exists
                    || paths.is_none_or(|paths| {
                        paths
                            .iter()
                            .any(|p| p.covers(&test.field) || test.field.covers(p))
                    });
                present
                    && fixed
                        .iter()
                        .find(|(field, _)| *field == test.field)
                        .is_none_or(|(_, value)| test.may_match_value(value))
            }
        }
    }
}

impl Predicate {
    /// Returns true only if every event whose `fixed` fields have these values matches: the
    /// dual of [`Predicate::may_match_with`], with the same narrow knowledge (only equality on a
    /// fixed field is decided). Used to tell a rule that covers a whole template from one that
    /// selects some of its events.
    #[must_use]
    pub fn holds_for_all_with(&self, fixed: &[(FieldPath, String)]) -> bool {
        match self {
            Self::Always => true,
            Self::Keywords(_) => false,
            Self::Any(children) => children.iter().any(|c| c.holds_for_all_with(fixed)),
            Self::All(children) => children.iter().all(|c| c.holds_for_all_with(fixed)),
            Self::Field(test) => {
                test.op == MatchOp::Equals
                    && fixed.iter().any(|(field, value)| {
                        *field == test.field
                            && test.values.iter().any(|v| {
                                if test.case_sensitive {
                                    v == value
                                } else {
                                    v.eq_ignore_ascii_case(value)
                                }
                            })
                    })
            }
        }
    }
}

/// Sorts and dedups a disjunction, folding tests that differ only in their values into one:
/// "some value contains one of A, or one of B" is exactly "one of A ∪ B", for keyword tests of
/// equal case sensitivity and for field tests of equal field, operator and case sensitivity.
/// The data plane then scans a value once instead of once per rule.
fn merge_alternatives(parts: Vec<Predicate>) -> Vec<Predicate> {
    let mut merged: [Option<KeywordTest>; 2] = [None, None];
    let mut fields: Vec<FieldTest> = Vec::new();
    let mut rest = Vec::new();
    for part in parts {
        match part {
            Predicate::Field(test) if test.op != MatchOp::Exists => {
                let same = fields.iter_mut().find(|f| {
                    f.field == test.field
                        && f.op == test.op
                        && f.case_sensitive == test.case_sensitive
                });
                match same {
                    Some(existing) => existing.values.extend(test.values),
                    None => fields.push(test),
                }
            }
            Predicate::Keywords(test) => {
                let slot = &mut merged[usize::from(test.case_sensitive)];
                match slot {
                    Some(existing) => existing.values.extend(test.values),
                    None => *slot = Some(test),
                }
            }
            other => rest.push(other),
        }
    }
    for mut test in merged.into_iter().flatten() {
        test.values.sort();
        test.values.dedup();
        rest.push(Predicate::Keywords(test));
    }
    for mut test in fields {
        test.values.sort();
        test.values.dedup();
        rest.push(Predicate::Field(test));
    }
    rest.sort();
    rest.dedup();
    rest
}

impl FieldTest {
    /// Whether this test can pass on a field whose value is `value` (its text form).
    fn may_match_value(&self, value: &str) -> bool {
        if matches!(self.op, MatchOp::Regex | MatchOp::Exists) {
            return true;
        }
        let fold = |s: &str| {
            if self.case_sensitive {
                s.to_owned()
            } else {
                s.to_ascii_lowercase()
            }
        };
        let value = fold(value);
        self.values
            .iter()
            .map(|v| fold(v))
            .any(|expected| match self.op {
                MatchOp::Equals => value == expected,
                MatchOp::Contains => value.contains(&expected),
                MatchOp::StartsWith => value.starts_with(&expected),
                MatchOp::EndsWith => value.ends_with(&expected),
                MatchOp::Regex | MatchOp::Exists => true,
            })
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
    fn a_fixed_value_rules_out_only_conflicting_tests() {
        let fixed = [(FieldPath::from("EventID"), "7036".to_owned())];
        let zerologon = Predicate::all([
            Predicate::any([eq("EventID", "5805"), eq("EventID", "5723")]),
            Predicate::Keywords(KeywordTest {
                values: vec!["mimikatz".into()],
                case_sensitive: false,
            }),
        ]);
        assert!(!zerologon.may_match_with(&fixed, None));
        assert!(eq("EventID", "7036").may_match_with(&fixed, None));
        assert!(
            eq("Image", "x").may_match_with(&fixed, None),
            "other fields are unknown"
        );
        assert!(
            Predicate::any([eq("EventID", "1"), Predicate::Always]).may_match_with(&fixed, None)
        );
        let regex = Predicate::Field(FieldTest {
            field: "EventID".into(),
            op: MatchOp::Regex,
            values: vec!["^5".into()],
            case_sensitive: false,
        });
        assert!(
            regex.may_match_with(&fixed, None),
            "regex is never decided here"
        );
        let case = [(FieldPath::from("Channel"), "System".to_owned())];
        assert!(eq("Channel", "system").may_match_with(&case, None));

        // A JSON template's exact key set rules out tests on fields it lacks.
        let paths: BTreeSet<FieldPath> = ["EventID", "process.name"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert!(!eq("CommandLine", "x").may_match_with(&[], Some(&paths)));
        assert!(
            eq("process", "x").may_match_with(&[], Some(&paths)),
            "a parent is present"
        );
        assert!(
            eq("process.name.raw", "x").may_match_with(&[], Some(&paths)),
            "inside a leaf"
        );
        assert_eq!(
            zerologon.may_match_with(&[], Some(&paths)),
            zerologon.may_match_with(&[], None)
        );
        assert!(!Predicate::present("CommandLine".into()).may_match_with(&[], Some(&paths)));
        let exists = Predicate::Field(FieldTest {
            field: "g".into(),
            op: MatchOp::Exists,
            values: vec![],
            case_sensitive: false,
        });
        assert!(
            exists.may_match_with(&[], Some(&paths)),
            "`g` may be an empty object"
        );
    }

    #[test]
    fn keyword_tests_in_a_disjunction_merge_by_case_sensitivity() {
        let kw = |values: &[&str], case_sensitive| {
            Predicate::Keywords(KeywordTest {
                values: values.iter().map(|v| (*v).to_owned()).collect(),
                case_sensitive,
            })
        };
        let merged = Predicate::any([
            kw(&["b", "a"], false),
            eq("x", "1"),
            kw(&["c", "a"], false),
            kw(&["Z"], true),
        ]);
        assert_eq!(
            merged,
            Predicate::Any(vec![
                eq("x", "1"),
                kw(&["Z"], true),
                kw(&["a", "b", "c"], false),
            ])
        );
        assert_eq!(
            Predicate::any([kw(&["a"], false), kw(&["b"], false)]),
            kw(&["a", "b"], false)
        );
    }

    #[test]
    fn empty_disjunction_matches_nothing() {
        assert_eq!(Predicate::any([]), Predicate::never());
        assert!(!Predicate::never().is_always());
    }
}
