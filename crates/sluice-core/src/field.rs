//! Field paths inside an event.

use std::borrow::Borrow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A dotted path to a field in an event, such as `TargetUserName` or `process.parent.name`.
///
/// Sigma and Wazuh rules refer to fields by these names, so the same type is used for the fields a
/// rule needs and the fields a reduction touches. Comparisons are exact and case-sensitive.
/// Event schemas are case-sensitive, and treating `user` and `User` as equal would hide a
/// guardrail miss.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldPath(String);

impl FieldPath {
    /// Creates a field path from its dotted form.
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Returns the dotted form of the path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Iterates over the path segments (`a.b.c` → `a`, `b`, `c`).
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// Returns true if `self` equals `other` or is one of its ancestors (`a` covers `a.b`).
    ///
    /// The guardrails use this to keep a parent object when a rule needs one of its children,
    /// because dropping the parent would also drop the child.
    #[must_use]
    pub fn covers(&self, other: &FieldPath) -> bool {
        other.0 == self.0
            || other
                .0
                .strip_prefix(&self.0)
                .is_some_and(|rest| rest.starts_with('.'))
    }
}

/// Lets sets and maps keyed by `FieldPath` be queried with a `&str`. Sound because ordering,
/// equality and hashing all derive from the inner string.
impl Borrow<str> for FieldPath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for FieldPath {
    fn from(path: &str) -> Self {
        Self::new(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_itself_and_descendants_only() {
        let parent = FieldPath::from("process");
        assert!(parent.covers(&"process".into()));
        assert!(parent.covers(&"process.name".into()));
        assert!(!parent.covers(&"process_name".into()));
        assert!(!parent.covers(&"proc".into()));
        assert!(!FieldPath::from("process.name").covers(&parent));
    }

    #[test]
    fn segments_split_on_dots() {
        let path = FieldPath::from("a.b.c");
        assert_eq!(path.segments().collect::<Vec<_>>(), ["a", "b", "c"]);
    }
}
