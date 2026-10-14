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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

    /// Returns true if a rule's field `self` may denote the event path `other`: the same path,
    /// an ancestor or a descendant of it, or any of those nested under an object
    /// (`ScriptBlockText` and `EventData.ScriptBlockText`).
    ///
    /// Rules name a provider's fields bare, while some SIEM tables keep them under one column:
    /// Sentinel's `WindowsEvent` stores them in `EventData`. Comparing only exact paths would
    /// let the guardrails believe such a rule reads nothing of the event, and cut what it reads.
    /// Matching more paths only keeps more, so this errs on the safe side.
    #[must_use]
    pub fn may_denote(&self, other: &FieldPath) -> bool {
        let related = |path: &str| {
            let candidate = FieldPath::new(path);
            self.covers(&candidate) || candidate.covers(self)
        };
        related(&other.0)
            || other
                .0
                .match_indices('.')
                .any(|(at, _)| related(&other.0[at + 1..]))
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
    fn c3_a_rule_field_denotes_the_same_field_nested_under_an_object() {
        let rule = FieldPath::from("ScriptBlockText");
        assert!(rule.may_denote(&"ScriptBlockText".into()));
        assert!(rule.may_denote(&"EventData.ScriptBlockText".into()));
        assert!(rule.may_denote(&"EventData.ScriptBlockText.part".into()));
        assert!(!rule.may_denote(&"EventData.ScriptBlockTextLength".into()));
        assert!(!rule.may_denote(&"MyScriptBlockText".into()));
        // Not the containing object by itself: the guardrails protect that object through the
        // template's leaf paths, which they expand claims to.
        assert!(!rule.may_denote(&"EventData".into()));
        let nested = FieldPath::from("process.name");
        assert!(nested.may_denote(&"event.process.name".into()));
        assert!(
            nested.may_denote(&"process".into()),
            "dropping the parent drops it"
        );
        assert!(!nested.may_denote(&"name".into()));
    }

    #[test]
    fn covers_is_case_sensitive() {
        assert!(!FieldPath::from("Process").covers(&"process.name".into()));
        assert!(!FieldPath::from("user").covers(&"User".into()));
    }

    #[test]
    fn covers_handles_deep_paths_and_dotted_prefixes() {
        let deep = FieldPath::from("a.b");
        assert!(deep.covers(&"a.b.c.d".into()));
        assert!(!deep.covers(&"a.bc".into()));
        assert!(!deep.covers(&"a".into()));
    }

    #[test]
    fn the_empty_path_covers_only_itself() {
        let empty = FieldPath::from("");
        assert!(empty.covers(&"".into()));
        assert!(!empty.covers(&"a".into()));
        assert!(!FieldPath::from("a").covers(&empty));
    }

    #[test]
    fn may_denote_is_symmetric_on_ancestors_and_descendants() {
        let rule = FieldPath::from("process.parent.name");
        assert!(
            rule.may_denote(&"process.parent".into()),
            "an ancestor holds it"
        );
        assert!(rule.may_denote(&"process.parent.name.keyword".into()));
        assert!(rule.may_denote(&"winlog.process.parent.name".into()));
        assert!(
            !rule.may_denote(&"parent.name".into()),
            "a suffix of the rule is not it"
        );
    }

    #[test]
    fn may_denote_only_strips_whole_leading_segments() {
        let rule = FieldPath::from("Image");
        assert!(rule.may_denote(&"a.b.Image".into()));
        assert!(!rule.may_denote(&"a.bImage".into()));
        assert!(!rule.may_denote(&"Images".into()));
    }

    #[test]
    fn paths_display_serialize_and_borrow_as_their_string() {
        let path = FieldPath::from("a.b");
        assert_eq!(path.to_string(), "a.b");
        assert_eq!(serde_json::to_string(&path).unwrap(), "\"a.b\"");
        let set: std::collections::BTreeSet<FieldPath> = [path].into();
        assert!(set.contains("a.b"));
    }

    #[test]
    fn segments_split_on_dots() {
        let path = FieldPath::from("a.b.c");
        assert_eq!(path.segments().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(FieldPath::from("a..b").segments().count(), 3);
        assert_eq!(FieldPath::from("").segments().collect::<Vec<_>>(), [""]);
    }
}
