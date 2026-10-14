//! Strongly typed identifiers.
//!
//! Every identifier is its own type, so a rule id can never be passed where a template id is
//! expected. All of them order and hash by their string value, which keeps serialized output
//! deterministic.

use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates the identifier from any string-like value.
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(id: &str) -> Self {
                Self::new(id)
            }
        }
    };
}

string_id! {
    /// A log source, such as `windows-security` or `sysmon`.
    SourceId
}

string_id! {
    /// A discovered log template within a source. Stable across runs for the same template.
    TemplateId
}

string_id! {
    /// A detection rule, such as a Sigma rule id or a Wazuh rule id (`wazuh:5710`).
    RuleId
}

/// Identity of one event within a sample.
///
/// Reductions never change an event's id, which is what lets the shadow proof compare the alerts
/// raised on full data with those raised on forwarded data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub u64);

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn ids_display_and_serialize_as_their_string() {
        let rule = RuleId::new("wazuh:5710");
        assert_eq!(rule.to_string(), "wazuh:5710");
        assert_eq!(rule.as_str(), "wazuh:5710");
        assert_eq!(serde_json::to_string(&rule).unwrap(), "\"wazuh:5710\"");
        assert_eq!(
            serde_json::from_str::<RuleId>("\"wazuh:5710\"").unwrap(),
            rule
        );
        assert_eq!(TemplateId::from("t"), TemplateId::new(String::from("t")));
    }

    #[test]
    fn ids_order_by_their_string_for_deterministic_output() {
        let ids: BTreeSet<SourceId> = ["b", "a", "c"].into_iter().map(SourceId::from).collect();
        let ordered: Vec<&str> = ids.iter().map(SourceId::as_str).collect();
        assert_eq!(ordered, ["a", "b", "c"]);
    }

    #[test]
    fn event_ids_display_with_a_hash_and_serialize_as_a_number() {
        assert_eq!(EventId(7).to_string(), "#7");
        assert_eq!(serde_json::to_string(&EventId(7)).unwrap(), "7");
        assert!(EventId(2) < EventId(10), "numeric, not textual, order");
    }
}
