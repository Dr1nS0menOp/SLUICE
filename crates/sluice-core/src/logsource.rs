//! Log source descriptors and rule scoping.

use serde::{Deserialize, Serialize};

/// Sigma-style log source descriptor (`product`, `service`, `category`).
///
/// Rules use it to say which data they apply to, and templates use it to say what they are. A
/// missing attribute means "unknown" on a template and "any" on a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogSource {
    /// For example `windows` or `linux`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// For example `security` or `sysmon`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// For example `process_creation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

impl LogSource {
    /// Returns false only when this rule scope provably excludes `data`.
    ///
    /// When the data side of an attribute is unknown, the rule *may* apply, and the guardrails
    /// must assume it does (fail closed). Values compare ASCII case-insensitively, as Sigma
    /// log sources are conventionally lowercase but not consistently so.
    #[must_use]
    pub fn may_apply_to(&self, data: &LogSource) -> bool {
        attribute_may_match(self.product.as_deref(), data.product.as_deref())
            && attribute_may_match(self.service.as_deref(), data.service.as_deref())
            && attribute_may_match(self.category.as_deref(), data.category.as_deref())
    }
}

fn attribute_may_match(rule: Option<&str>, data: Option<&str>) -> bool {
    match (rule, data) {
        (Some(rule), Some(data)) => rule.eq_ignore_ascii_case(data),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(product: Option<&str>, service: Option<&str>, category: Option<&str>) -> LogSource {
        LogSource {
            product: product.map(Into::into),
            service: service.map(Into::into),
            category: category.map(Into::into),
        }
    }

    #[test]
    fn matching_attributes_apply() {
        let rule = source(Some("windows"), Some("security"), None);
        let data = source(Some("Windows"), Some("security"), Some("authentication"));
        assert!(rule.may_apply_to(&data));
    }

    #[test]
    fn conflicting_attribute_excludes() {
        let rule = source(Some("windows"), Some("sysmon"), None);
        let data = source(Some("windows"), Some("security"), None);
        assert!(!rule.may_apply_to(&data));
    }

    #[test]
    fn unknown_data_attribute_fails_closed() {
        let rule = source(Some("windows"), Some("sysmon"), Some("process_access"));
        let data = source(Some("windows"), None, None);
        assert!(rule.may_apply_to(&data));
    }

    #[test]
    fn rule_without_scope_applies_everywhere() {
        assert!(LogSource::default().may_apply_to(&source(Some("linux"), None, None)));
    }
}
