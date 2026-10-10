//! Log source descriptors and rule scoping.

use serde::{Deserialize, Serialize};

/// Sigma-style log source descriptor (`product`, `service`, `category`).
///
/// Rules use it to say which data they apply to, and templates use it to say what they are. A
/// missing attribute means "any" on a rule, and "unknown" on data unless the data's descriptor is
/// marked complete.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Data side only: the attributes given are all there is, so a rule that names a missing one
    /// (say `category: database` against `{product: windows, service: system}`) does not apply.
    /// Off by default, because an incomplete descriptor would then hide rules: Sysmon data is
    /// `process_creation` and more without saying so. Ignored on rules and recipes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg_attr(feature = "schema", schemars(skip))]
    pub complete: bool,
}

impl LogSource {
    /// Returns false only when this rule scope provably excludes `data`.
    ///
    /// When the data side of an attribute is unknown, the rule *may* apply, and the guardrails
    /// must assume it does (fail closed). Values compare ASCII case-insensitively, as Sigma
    /// log sources are conventionally lowercase but not consistently so.
    #[must_use]
    pub fn may_apply_to(&self, data: &LogSource) -> bool {
        let complete = data.complete;
        attribute_may_match(self.product.as_deref(), data.product.as_deref(), complete)
            && attribute_may_match(self.service.as_deref(), data.service.as_deref(), complete)
            && attribute_may_match(self.category.as_deref(), data.category.as_deref(), complete)
    }
}

fn attribute_may_match(rule: Option<&str>, data: Option<&str>, complete: bool) -> bool {
    match (rule, data) {
        (Some(rule), Some(data)) => rule.eq_ignore_ascii_case(data),
        (Some(_), None) => !complete,
        (None, _) => true,
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
            complete: false,
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
    fn a_complete_descriptor_excludes_rules_for_attributes_it_lacks() {
        let database = source(None, None, Some("database"));
        let mut system = source(Some("windows"), Some("system"), None);
        assert!(database.may_apply_to(&system), "unknown by default");
        system.complete = true;
        assert!(!database.may_apply_to(&system));
        assert!(source(Some("windows"), None, None).may_apply_to(&system));
    }

    #[test]
    fn rule_without_scope_applies_everywhere() {
        assert!(LogSource::default().may_apply_to(&source(Some("linux"), None, None)));
    }
}
