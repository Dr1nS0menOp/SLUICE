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
    /// log sources are conventionally lowercase but not consistently so. Values with other
    /// letters are never told apart this way (engines may fold them by Unicode rules), so they
    /// may always apply.
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
        (Some(rule), Some(data)) => {
            rule.eq_ignore_ascii_case(data) || !rule.is_ascii() || !data.is_ascii()
        }
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

    #[test]
    fn every_attribute_must_agree() {
        let data = source(Some("windows"), Some("security"), Some("authentication"));
        assert!(!source(Some("linux"), None, None).may_apply_to(&data));
        assert!(!source(None, Some("system"), None).may_apply_to(&data));
        assert!(!source(None, None, Some("process_creation")).may_apply_to(&data));
        assert!(source(None, None, Some("AUTHENTICATION")).may_apply_to(&data));
    }

    #[test]
    fn a_complete_descriptor_still_applies_rules_for_attributes_it_has() {
        let mut data = source(Some("windows"), Some("security"), None);
        data.complete = true;
        assert!(source(Some("windows"), Some("security"), None).may_apply_to(&data));
        assert!(LogSource::default().may_apply_to(&data));
        assert!(!source(Some("windows"), Some("security"), Some("x")).may_apply_to(&data));
    }

    #[test]
    fn complete_on_the_rule_side_is_ignored() {
        let mut rule = source(Some("windows"), None, Some("process_creation"));
        rule.complete = true;
        assert!(rule.may_apply_to(&source(Some("windows"), None, None)));
    }

    #[test]
    fn c3_non_ascii_attributes_are_never_told_apart_by_case() {
        // `Ä` and `ä` are one letter to a Unicode-folding engine: excluding the rule here would
        // leave its fields unprotected.
        let rule = source(Some("äpp"), None, None);
        assert!(rule.may_apply_to(&source(Some("ÄPP"), None, None)));
        assert!(rule.may_apply_to(&source(Some("äpp"), None, None)));
        // One side alone non-ASCII is enough: the Kelvin sign folds to an ASCII `k`.
        let ascii = source(Some("k8s"), None, None);
        assert!(ascii.may_apply_to(&source(Some("\u{212a}8s"), None, None)));
        assert!(source(Some("\u{212a}8s"), None, None).may_apply_to(&source(
            Some("K8S"),
            None,
            None
        )));
        assert!(!source(Some("app"), None, None).may_apply_to(&source(Some("web"), None, None)));
    }

    #[test]
    fn empty_attributes_are_values_not_absences() {
        // `product: ""` is a declared, empty product: it matches only itself.
        assert!(!source(Some(""), None, None).may_apply_to(&source(Some("windows"), None, None)));
        assert!(source(Some(""), None, None).may_apply_to(&source(Some(""), None, None)));
    }

    #[test]
    fn complete_is_not_serialized_when_false() {
        let json = serde_json::to_string(&source(Some("windows"), None, None)).unwrap();
        assert_eq!(json, r#"{"product":"windows"}"#);
        let parsed: LogSource =
            serde_json::from_str(r#"{"product":"windows","complete":true}"#).unwrap();
        assert!(parsed.complete);
    }
}
