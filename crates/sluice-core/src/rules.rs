//! What detection rules need from the data.
//!
//! Rule engines (Sigma, Wazuh, …) live in adapter crates. Each one reduces its rules to
//! [`RuleRequirements`], the engine-neutral facts the guardrails need to keep every rule working.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::RuleId;
use crate::logsource::LogSource;
use crate::predicate::Predicate;
use crate::schema::Schema;

/// The data a single rule depends on.
///
/// Every field is a conservative over-approximation. When an adapter is unsure, it must widen:
/// add the field, set the flag, or use [`Predicate::Always`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRequirements {
    /// The rule.
    pub rule: RuleId,
    /// Data the rule applies to. Empty means everything.
    pub logsource: LogSource,
    /// The convention the rule's field names are written in, or `None` when its adapter relates
    /// them to the data by other means (Wazuh decoders, Sentinel's table columns, operator
    /// rules). A rule with a convention can only be compared with records that follow the same
    /// one (ADR 0018); on JSON records that do not, it is read as widely as can be.
    #[serde(default)]
    pub field_names: Option<Schema>,
    /// Every field the rule references, including fields only used in exclusions
    /// (`not filter`). An exclusion that loses its field would start alerting on noise, and a
    /// silent change in either direction is a regression.
    pub fields: RequiredFields,
    /// The rule matches on free text (Sigma keywords, Wazuh `<match>`/`<regex>` on the log), so
    /// the raw text of every applicable template must reach it unchanged.
    pub matches_raw_text: bool,
    /// The rule counts or correlates events (Sigma correlations, Wazuh `frequency`). Its result
    /// depends on how many matching events arrive and in what order, so a reduction that removes,
    /// merges or reorders events its pre-filter matches would change it. Rule-guided routing
    /// forwards all of those unchanged (ADR 0004); a future de-duplication must not touch them.
    pub stateful: bool,
    /// The rule only ever sees text lines, never a structured (JSON) event, so it does not apply
    /// to JSON templates. A Wazuh rule whose decoder selects by syslog program name is such a
    /// rule: a JSON line has no syslog header, so Wazuh decodes it with its JSON decoder only
    /// (see `docs/notes/wazuh.md`). `false` is always safe.
    #[serde(default)]
    pub text_lines_only: bool,
    /// Superset of the events this rule could match on its own.
    pub prefilter: Predicate,
}

/// The fields a rule reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredFields {
    /// Exactly these fields (and their children) are read.
    Known(BTreeSet<FieldPath>),
    /// The rule may read any field, so no field may be removed from applicable events.
    Unknown,
}

impl RequiredFields {
    /// Builds a known field set.
    pub fn known(fields: impl IntoIterator<Item = FieldPath>) -> Self {
        Self::Known(fields.into_iter().collect())
    }
}

impl RuleRequirements {
    /// Requirements for a rule that could not be understood: it applies everywhere, reads every
    /// field, matches anything and counts events. Using this is always safe and never saves
    /// anything.
    #[must_use]
    pub fn opaque(rule: RuleId) -> Self {
        Self {
            rule,
            logsource: LogSource::default(),
            field_names: None,
            fields: RequiredFields::Unknown,
            matches_raw_text: true,
            stateful: true,
            text_lines_only: false,
            prefilter: Predicate::Always,
        }
    }

    /// The same rule on a text line whose fields the SIEM parses itself: bounded by its keyword
    /// tests only ([`Predicate::on_text_line`]), and reading the line, which every field it
    /// tests comes from.
    #[must_use]
    pub fn on_text_line(&self) -> Self {
        Self {
            prefilter: self.prefilter.on_text_line(),
            matches_raw_text: true,
            ..self.clone()
        }
    }

    /// The same rule, read as widely as can be: any field, on any event of its log source. Used
    /// when its field names cannot be related to the data's, so nothing it might read is cut.
    #[must_use]
    pub fn widened(&self) -> Self {
        Self {
            logsource: self.logsource.clone(),
            text_lines_only: self.text_lines_only,
            ..Self::opaque(self.rule.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn narrow() -> RuleRequirements {
        RuleRequirements {
            rule: RuleId::new("sigma:x"),
            logsource: LogSource {
                product: Some("windows".into()),
                ..LogSource::default()
            },
            field_names: Some(Schema::Sigma),
            fields: RequiredFields::known([FieldPath::from("Image")]),
            matches_raw_text: false,
            stateful: false,
            text_lines_only: true,
            prefilter: Predicate::never(),
        }
    }

    #[test]
    fn c3_an_opaque_rule_may_read_and_match_anything_anywhere() {
        let opaque = RuleRequirements::opaque(RuleId::new("r"));
        assert_eq!(opaque.logsource, LogSource::default());
        assert_eq!(opaque.fields, RequiredFields::Unknown);
        assert!(opaque.matches_raw_text && opaque.stateful && !opaque.text_lines_only);
        assert!(opaque.prefilter.is_always());
        assert_eq!(opaque.field_names, None);
    }

    #[test]
    fn c3_widening_keeps_only_the_rule_and_where_it_applies() {
        let widened = narrow().widened();
        assert_eq!(widened.rule, narrow().rule);
        assert_eq!(widened.logsource, narrow().logsource);
        assert_eq!(widened.text_lines_only, narrow().text_lines_only);
        assert_eq!(widened.fields, RequiredFields::Unknown);
        assert!(widened.prefilter.is_always() && widened.matches_raw_text && widened.stateful);
        assert_eq!(
            widened.field_names, None,
            "a widened rule compares with any records"
        );
    }

    #[test]
    fn known_fields_are_a_set() {
        let fields = RequiredFields::known(["b", "a", "b"].map(FieldPath::from));
        assert_eq!(
            fields,
            RequiredFields::Known(["a", "b"].map(FieldPath::from).into())
        );
    }

    #[test]
    fn older_requirements_without_newer_fields_still_parse() {
        let json = r#"{"rule":"r","logsource":{},"fields":"unknown","matches_raw_text":true,"stateful":false,"prefilter":"always"}"#;
        let parsed: RuleRequirements = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.field_names, None);
        assert!(!parsed.text_lines_only);
    }
}
