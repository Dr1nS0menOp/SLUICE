//! "Rules in the SIEM": every rule and query Sluice was given, next to what it made of it, so a
//! reader can check the list against the SIEM's own (ADR 0021).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::rules::{RequiredFields, RuleRequirements};

use crate::analyze::Input;
use crate::report::text;

/// How well Sluice understood a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    /// Its scope, fields and first filter were read: it protects exactly what it needs.
    Understood,
    /// Read, but too widely to narrow: it keeps more data than it may need.
    ReadBroadly,
    /// Could not be read at all: it blocks savings everywhere it could apply.
    NotRead,
}

impl RuleStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Understood => "understood",
            Self::ReadBroadly => "read broadly",
            Self::NotRead => "not read",
        }
    }
}

/// One rule or query, and what Sluice made of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleRow {
    /// `Sigma`, `Wazuh`, `Sentinel`, `Elastic` or `Splunk`.
    pub set: String,
    /// The rule's id.
    pub rule: String,
    /// Its name as the SIEM shows it, where known.
    pub name: Option<String>,
    /// How well it was understood.
    pub status: RuleStatus,
    /// What Sluice took from it, in plain words.
    pub detail: String,
}

/// Every rule of `input`, once per rule id (mapped Sigma copies are the same rule).
pub(crate) fn rows(input: Input<'_>) -> Vec<RuleRow> {
    let mut rows = Vec::new();
    set_rows(
        &mut rows,
        "Sigma",
        input.sigma.requirements(),
        &input.sigma.names(),
    );
    if let Some(wazuh) = input.wazuh {
        set_rows(&mut rows, "Wazuh", wazuh.requirements(), wazuh.names());
    }
    if let Some(sentinel) = input.sentinel {
        set_rows(
            &mut rows,
            "Sentinel",
            sentinel.rules.requirements(),
            sentinel.rules.names(),
        );
    }
    if let Some(elastic) = input.elastic {
        set_rows(
            &mut rows,
            "Elastic",
            elastic.rules.requirements(),
            elastic.rules.names(),
        );
    }
    if let Some(splunk) = input.splunk {
        set_rows(&mut rows, "Splunk", splunk.requirements(), splunk.names());
    }
    rows
}

fn set_rows(
    rows: &mut Vec<RuleRow>,
    set: &str,
    requirements: &[RuleRequirements],
    names: &BTreeMap<RuleId, String>,
) {
    let mut seen = BTreeSet::new();
    for requirement in requirements {
        if !seen.insert(&requirement.rule) {
            continue;
        }
        let (status, detail) = judge(requirement);
        rows.push(RuleRow {
            set: set.to_owned(),
            rule: requirement.rule.to_string(),
            name: names.get(&requirement.rule).cloned(),
            status,
            detail,
        });
    }
}

fn judge(rule: &RuleRequirements) -> (RuleStatus, String) {
    let id = rule.rule.as_str();
    if [":unreadable:", ":unparsed:", ":unknown:"]
        .iter()
        .any(|marker| id.contains(marker))
    {
        return (
            RuleStatus::NotRead,
            "could not be read; it blocks savings everywhere".to_owned(),
        );
    }
    let scope = text::logsource(&rule.logsource);
    let fields = match &rule.fields {
        RequiredFields::Known(fields) => Some(fields),
        RequiredFields::Unknown => None,
    };
    let unbounded = rule.prefilter.is_always();
    let status = if fields.is_none() || unbounded {
        RuleStatus::ReadBroadly
    } else {
        RuleStatus::Understood
    };
    let mut parts = vec![format!("applies to {scope}")];
    parts.push(match fields {
        Some(fields) if fields.is_empty() => "reads no named field".to_owned(),
        Some(fields) => {
            let shown: Vec<&str> = fields.iter().take(5).map(FieldPath::as_str).collect();
            let more = fields.len().saturating_sub(shown.len());
            if more > 0 {
                format!("reads {} and {more} more", shown.join(", "))
            } else {
                format!("reads {}", shown.join(", "))
            }
        }
        None => "may read every field".to_owned(),
    });
    if unbounded {
        parts.push("may match any event in that scope".to_owned());
    }
    if rule.stateful {
        parts.push("counts or correlates events".to_owned());
    }
    (status, parts.join("; "))
}

/// The table's closing sentence: how many rules there are and how many were not fully read.
pub(crate) fn verdict(rows: &[RuleRow]) -> String {
    let count = |status| rows.iter().filter(|r| r.status == status).count();
    let (broad, not_read) = (count(RuleStatus::ReadBroadly), count(RuleStatus::NotRead));
    match (rows.len(), broad, not_read) {
        (0, ..) => "No rules were given.".to_owned(),
        (n, 0, 0) => format!("All {n} rules were understood."),
        (n, broad, not_read) => format!(
            "{n} rules: {} understood, {broad} read broadly (they keep more data than they may \
             need), {not_read} not read (they block savings wherever they could apply).",
            n - broad - not_read
        ),
    }
}

/// The status label, for tables.
pub(crate) fn label(status: RuleStatus) -> &'static str {
    status.label()
}

#[cfg(test)]
mod tests {
    use sluice_core::logsource::LogSource;
    use sluice_core::predicate::Predicate;

    use super::*;

    fn rule(id: &str, fields: RequiredFields, prefilter: Predicate) -> RuleRequirements {
        RuleRequirements {
            rule: RuleId::new(id),
            logsource: LogSource::default(),
            field_names: None,
            fields,
            matches_raw_text: false,
            stateful: false,
            text_lines_only: false,
            prefilter,
        }
    }

    #[test]
    fn a_bounded_rule_with_known_fields_is_understood() {
        let known = RequiredFields::known([FieldPath::from("EventID")]);
        let (status, detail) = judge(&rule("sentinel:a", known, Predicate::never()));
        assert_eq!(status, RuleStatus::Understood);
        assert!(detail.contains("reads EventID"), "{detail}");
    }

    #[test]
    fn a_rule_that_may_read_anything_is_read_broadly() {
        let (status, _) = judge(&rule(
            "sigma:b",
            RequiredFields::Unknown,
            Predicate::never(),
        ));
        assert_eq!(status, RuleStatus::ReadBroadly);
        let (status, detail) = judge(&rule(
            "sigma:c",
            RequiredFields::known([]),
            Predicate::Always,
        ));
        assert_eq!(status, RuleStatus::ReadBroadly);
        assert!(detail.contains("may match any event"));
    }

    #[test]
    fn an_unreadable_rule_is_not_read() {
        let opaque = RuleRequirements::opaque(RuleId::new("sentinel:unreadable:x.yaml#1"));
        assert_eq!(judge(&opaque).0, RuleStatus::NotRead);
    }

    #[test]
    fn the_verdict_counts_what_was_not_fully_read() {
        let row = |status| RuleRow {
            set: "Sentinel".into(),
            rule: "r".into(),
            name: None,
            status,
            detail: String::new(),
        };
        assert_eq!(verdict(&[]), "No rules were given.");
        assert_eq!(
            verdict(&[row(RuleStatus::Understood)]),
            "All 1 rules were understood."
        );
        let mixed = verdict(&[
            row(RuleStatus::Understood),
            row(RuleStatus::ReadBroadly),
            row(RuleStatus::NotRead),
        ]);
        assert!(
            mixed.starts_with("3 rules: 1 understood, 1 read broadly"),
            "{mixed}"
        );
    }
}
