//! What each rule was read as when a plan was proven, so that a later `sluice verify` can tell
//! which rules the plan does not protect (ADR 0039).
//!
//! A fingerprint is a digest of the rule's requirements (the log source, the fields it reads,
//! its pre-filter), not of its text: a rule whose text changed but which reads the same is still
//! protected by the plan, and one whose text is the same but which a newer Sluice reads
//! differently is not.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sluice_core::rules::RuleRequirements;

/// One rule, as the plan was proven with it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct RuleFingerprint {
    /// The rule's id, such as `sigma:<uuid>` or `sentinel:<name>`.
    pub rule: String,
    /// `sha256:` and the hex SHA-256 of what Sluice read the rule as: its requirements as
    /// compact JSON. Rules that share an id are digested together, in a fixed order.
    pub requirements: String,
}

/// The fingerprints of `rules`, one per rule id, sorted by id.
#[must_use]
pub fn fingerprints<'a>(
    rules: impl IntoIterator<Item = &'a RuleRequirements>,
) -> Vec<RuleFingerprint> {
    let mut by_rule: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rule in rules {
        by_rule
            .entry(rule.rule.to_string())
            .or_default()
            .push(canonical(rule));
    }
    by_rule
        .into_iter()
        .map(|(rule, mut readings)| {
            readings.sort();
            let mut digest = Sha256::new();
            for reading in &readings {
                digest.update(reading.as_bytes());
                // A separator no JSON text contains, so two readings never run into one.
                digest.update([0]);
            }
            RuleFingerprint {
                rule,
                requirements: format!("sha256:{}", hex(&digest.finalize())),
            }
        })
        .collect()
}

/// The requirements as compact JSON. Their sets and maps are ordered, so the same reading
/// always gives the same text.
fn canonical(rule: &RuleRequirements) -> String {
    serde_json::to_string(rule).unwrap_or_else(|error| {
        // Requirements are plain data and always serialize; should they not, the rule still
        // gets a reading of its own, so it is never mistaken for an unchanged one.
        format!("unserializable {}: {error}", rule.rule)
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sluice_core::ids::{Engine, RuleId};
    use sluice_core::logsource::LogSource;
    use sluice_core::predicate::Predicate;
    use sluice_core::rules::RequiredFields;

    use super::*;

    fn rule(id: &str, fields: &[&str]) -> RuleRequirements {
        RuleRequirements {
            rule: RuleId::of(Engine::Sigma, id),
            logsource: LogSource::default(),
            field_names: None,
            fields: RequiredFields::Known(
                fields.iter().map(|&f| f.into()).collect::<BTreeSet<_>>(),
            ),
            matches_raw_text: false,
            stateful: false,
            text_lines_only: false,
            prefilter: Predicate::Always,
        }
    }

    #[test]
    fn a_rule_read_the_same_has_the_same_fingerprint() {
        let once = fingerprints([&rule("a", &["Image", "User"])]);
        let again = fingerprints([&rule("a", &["Image", "User"])]);
        assert_eq!(once, again);
        assert!(once[0].requirements.starts_with("sha256:"));
        assert_eq!(once[0].requirements.len(), "sha256:".len() + 64);
    }

    #[test]
    fn a_rule_that_reads_another_field_has_another_fingerprint() {
        let before = fingerprints([&rule("a", &["Image"])]);
        let after = fingerprints([&rule("a", &["Image", "CommandLine"])]);
        assert_eq!(before[0].rule, after[0].rule);
        assert_ne!(before[0].requirements, after[0].requirements);
    }

    #[test]
    fn rules_that_share_an_id_are_one_fingerprint_whatever_their_order() {
        let (x, y) = (rule("a", &["Image"]), rule("a", &["User"]));
        let one = fingerprints([&x, &y]);
        assert_eq!(one.len(), 1);
        assert_eq!(one, fingerprints([&y, &x]));
        assert_ne!(one, fingerprints([&x]));
    }

    #[test]
    fn fingerprints_are_sorted_by_rule() {
        let listed = fingerprints([&rule("b", &[]), &rule("a", &[])]);
        let ids: Vec<&str> = listed.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(ids, ["sigma:a", "sigma:b"]);
    }
}
