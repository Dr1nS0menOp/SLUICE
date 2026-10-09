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
            fields: RequiredFields::Unknown,
            matches_raw_text: true,
            stateful: true,
            prefilter: Predicate::Always,
        }
    }
}
