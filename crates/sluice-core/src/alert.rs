//! Alerts and the rule-engine contract the shadow proof relies on.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::event::Event;
use crate::ids::{EventId, RuleId};

/// One rule firing on one event.
///
/// For a correlation rule, `event` is the event that completed the correlation. Reductions keep
/// event ids, so the same alert on full and on forwarded data compares equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Alert {
    /// The rule that fired.
    pub rule: RuleId,
    /// The event it fired on.
    pub event: EventId,
}

/// A rule engine could not evaluate. The proof must treat this as "not proven", never as
/// "no alerts": two failed evaluations would otherwise compare equal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rule engine failed: {0}")]
pub struct EngineError(pub String);

/// Evaluates rules on one event at a time, without state (for example Wazuh `logtest`).
///
/// Used for spot checks where a full [`RuleEngine`] is not available: the rules an original
/// event fires are compared with those its reduced form fires.
pub trait EventRules {
    /// The rules that alert on this event body.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the rules cannot be evaluated; the check then fails closed.
    fn fired(
        &self,
        fields: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<BTreeSet<RuleId>, EngineError>;

    /// The rules that alert on one raw log line, as the SIEM receives it from a text source (a
    /// log file or syslog). Text rules such as Wazuh's `sshd` rules decode the line itself, so
    /// wrapping it in JSON would hide every match.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the rules cannot be evaluated; the check then fails closed.
    fn fired_line(&self, line: &str) -> Result<BTreeSet<RuleId>, EngineError>;
}

/// Evaluates detection rules over a sequence of events.
///
/// Implementations must be deterministic: the same events give the same alerts. Events arrive in
/// time order, and stateful rules (correlations, frequencies) see exactly those events, starting
/// from empty state on every call.
pub trait RuleEngine {
    /// All alerts the rules raise on `events`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if evaluation is impossible. It must never return a partial or
    /// empty set in place of an error.
    fn alerts(&self, events: &[Event]) -> Result<BTreeSet<Alert>, EngineError>;
}
