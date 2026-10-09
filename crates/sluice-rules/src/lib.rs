//! Rule awareness: Sigma and Wazuh rules as engine-neutral requirements.
//!
//! Each engine's rules are reduced to [`sluice_core::rules::RuleRequirements`], the facts the
//! guardrails need: scope, fields read, raw-text matching, statefulness and a superset
//! pre-filter. Sigma rules can also be evaluated ([`SigmaEngine`]) for the shadow proof.
//!
//! Every uncertainty widens a requirement. A rule we cannot fully understand still counts, as an
//! opaque requirement that blocks every cut it might be affected by, and it is reported as a
//! problem.

mod error;
mod sigma;
mod wazuh;

pub use crate::error::RulesError;
pub use crate::sigma::{SigmaEngine, SigmaRules};
pub use crate::wazuh::WazuhRules;
