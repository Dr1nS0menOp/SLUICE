//! Rule awareness: Sigma, Wazuh, Sentinel, Elastic and Splunk rules as engine-neutral
//! requirements.
//!
//! Each engine's rules are reduced to [`sluice_core::rules::RuleRequirements`], the facts the
//! guardrails need: scope, fields read, raw-text matching, statefulness and a superset
//! pre-filter. Sigma rules can also be evaluated ([`SigmaEngine`]) for the shadow proof.
//!
//! Every uncertainty widens a requirement. A rule we cannot fully understand still counts, as an
//! opaque requirement that blocks every cut it might be affected by, and it is reported as a
//! problem.

mod elastic;
mod error;
mod sentinel;
mod sigma;
mod splunk;
mod wazuh;

pub use crate::elastic::{ElasticQuery, ElasticRules};
pub use crate::error::RulesError;
pub use crate::sentinel::SentinelRules;
pub use crate::sigma::{SigmaEngine, SigmaPipeline, SigmaRules};
pub use crate::splunk::SplunkRules;
pub use crate::wazuh::WazuhRules;

/// Whether `value` names a network, such as `10.0.0.0/8` or `fe80::/10`. Elasticsearch and
/// Splunk match an address against it by membership (`10.1.2.3` holds no `8`), which no test
/// of the value's text describes: a pre-filter widens it to the field having a value.
pub(crate) fn is_cidr(value: &str) -> bool {
    value.split_once('/').is_some_and(|(address, bits)| {
        address.parse::<std::net::IpAddr>().is_ok() && bits.parse::<u8>().is_ok()
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn networks_are_told_from_paths_and_dates() {
        assert!(super::is_cidr("10.0.0.0/8"));
        assert!(super::is_cidr("fe80::/10"));
        assert!(!super::is_cidr("/usr/bin"));
        assert!(!super::is_cidr("10/8"));
        assert!(!super::is_cidr("10.0.0.0"));
    }
}
