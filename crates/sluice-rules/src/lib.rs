//! Rule awareness: Sigma, Wazuh, Sentinel and Elastic rules as engine-neutral requirements.
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
mod wazuh;

pub use crate::elastic::{ElasticQuery, ElasticRules};
pub use crate::error::RulesError;
pub use crate::sentinel::{
    FetchedNames, KqlNames, SentinelRules, SentinelWorkspace, UncheckedNames,
};
pub use crate::sigma::{SigmaEngine, SigmaPipeline, SigmaRules};
pub use crate::wazuh::WazuhRules;

/// Whether `value` names a network, such as `10.0.0.0/8` or `fe80::/10`. Elasticsearch matches an
/// address against it by membership (`10.1.2.3` holds no `8`), which no test of the value's
/// text describes: a pre-filter widens it to the field having a value.
pub(crate) fn is_cidr(value: &str) -> bool {
    value.split_once('/').is_some_and(|(address, bits)| {
        address.parse::<std::net::IpAddr>().is_ok() && bits.parse::<u8>().is_ok()
    })
}

/// The significant digits of a value that is a number: without sign, leading zeros and trailing
/// fractional zeros (`04624` and `4624.0` give `4624`). Engines that compare a number by value
/// match every way of writing it, and each holds these digits, but one with an exponent. `None`
/// for anything else.
pub(crate) fn significant_digits(value: &str) -> Option<String> {
    let unsigned = value.trim_start_matches(['+', '-']);
    if unsigned.is_empty()
        || unsigned == "."
        || unsigned.matches('.').count() > 1
        || !unsigned.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return None;
    }
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let whole = whole.trim_start_matches('0');
    let fraction = fraction.trim_end_matches('0');
    let digits = if fraction.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fraction}")
    };
    // Zero: every way to write it holds a `0`.
    Some(if digits.is_empty() {
        "0".to_owned()
    } else {
        digits
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn numbers_keep_their_significant_digits() {
        assert_eq!(super::significant_digits("04624").as_deref(), Some("4624"));
        assert_eq!(super::significant_digits("-4.50").as_deref(), Some("4.5"));
        assert_eq!(super::significant_digits("0.0").as_deref(), Some("0"));
        assert_eq!(super::significant_digits("4.0.1"), None);
        assert_eq!(super::significant_digits("4624a"), None);
    }

    #[test]
    fn networks_are_told_from_paths_and_dates() {
        assert!(super::is_cidr("10.0.0.0/8"));
        assert!(super::is_cidr("fe80::/10"));
        assert!(!super::is_cidr("/usr/bin"));
        assert!(!super::is_cidr("10/8"));
        assert!(!super::is_cidr("10.0.0.0"));
    }
}
