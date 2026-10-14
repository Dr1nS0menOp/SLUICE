//! Microsoft Sentinel's rule inventory, read-only (ADR 0021).
//!
//! [`fetch`] reads what a workspace runs and returns it as files the Sentinel loader
//! (`sluice_rules::SentinelRules`) reads:
//!
//! - `rules/`: enabled `Scheduled` and `NRT` analytics rules (`id`, `name`, `kind`, `query`).
//! - `saved/`: saved searches, hunting queries among them, as rules whose rows must not change.
//! - `functions/`: workspace functions (`FunctionName`, `FunctionQuery`), so rules that call one
//!   read what its body reads.
//! - `queries/`: with [`Options::query_log_days`], every distinct query people ran
//!   (`LAQueryLogs`), as rules.
//!
//! The files are JSON, which is also YAML. Credentials are an Azure AD application's client
//! secret (client credentials flow); Sluice only ever reads.

mod azure;
mod inventory;

pub use crate::azure::{Credentials, Http, SentinelError, Transport};
pub use crate::inventory::{Options, fetch};
