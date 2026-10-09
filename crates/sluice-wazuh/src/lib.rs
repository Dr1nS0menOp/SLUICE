//! Exact Wazuh checks through the manager API's `PUT /logtest` (Wazuh 4.x).
//!
//! `logtest` decodes one event with the manager's real decoders and rules and reports the rule
//! that alerts, if any. Sluice sends each event as JSON (`log_format: json`), the way it forwards
//! them, and compares the original with its reduced form.
//!
//! `logtest` keeps no frequency state between calls, so stateful rules are not exercised here;
//! they are covered by their requirements (all events they could count are forwarded).
//!
//! The API shapes follow the Wazuh 4.12 `OpenAPI` spec. Wazuh's `main` branch (5.x) no longer
//! has `/logtest`, so this integration targets 4.x managers.

mod client;

pub use crate::client::{Http, Logtest, LogtestConfig, Transport, WazuhError};
