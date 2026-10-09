//! One module per synthetic log source.

pub(crate) mod dns;
pub(crate) mod firewall;
pub(crate) mod linux_auth;
pub(crate) mod nginx;
pub(crate) mod sysmon;
pub(crate) mod windows_security;
mod winlog;

use serde_json::{Map, Value};
use sluice_core::logsource::LogSource;

use crate::Format;
use crate::fields::Fields;
use crate::rng::Rng;

/// How to generate one source and what it is.
pub(crate) struct Spec {
    pub(crate) id: &'static str,
    pub(crate) generate: fn(&mut Ctx),
    pub(crate) logsource: fn() -> LogSource,
    pub(crate) format: fn() -> Format,
}

/// Every source, in a fixed order. The order affects only tie-breaking between equal timestamps.
pub(crate) const SPECS: [Spec; 6] = [
    windows_security::SPEC,
    sysmon::SPEC,
    linux_auth::SPEC,
    firewall::SPEC,
    dns::SPEC,
    nginx::SPEC,
];

/// Every planted attack: name and description.
pub(crate) const SCENARIOS: [(&str, &str); 6] = [
    (
        windows_security::FAILED_LOGON_BURST,
        "12 failed logons for one account from one workstation within a minute",
    ),
    (
        sysmon::LSASS_ACCESS,
        "a renamed dump tool opens LSASS with read access (credential theft)",
    ),
    (
        sysmon::ENCODED_POWERSHELL,
        "whoami discovery followed by an encoded PowerShell command",
    ),
    (
        linux_auth::SSH_BRUTE_FORCE,
        "30 failed SSH passwords from one external IP, then a successful root login",
    ),
    (
        dns::BAD_DOMAIN_LOOKUP,
        "a workstation resolves a known malicious domain",
    ),
    (
        nginx::PATH_TRAVERSAL,
        "a scanner probes the web app with path traversal requests",
    ),
];

pub(crate) fn logsource(product: &str, service: Option<&str>) -> LogSource {
    LogSource {
        product: Some(product.to_owned()),
        service: service.map(str::to_owned),
        category: None,
    }
}

pub(crate) fn text_format() -> Format {
    Format::Text {
        field: "message".into(),
    }
}

pub(crate) fn json_format() -> Format {
    Format::Json
}

/// An event before it gets its id: ids are assigned after all sources are merged and sorted.
#[derive(Debug)]
pub(crate) struct Draft {
    pub(crate) timestamp: i64,
    pub(crate) fields: Map<String, Value>,
    /// The attack scenario this event belongs to, if any.
    pub(crate) scenario: Option<&'static str>,
}

/// Per-source generation context.
pub(crate) struct Ctx {
    pub(crate) rng: Rng,
    start: i64,
    duration_secs: i64,
    scale_percent: u64,
    drafts: Vec<Draft>,
}

impl Ctx {
    pub(crate) fn new(rng: Rng, start: i64, duration_secs: i64, scale_percent: u64) -> Self {
        Self {
            rng,
            start,
            duration_secs: duration_secs.max(1),
            scale_percent,
            drafts: Vec::new(),
        }
    }

    /// Scales a base volume (defined per hour at 100 %) to the configured duration and scale.
    pub(crate) fn volume(&self, per_hour: u64) -> u64 {
        let secs = u64::try_from(self.duration_secs).unwrap_or(1);
        per_hour
            .saturating_mul(self.scale_percent)
            .saturating_mul(secs)
            / (100 * 3_600)
    }

    /// A uniformly random time inside the window.
    pub(crate) fn any_time(&mut self) -> i64 {
        let span = u64::try_from(self.duration_secs).unwrap_or(1);
        self.start + i64::try_from(self.rng.below(span)).unwrap_or(0)
    }

    /// The time at `percent` of the window. Scenarios use it, so they land at stable positions
    /// whatever the duration.
    pub(crate) fn at_percent(&self, percent: i64) -> i64 {
        self.start + self.duration_secs * percent / 100
    }

    pub(crate) fn emit(&mut self, timestamp: i64, fields: Fields) {
        self.push(timestamp, fields, None);
    }

    pub(crate) fn emit_attack(&mut self, scenario: &'static str, timestamp: i64, fields: Fields) {
        self.push(timestamp, fields, Some(scenario));
    }

    fn push(&mut self, timestamp: i64, fields: Fields, scenario: Option<&'static str>) {
        self.drafts.push(Draft {
            timestamp,
            fields: fields.into_map(),
            scenario,
        });
    }

    pub(crate) fn into_drafts(self) -> Vec<Draft> {
        self.drafts
    }
}

/// A Beats-style agent envelope, identical for every event from one host: classic per-host fat.
pub(crate) fn beats_envelope(kind: &str, host: &str, agent_id: &str) -> Fields {
    use crate::fields::object;
    Fields::new()
        .set(
            "agent",
            object([
                ("type", kind.into()),
                ("version", "8.15.2".into()),
                ("id", agent_id.into()),
                ("name", host.into()),
                ("ephemeral_id", format!("{agent_id}-e").into()),
            ]),
        )
        .set("ecs", object([("version", "8.11.0".into())]))
}
