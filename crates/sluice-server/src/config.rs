//! The `sluice up` configuration file.

use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Map, Value};
use sluice_autopilot::Policy;
use sluice_core::schema::Schema;
use sluice_core::source::Source;

/// Everything `sluice up` needs to know.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address of the control plane's HTTP API.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The sources, each with the Vector source that receives it.
    pub sources: Vec<LiveSourceConfig>,
    /// Destination sinks (Vector sink configs). Sluice sets their `inputs`.
    pub destinations: Map<String, Value>,
    /// Vector secret backends for the destinations' credentials (`SECRET[name.key]`), such as
    /// `{siem: {type: directory, path: /run/secrets/sluice}}`. The name `sluice` is reserved.
    #[serde(default)]
    pub vector_secrets: Map<String, Value>,
    /// Directory of the full-fidelity archive.
    pub archive_dir: PathBuf,
    /// Vector's data directory.
    pub data_dir: PathBuf,
    /// A secret file of named operator tokens, one `name token` per line (ADR 0016). Each
    /// operator signs in with their own token, so the audit log names them.
    #[serde(default)]
    pub operators_file: Option<PathBuf>,
    /// Single sign-on for the console with an OIDC provider (ADR 0016).
    #[serde(default)]
    pub oidc: Option<crate::oidc::OidcConfig>,
    /// The configuration the Vector that `sluice up` starts runs. Sluice writes the safe
    /// configuration here (nothing saved: every event forwarded unchanged); the operator
    /// deploys a reviewed proposal here; with `auto_apply`, Sluice writes its own.
    pub vector_config: PathBuf,
    /// Where proven configurations are proposed (`vector.yaml` and `proposal.json`), for review
    /// before the operator deploys them to `vector_config` (ADR 0022). Default:
    /// `<data_dir>/proposals`.
    #[serde(default)]
    pub proposals_dir: Option<PathBuf>,
    /// Let Sluice apply its own proven configurations, without review: for demos and labs.
    /// Off by default: Sluice proposes, and only ever switches savings off by itself.
    #[serde(default)]
    pub auto_apply: bool,
    /// The Vector binary.
    #[serde(default = "default_vector")]
    pub vector_binary: PathBuf,
    /// Keep one in `tap_rate` events for the control plane.
    #[serde(default = "default_tap_rate")]
    pub tap_rate: u64,
    /// Seconds between cycles.
    #[serde(default = "default_cycle_secs")]
    pub cycle_secs: u64,
    /// The rolling window each cycle analyzes.
    #[serde(default)]
    pub window: WindowConfig,
    /// When proven recipes are enforced.
    #[serde(default)]
    pub promotion: PromotionConfig,
}

impl ServerConfig {
    /// Where proposals are written, or `None` when Sluice applies its own configurations.
    #[must_use]
    pub fn proposals(&self) -> Option<PathBuf> {
        (!self.auto_apply).then(|| {
            self.proposals_dir
                .clone()
                .unwrap_or_else(|| self.data_dir.join("proposals"))
        })
    }
}

/// A source plus the Vector source that receives it.
#[derive(Debug, Clone, Deserialize)]
pub struct LiveSourceConfig {
    /// Sluice's view of the source.
    #[serde(flatten)]
    pub source: Source,
    /// The Vector source configuration (must produce JSON objects).
    pub vector: Value,
    /// How events are shaped as the SIEM stores them, after the archive keeps the original.
    #[serde(default)]
    pub shape: Option<Shape>,
}

impl LiveSourceConfig {
    /// The source as the analysis sees it. A source that does not declare its field naming
    /// convention but has a `shape` follows the shape's: the shape writes those names.
    #[must_use]
    pub fn analysis_source(&self) -> Source {
        let mut source = self.source.clone();
        if let (false, Some(shape)) = (source.schema.is_declared(), self.shape) {
            source.schema = shape.schema();
        }
        source
    }
}

/// A shaping of raw events into a SIEM table's record (ADR 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// Vector `windows_event_log` events of the Security channel as Sentinel's `SecurityEvent`.
    SentinelSecurityEvent,
    /// Vector `windows_event_log` events of other channels as Sentinel's `WindowsEvent`.
    SentinelWindowsEvent,
    /// Syslog (Vector's `syslog` source, or a raw line) as Sentinel's `Syslog`.
    SentinelSyslog,
    /// Firewall records as Sentinel's `CommonSecurityLog`.
    SentinelCommonSecurityLog,
    /// Firewall records as Sentinel's normalized `ASimNetworkSessionLogs`.
    SentinelAsimNetworkSession,
    /// DNS query records as Sentinel's normalized `ASimDnsActivityLogs`.
    SentinelAsimDns,
    /// Web server access logs as Sentinel's normalized `ASimWebSessionLogs`.
    SentinelAsimWebSession,
}

impl Shape {
    /// The field naming convention of the records this shape writes: Windows event data under
    /// the names Sigma uses (ADR 0014), the ASIM tables under ASIM's, the other tables under
    /// their own columns.
    #[must_use]
    pub fn schema(self) -> Schema {
        match self {
            Self::SentinelSecurityEvent | Self::SentinelWindowsEvent => Schema::Sigma,
            Self::SentinelSyslog | Self::SentinelCommonSecurityLog => Schema::Sentinel,
            Self::SentinelAsimNetworkSession
            | Self::SentinelAsimDns
            | Self::SentinelAsimWebSession => Schema::Asim,
        }
    }

    /// The VRL that shapes an event.
    #[must_use]
    pub fn program(self) -> String {
        match self {
            Self::SentinelSecurityEvent => sluice_vector::windows::security_event_program(),
            Self::SentinelWindowsEvent => sluice_vector::windows::windows_event_program(),
            Self::SentinelSyslog => sluice_vector::syslog::syslog_program(),
            Self::SentinelCommonSecurityLog => {
                sluice_vector::common_security_log::common_security_log_program()
            }
            Self::SentinelAsimNetworkSession => {
                sluice_vector::asim_network_session::asim_network_session_program()
            }
            Self::SentinelAsimDns => sluice_vector::asim_dns::asim_dns_program(),
            Self::SentinelAsimWebSession => {
                sluice_vector::asim_web_session::asim_web_session_program()
            }
        }
    }
}

/// Bounds of the rolling window, per source.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowConfig {
    /// Most events kept per source.
    pub max_events_per_source: usize,
    /// Oldest event kept, in seconds.
    pub max_age_secs: i64,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            max_events_per_source: 20_000,
            max_age_secs: 3_600,
        }
    }
}

/// Promotion policy, in configuration form.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionConfig {
    /// Minimum time in shadow, in seconds.
    pub shadow_secs: i64,
    /// Minimum consecutive proofs in shadow.
    pub min_proofs: u32,
    /// Conservative mode: no recipe is enforced without an operator's approval (ADR 0016).
    #[serde(default)]
    pub approval: bool,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        let policy = Policy::default();
        Self {
            shadow_secs: policy.shadow_secs,
            min_proofs: policy.min_proofs,
            approval: policy.approval,
        }
    }
}

impl From<PromotionConfig> for Policy {
    fn from(config: PromotionConfig) -> Self {
        Self {
            shadow_secs: config.shadow_secs,
            min_proofs: config.min_proofs,
            approval: config.approval,
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:8686".to_owned()
}

fn default_vector() -> PathBuf {
    PathBuf::from("vector")
}

fn default_tap_rate() -> u64 {
    10
}

fn default_cycle_secs() -> u64 {
    300
}
