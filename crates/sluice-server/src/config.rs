//! The `sluice up` configuration file.

use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Map, Value};
use sluice_autopilot::Policy;
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
    /// Where Sluice writes the Vector configuration.
    pub vector_config: PathBuf,
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

/// A source plus the Vector source that receives it.
#[derive(Debug, Clone, Deserialize)]
pub struct LiveSourceConfig {
    /// Sluice's view of the source.
    #[serde(flatten)]
    pub source: Source,
    /// The Vector source configuration (must produce JSON objects).
    pub vector: Value,
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
}

impl Default for PromotionConfig {
    fn default() -> Self {
        let policy = Policy::default();
        Self {
            shadow_secs: policy.shadow_secs,
            min_proofs: policy.min_proofs,
        }
    }
}

impl From<PromotionConfig> for Policy {
    fn from(config: PromotionConfig) -> Self {
        Self {
            shadow_secs: config.shadow_secs,
            min_proofs: config.min_proofs,
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
