//! The control plane's state and one control cycle.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError, RwLock};

use serde_json::{Value, json};
use sluice_autopilot::{
    Helpers, Input, Lifecycle, RecipeBook, Report, Settings, Transition, cycle,
};
use sluice_core::event::Timestamp;
use sluice_core::source::Source;
use sluice_rules::{SigmaRules, WazuhRules};
use sluice_vector::{LiveSettings, LiveSource, Plan, VrlReducer, live_config};

use crate::config::ServerConfig;

/// Name of Sluice's own Vector secret backend; reserved in `vector_secrets`.
pub(crate) const SECRET_BACKEND: &str = "sluice";
/// How the tap sinks refer to the control token.
const TOKEN_REFERENCE: &str = "SECRET[sluice.control_token]";
use crate::error::ServerError;
use crate::status::{RuleInfo, Status};
use crate::window::Windows;

/// The rules the control plane enforces against.
pub struct Rules {
    /// Sigma rules, evaluated in every proof.
    pub sigma: SigmaRules,
    /// Wazuh rules, constraining the guardrails.
    pub wazuh: Option<WazuhRules>,
}

/// What one control cycle did.
#[derive(Debug, Default)]
pub(crate) struct CycleReport {
    /// Lifecycle transitions.
    pub(crate) transitions: Vec<Transition>,
    /// Whether the Vector configuration was rewritten (Vector must reload).
    pub(crate) config_changed: bool,
}

/// Everything the HTTP handlers and the control loop share.
pub(crate) struct Shared {
    pub(crate) config: ServerConfig,
    pub(crate) sources: Vec<Source>,
    rules: Rules,
    book: RecipeBook,
    pub(crate) windows: Mutex<Windows>,
    lifecycle: Mutex<Lifecycle>,
    pub(crate) status: RwLock<Status>,
    /// What every loaded rule needs; fixed for the process lifetime.
    pub(crate) rule_info: Vec<RuleInfo>,
    /// The bearer token every route but `/healthz` requires, if set.
    pub(crate) control_token: Option<String>,
    last_config: Mutex<String>,
}

impl Shared {
    pub(crate) fn new(
        config: ServerConfig,
        rules: Rules,
        book: RecipeBook,
        control_token: Option<String>,
    ) -> Self {
        let sources = config.sources.iter().map(|s| s.source.clone()).collect();
        let mut rule_info: Vec<RuleInfo> = rules
            .sigma
            .requirements()
            .iter()
            .map(|r| RuleInfo::new("sigma", r))
            .collect();
        if let Some(wazuh) = &rules.wazuh {
            rule_info.extend(
                wazuh
                    .requirements()
                    .iter()
                    .map(|r| RuleInfo::new("wazuh", r)),
            );
        }
        Self {
            rule_info,
            control_token,
            windows: Mutex::new(Windows::new(config.window)),
            lifecycle: Mutex::new(Lifecycle::new(config.promotion.into())),
            config,
            sources,
            rules,
            book,
            status: RwLock::new(Status::default()),
            last_config: Mutex::new(String::new()),
        }
    }

    /// The directory of Sluice's own Vector secrets, next to Vector's data.
    fn secrets_dir(&self) -> PathBuf {
        self.config.data_dir.join("sluice-secrets")
    }

    /// Writes the control token where Vector's `sluice` secret backend reads it, readable by
    /// this user only. Without a token, there is nothing to write.
    pub(crate) fn write_secrets(&self) -> Result<(), ServerError> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let Some(token) = &self.control_token else {
            return Ok(());
        };
        let io = |e: std::io::Error| ServerError::Io(format!("writing the control token: {e}"));
        let dir = self.secrets_dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(io)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("control_token"))
            .map_err(io)?;
        std::io::Write::write_all(&mut file, token.as_bytes()).map_err(io)
    }

    /// The configuration with nothing enforced: every source passes through.
    pub(crate) fn initial_config(&self) -> Result<String, ServerError> {
        self.render(&[], &VrlReducer::default())
    }

    /// Writes the configuration with nothing enforced: every source passes through.
    pub(crate) fn write_initial_config(&self) -> Result<(), ServerError> {
        let yaml = self.initial_config()?;
        self.write_if_changed(&yaml).map(|_| ())
    }

    /// Runs one cycle on the current window.
    pub(crate) fn run_cycle(&self, now: i64) -> Result<CycleReport, ServerError> {
        let events = lock(&self.windows).snapshot(now);
        if events.is_empty() {
            return Ok(CycleReport::default());
        }
        let mut lifecycle = lock(&self.lifecycle);
        let input = Input {
            sources: &self.sources,
            events: &events,
            sigma: &self.rules.sigma,
            wazuh: self.rules.wazuh.as_ref(),
        };
        let result = cycle(
            input,
            &self.book,
            &Settings::default(),
            Helpers::default(),
            &mut lifecycle,
            Timestamp(now),
        )
        .map_err(|e| ServerError::Cycle(e.to_string()))?;
        let yaml = self.render(&result.plans(), &result.data_plane)?;
        let config_changed = self.write_if_changed(&yaml)?;

        let mut status = self.status.write().unwrap_or_else(PoisonError::into_inner);
        let report = Report::new(
            &result.analysis,
            &self.rules.sigma,
            self.rules.wazuh.as_ref(),
        );
        status.record(now, &result, &lifecycle, &report, &self.sources);
        status.window = lock(&self.windows)
            .sizes()
            .into_iter()
            .map(|(s, n)| (s.to_string(), n))
            .collect();
        Ok(CycleReport {
            transitions: result.transitions,
            config_changed,
        })
    }

    fn render(&self, plans: &[Plan<'_>], data_plane: &VrlReducer) -> Result<String, ServerError> {
        let sources: Vec<LiveSource<'_>> = self
            .config
            .sources
            .iter()
            .map(|s| LiveSource {
                source: &s.source,
                vector: &s.vector,
            })
            .collect();
        let mut secret_backends = self.config.vector_secrets.clone();
        if self.control_token.is_some() {
            secret_backends.insert(
                SECRET_BACKEND.to_owned(),
                json!({ "type": "directory", "path": self.secrets_dir() }),
            );
        }
        let control_plane = format!("http://{}", self.config.listen);
        let archive_dir = self.config.archive_dir.display().to_string();
        let data_dir = self.config.data_dir.display().to_string();
        let settings = LiveSettings {
            control_plane: &control_plane,
            tap_rate: self.config.tap_rate,
            archive_dir: &archive_dir,
            data_dir: &data_dir,
            destinations: &self.config.destinations,
            tap_token: self.control_token.as_ref().map(|_| TOKEN_REFERENCE),
            secret_backends: &secret_backends,
        };
        live_config(&sources, plans, data_plane, &settings)
            .map_err(|e| ServerError::Config(e.to_string()))
    }

    /// Writes the Vector configuration atomically (temp file, then rename) if it changed, so
    /// Vector never reads a half-written file. Returns whether it changed.
    fn write_if_changed(&self, yaml: &str) -> Result<bool, ServerError> {
        let mut last = lock(&self.last_config);
        if *last == yaml {
            return Ok(false);
        }
        write_atomic(&self.config.vector_config, yaml)?;
        yaml.clone_into(&mut last);
        tracing::info!(path = %self.config.vector_config.display(), "wrote Vector configuration");
        Ok(true)
    }
}

pub(crate) fn write_atomic(path: &Path, contents: &str) -> Result<(), ServerError> {
    let io = |e: std::io::Error| ServerError::Io(format!("{}: {e}", path.display()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io)?;
    }
    let temporary = path.with_extension("yaml.tmp");
    fs::write(&temporary, contents).map_err(io)?;
    fs::rename(&temporary, path).map_err(io)
}

/// Locks a mutex, recovering the data if another thread panicked while holding it: the state
/// is only ever replaced whole, so it is never left half-updated.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The object inside a JSON value; tapped events must be objects.
pub(crate) fn as_object(value: Value) -> Option<serde_json::Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}
