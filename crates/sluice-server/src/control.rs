//! The control plane's state and one control cycle.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError, RwLock};

use serde_json::{Value, json};
use sluice_autopilot::{
    Helpers, Input, Lifecycle, RecipeBook, Report, Sentinel, Settings, Transition, cycle,
};
use sluice_core::alert::RuleEngine;
use sluice_core::event::{Event, Timestamp};
use sluice_core::source::Source;
use sluice_rules::{SentinelRules, SigmaRules, WazuhRules};
use sluice_vector::{
    LiveProfile, LiveSettings, LiveSource, Plan, destination_profile, live_config,
};

use crate::config::{ServerConfig, Shape};

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
    /// Microsoft Sentinel analytics rules, for destinations that name `sentinel`.
    pub sentinel: Option<SentinelRuleSet>,
}

/// Sentinel analytics rules and, if available, the engine that runs them for the proof
/// (ADR 0015).
pub struct SentinelRuleSet {
    /// The rules; their requirements constrain the guardrails.
    pub rules: SentinelRules,
    /// Runs the rules' queries (the Kusto emulator). Without it, the proof of a profile with
    /// Sentinel covers its other rule sets only.
    pub engine: Option<Box<dyn RuleEngine + Send + Sync>>,
}

/// What one control cycle did.
#[derive(Debug, Default)]
pub(crate) struct CycleReport {
    /// Lifecycle transitions, with the rule profile they happened in.
    pub(crate) transitions: Vec<(String, Transition)>,
    /// Whether the Vector configuration was rewritten (Vector must reload).
    pub(crate) config_changed: bool,
}

/// The rules one group of destinations' SIEMs run, and what Sluice proved against them. Each
/// profile has its own lifecycle: a recipe enforced for a Sentinel destination proven against
/// Sigma says nothing about a Wazuh destination.
pub(crate) struct Profile {
    pub(crate) name: String,
    sigma: bool,
    wazuh: bool,
    sentinel: bool,
    pub(crate) lifecycle: Mutex<Lifecycle>,
    pub(crate) status: RwLock<Status>,
}

/// Everything the HTTP handlers and the control loop share.
pub(crate) struct Shared {
    pub(crate) config: ServerConfig,
    pub(crate) sources: Vec<Source>,
    rules: Rules,
    /// Stands in for Sigma in profiles that do not run it.
    no_sigma: SigmaRules,
    book: RecipeBook,
    pub(crate) windows: Mutex<Windows>,
    /// One per rule profile any destination uses, sorted by name.
    pub(crate) profiles: Vec<Profile>,
    /// What every loaded rule needs; fixed for the process lifetime.
    pub(crate) rule_info: Vec<RuleInfo>,
    /// The bearer token every route but `/healthz` requires, if set.
    pub(crate) control_token: Option<String>,
    last_config: Mutex<String>,
    /// Where operator decisions and the audit log are kept (ADR 0016).
    pub(crate) store: crate::operator::Store,
    /// Held templates and kept fields per profile.
    pub(crate) decisions: Mutex<BTreeMap<String, crate::operator::ProfileDecisions>>,
    /// Named operator tokens; empty without an operators file.
    pub(crate) operators: Vec<crate::operators::Operator>,
    /// Single sign-on, when configured.
    pub(crate) oidc: Option<crate::oidc::Oidc>,
}

impl Shared {
    /// # Errors
    ///
    /// Returns [`ServerError::Config`] if a destination names rules that are not loaded.
    pub(crate) fn new(
        config: ServerConfig,
        rules: Rules,
        book: RecipeBook,
        control_token: Option<String>,
    ) -> Result<Self, ServerError> {
        let loaded = loaded(&rules);
        let mut names = std::collections::BTreeSet::new();
        for (name, sink) in &config.destinations {
            names.insert(
                destination_profile(name, sink, &loaded)
                    .map_err(|e| ServerError::Config(e.to_string()))?,
            );
        }
        let listed: Vec<String> = names.iter().cloned().collect();
        let operators = match &config.operators_file {
            Some(path) => crate::operators::load(path)?,
            None => Vec::new(),
        };
        let oidc = config
            .oidc
            .clone()
            .map(crate::oidc::Oidc::new)
            .transpose()?;
        let store = crate::operator::Store::new(&config.data_dir);
        let decisions = store.load()?;
        let profiles: Vec<Profile> = names
            .into_iter()
            .map(|name| Profile {
                sigma: name.split('+').any(|r| r == "sigma"),
                wazuh: name.split('+').any(|r| r == "wazuh"),
                sentinel: name.split('+').any(|r| r == "sentinel"),
                lifecycle: Mutex::new(Lifecycle::new(config.promotion.into())),
                status: RwLock::new(Status {
                    profile: name.clone(),
                    profiles: listed.clone(),
                    ..Status::default()
                }),
                name,
            })
            .collect();
        for profile in &profiles {
            let decided = decisions.get(&profile.name).cloned().unwrap_or_default();
            let mut lifecycle = lock(&profile.lifecycle);
            for template in &decided.held {
                lifecycle.hold(&sluice_core::ids::TemplateId::new(template.as_str()));
            }
            let mut status = profile
                .status
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            status.operator = crate::operator::operator_status(&lifecycle, &decided, &[]);
        }
        let sources = config
            .sources
            .iter()
            .map(crate::config::LiveSourceConfig::analysis_source)
            .collect();
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
        if let Some(sentinel) = &rules.sentinel {
            rule_info.extend(
                sentinel
                    .rules
                    .requirements()
                    .iter()
                    .map(|r| RuleInfo::new("sentinel", r)),
            );
        }
        Ok(Self {
            rule_info,
            control_token,
            windows: Mutex::new(Windows::new(config.window)),
            profiles,
            config,
            sources,
            rules,
            no_sigma: SigmaRules::parse(std::iter::empty::<&str>())
                .map_err(|e| ServerError::Config(e.to_string()))?,
            book,
            last_config: Mutex::new(String::new()),
            store,
            decisions: Mutex::new(decisions),
            operators,
            oidc,
        })
    }

    /// The profile named `name`, or the first one (with a single profile, the only one).
    pub(crate) fn profile(&self, name: Option<&str>) -> Option<&Profile> {
        match name {
            Some(name) => self.profiles.iter().find(|p| p.name == name),
            None => self.profiles.first(),
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
        self.render(&[])
    }

    /// Writes the configuration with nothing enforced: every source passes through.
    pub(crate) fn write_initial_config(&self) -> Result<(), ServerError> {
        let yaml = self.initial_config()?;
        self.write_if_changed(&yaml).map(|_| ())
    }

    /// Runs one cycle on the current window, for every rule profile: each is analyzed, proven
    /// and advanced against its own rules only. The configuration is written once, with every
    /// profile's pipeline; if any profile fails, nothing changes.
    pub(crate) fn run_cycle(&self, now: i64) -> Result<CycleReport, ServerError> {
        let events = lock(&self.windows).take(now);
        let result = if events.is_empty() {
            Ok(CycleReport::default())
        } else {
            self.cycle_on(&events, now)
        };
        lock(&self.windows).give_back(events);
        result
    }

    fn cycle_on(&self, events: &[Event], now: i64) -> Result<CycleReport, ServerError> {
        let decisions = lock(&self.decisions).clone();
        let mut lifecycles: Vec<_> = self.profiles.iter().map(|p| lock(&p.lifecycle)).collect();
        let mut results = Vec::with_capacity(self.profiles.len());
        for (profile, lifecycle) in self.profiles.iter().zip(&mut lifecycles) {
            let input = self.input(profile, events);
            let settings = Settings {
                operator_rules: decisions
                    .get(&profile.name)
                    .map(|d| d.rules(&self.sources))
                    .unwrap_or_default(),
                ..Settings::default()
            };
            let result = cycle(
                input,
                &self.book,
                &settings,
                Helpers::default(),
                lifecycle,
                Timestamp(now),
            )
            .map_err(|e| ServerError::Cycle(format!("profile {}: {e}", profile.name)))?;
            results.push(result);
        }
        let plans: Vec<Vec<Plan<'_>>> =
            results.iter().map(sluice_autopilot::Cycle::plans).collect();
        let live: Vec<LiveProfile<'_>> = self
            .profiles
            .iter()
            .zip(&results)
            .zip(&plans)
            .map(|((profile, result), plans)| LiveProfile {
                name: &profile.name,
                plans,
                data_plane: &result.data_plane,
            })
            .collect();
        let yaml = self.render(&live)?;
        let config_changed = self.write_if_changed(&yaml)?;

        // The window this cycle analyzed, per source.
        let mut window: BTreeMap<String, usize> = BTreeMap::new();
        for event in events {
            *window.entry(event.source.to_string()).or_default() += 1;
        }
        let mut transitions = Vec::new();
        for ((profile, lifecycle), result) in self.profiles.iter().zip(&lifecycles).zip(&results) {
            let input = self.input(profile, events);
            let report = Report::new(&result.analysis, input.sigma, input.wazuh);
            let mut status = profile
                .status
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            status.record(now, result, lifecycle, &report, &self.sources, events);
            status.window.clone_from(&window);
            let decided = decisions.get(&profile.name).cloned().unwrap_or_default();
            status.operator =
                crate::operator::operator_status(lifecycle, &decided, &status.history);
            transitions.extend(
                result
                    .transitions
                    .iter()
                    .map(|t| (profile.name.clone(), t.clone())),
            );
        }
        Ok(CycleReport {
            transitions,
            config_changed,
        })
    }

    /// The analysis input of a profile: the events with the rules it runs.
    fn input<'a>(&'a self, profile: &Profile, events: &'a [Event]) -> Input<'a> {
        let sigma = if profile.sigma {
            &self.rules.sigma
        } else {
            &self.no_sigma
        };
        Input {
            sources: &self.sources,
            events,
            sigma,
            wazuh: self.rules.wazuh.as_ref().filter(|_| profile.wazuh),
            sentinel: self
                .rules
                .sentinel
                .as_ref()
                .filter(|_| profile.sentinel)
                .map(|s| Sentinel {
                    rules: &s.rules,
                    engine: s.engine.as_deref().map(|e| e as &dyn RuleEngine),
                }),
        }
    }

    fn render(&self, profiles: &[LiveProfile<'_>]) -> Result<String, ServerError> {
        let shapes: Vec<Option<String>> = self
            .config
            .sources
            .iter()
            .map(|s| s.shape.map(Shape::program))
            .collect();
        let sources: Vec<LiveSource<'_>> = self
            .config
            .sources
            .iter()
            .zip(&shapes)
            .map(|(s, shape)| LiveSource {
                source: &s.source,
                vector: &s.vector,
                shape: shape.as_deref(),
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
        live_config(&sources, profiles, &loaded(&self.rules), &settings)
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

/// The rule sets a destination can name: Sigma always (it may be empty), Wazuh and Sentinel
/// when loaded.
fn loaded(rules: &Rules) -> Vec<&'static str> {
    let mut loaded = vec!["sigma"];
    if rules.wazuh.is_some() {
        loaded.push("wazuh");
    }
    if rules.sentinel.is_some() {
        loaded.push("sentinel");
    }
    loaded
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
