//! `vector.yaml` for live operation (`sluice up`, ADR 0005).
//!
//! Per source:
//!
//! ```text
//! <operator's Vector source> ─┬─▶ archive (gzip NDJSON, before any reduction)
//!                             ├─▶ sample ─▶ http ─▶ control plane /tap/<source>
//!                             └─▶ sluice_<src> (proven VRL) ─▶ route ─┬─ forward ──┐
//!                                       │ errors              └─ summarize ─▶ reduce ─┤
//!                                       └──────────────────────────────────────────────┴─▶ destinations
//! ```
//!
//! A source without a program (nothing discovered yet) goes straight to the destinations.
//!
//! Destinations whose SIEMs run different rules get different reductions: each rule profile
//! (`sluice_rules` on a destination, all loaded rules by default) has its own program, route and
//! summaries per source, proven against that profile's rules only. The input, the archive and the
//! tap stay one per source. With a single profile the component names carry no profile tag.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sluice_core::ids::SourceId;
use sluice_core::source::{Source, SourceFormat};

use crate::config::{Components, Pipeline};
use crate::connect::{AZURE_MAX_BATCH_BYTES, AZURE_MAX_REQUEST_BYTES};
use crate::error::VectorError;
use crate::program::{FORWARD, Plan};
use crate::runtime::VrlReducer;

/// A source and the Vector source that receives it (any Vector source producing JSON objects).
#[derive(Debug, Clone, Copy)]
pub struct LiveSource<'a> {
    /// Sluice's view of the source.
    pub source: &'a Source,
    /// The Vector source configuration, used verbatim.
    pub vector: &'a Value,
    /// VRL that shapes each event as the SIEM stores it (such as Sentinel's `SecurityEvent`,
    /// [`crate::windows`]). It runs after the archive, which keeps the original (contract rule
    /// 2), and before the tap and the reductions, so Sluice proves on what the SIEM stores.
    pub shape: Option<&'a str>,
}

/// Deployment settings.
#[derive(Debug, Clone, Copy)]
pub struct LiveSettings<'a> {
    /// Base URL of the control plane, such as `http://127.0.0.1:8686`.
    pub control_plane: &'a str,
    /// Keep one in `tap_rate` events for the control plane.
    pub tap_rate: u64,
    /// Directory of the full-fidelity archive.
    pub archive_dir: &'a str,
    /// Vector's data directory.
    pub data_dir: &'a str,
    /// Destination sinks, used verbatim except for `inputs`, which Sluice sets.
    pub destinations: &'a Map<String, Value>,
    /// Reference to the control plane's bearer token, if it requires one, such as
    /// `SECRET[sluice.control_token]`. The token itself never appears in the file.
    pub tap_token: Option<&'a str>,
    /// Vector secret backends (`secret:`), used verbatim. Vector 0.59 does not interpolate
    /// `${VAR}` without `--dangerously-allow-env-var-interpolation`, so credentials go through
    /// these (`SECRET[backend.key]`).
    pub secret_backends: &'a Map<String, Value>,
}

/// The proven reductions for the destinations of one rule profile.
#[derive(Debug, Clone, Copy)]
pub struct LiveProfile<'a> {
    /// The profile's name, as [`destination_profile`] gives it.
    pub name: &'a str,
    /// Each template with its deployed recipe.
    pub plans: &'a [Plan<'a>],
    /// The data plane enforcing `plans`.
    pub data_plane: &'a VrlReducer,
}

/// Destination key, removed before Vector sees the sink, naming the rule sets the destination's
/// SIEM runs: `[sigma]`, `[wazuh]` or both. Without it, every loaded rule set applies. A
/// destination is only proven against its own rules, so a SIEM that never runs Wazuh rules is not
/// held back by them.
pub const RULES_KEY: &str = "sluice_rules";

/// The rule profile of a destination: its `sluice_rules`, sorted and joined with `+`, or all of
/// `loaded` when it has none.
///
/// # Errors
///
/// Returns [`VectorError::Config`] if `sluice_rules` is not a non-empty list of loaded rule sets.
pub fn destination_profile(
    name: &str,
    sink: &Value,
    loaded: &[&str],
) -> Result<String, VectorError> {
    let invalid = || {
        VectorError::Config(format!(
            "destination {name}: {RULES_KEY} must be a non-empty list of loaded rule sets ({})",
            loaded.join(", ")
        ))
    };
    let rules: BTreeSet<&str> = match sink.get(RULES_KEY) {
        None => loaded.iter().copied().collect(),
        Some(list) => list
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(|r| {
                r.as_str()
                    .filter(|r| loaded.contains(r))
                    .ok_or_else(invalid)
            })
            .collect::<Result<_, _>>()?,
    };
    if rules.is_empty() {
        return Err(invalid());
    }
    Ok(rules.into_iter().collect::<Vec<_>>().join("+"))
}

/// Renders the live configuration.
///
/// `profiles` holds one entry per rule profile any destination uses (see
/// [`destination_profile`]); a destination whose profile is missing gets the sources unreduced.
///
/// # Errors
///
/// Returns [`VectorError::Config`] if a destination is misconfigured or the configuration cannot
/// be serialized.
pub fn live_config(
    sources: &[LiveSource<'_>],
    profiles: &[LiveProfile<'_>],
    loaded: &[&str],
    settings: &LiveSettings<'_>,
) -> Result<String, VectorError> {
    let analysis_sources: Vec<Source> = sources.iter().map(|s| s.source.clone()).collect();
    crate::config::check_sources(&analysis_sources)?;
    let mut pipeline = Pipeline::default();
    let mut outputs: BTreeMap<&str, Outputs> = BTreeMap::new();
    let mut unreduced = Outputs::default();
    let tagged = profiles.len() > 1;
    for live in sources {
        let c = Components::for_source(&live.source.id);
        let entry = add_intake(&mut pipeline, live, &c, settings);

        unreduced.add_events(live.source, [entry.clone()]);
        for profile in profiles {
            let p = if tagged {
                c.for_profile(profile.name)
            } else {
                c.clone()
            };
            let out = outputs.entry(profile.name).or_default();
            match profile.data_plane.program(&live.source.id) {
                Some(program) => {
                    pipeline.add_transforms(
                        &p,
                        &entry,
                        &live.source.id,
                        program.source(),
                        profile.plans,
                    );
                    out.add_events(
                        live.source,
                        [
                            format!("{}.{FORWARD}", p.split),
                            format!("{}._unmatched", p.split),
                            format!("{}.dropped", p.program),
                        ],
                    );
                    out.summaries
                        .push((live.source.id.clone(), p.summaries.clone()));
                }
                None => out.add_events(live.source, [entry.clone()]),
            }
        }
    }
    for (name, sink) in settings.destinations {
        let sink = destination(name, sink, &outputs, &unreduced, loaded, sources)?;
        pipeline.sinks.insert(name.clone(), sink);
    }

    let mut config = json!({
        "data_dir": settings.data_dir,
        "sources": pipeline.sources,
        "transforms": pipeline.transforms,
        "sinks": pipeline.sinks,
    });
    if !settings.secret_backends.is_empty() {
        config["secret"] = json!(settings.secret_backends);
    }
    let yaml = serde_yaml_ng::to_string(&config).map_err(|e| VectorError::Config(e.to_string()))?;
    Ok(format!(
        "# Generated by `sluice up`. Do not edit: Sluice rewrites this file as recipes are\n\
         # promoted or rolled back, and Vector reloads it.\n{yaml}"
    ))
}

/// Destination key, removed before Vector sees the sink, that limits a destination to events of
/// some source formats: `[json]` or `[text]`. A SIEM may need text sources as raw lines (Wazuh's
/// syslog rules) and JSON sources as JSON; summaries are JSON records and go with `json`.
pub const FORMATS_KEY: &str = "sluice_formats";

/// Destination key, removed before Vector sees the sink, that limits a destination to some
/// sources by id, such as `[windows-security]`. A SIEM table takes one shape of record:
/// Sentinel's `SecurityEvent` and `WindowsEvent` need one destination each.
pub const SOURCES_KEY: &str = "sluice_sources";

/// Destination key, removed before Vector sees the sink, that limits a destination to some kinds
/// of record: `[events]` or `[summaries]` (both when absent). A table that takes one shape of
/// record cannot hold Sluice's summary records: they go to a table of their own (`sluice connect
/// sentinel --summary-table`).
pub const RECORDS_KEY: &str = "sluice_records";

/// Which kinds of record a destination takes.
#[derive(Clone, Copy)]
struct Records {
    events: bool,
    summaries: bool,
}

impl Records {
    /// The kinds a destination's `sluice_records` names; both without the key.
    fn of(name: &str, value: Option<&Value>) -> Result<Self, VectorError> {
        let Some(value) = value else {
            return Ok(Self {
                events: true,
                summaries: true,
            });
        };
        let invalid = || {
            VectorError::Config(format!(
                "destination {name}: {RECORDS_KEY} must be a non-empty list of `events` and \
                 `summaries`"
            ))
        };
        let mut records = Self {
            events: false,
            summaries: false,
        };
        for kind in value.as_array().ok_or_else(invalid)? {
            match kind.as_str() {
                Some("events") => records.events = true,
                Some("summaries") => records.summaries = true,
                _ => return Err(invalid()),
            }
        }
        if !(records.events || records.summaries) {
            return Err(invalid());
        }
        Ok(records)
    }
}

/// The component outputs that feed destinations, by kind, each with the source it carries.
#[derive(Default)]
struct Outputs {
    json_events: Vec<(SourceId, String)>,
    text_events: Vec<(SourceId, String)>,
    summaries: Vec<(SourceId, String)>,
}

impl Outputs {
    fn add_events(&mut self, source: &Source, outputs: impl IntoIterator<Item = String>) {
        let tagged = outputs.into_iter().map(|o| (source.id.clone(), o));
        match source.format {
            SourceFormat::Json => self.json_events.extend(tagged),
            SourceFormat::Text { .. } => self.text_events.extend(tagged),
        }
    }

    /// The inputs of destination `name` given its `sluice_formats` and `sluice_sources` (all
    /// outputs of all sources when absent).
    fn select(
        &self,
        name: &str,
        formats: Option<&Value>,
        only: Option<&BTreeSet<SourceId>>,
        records: Records,
        sources: &[LiveSource<'_>],
    ) -> Result<Vec<String>, VectorError> {
        let wanted = |outputs: &[(SourceId, String)], summaries: bool| -> Vec<String> {
            if (summaries && !records.summaries) || (!summaries && !records.events) {
                return Vec::new();
            }
            outputs
                .iter()
                .filter(|(source, _)| only.is_none_or(|o| o.contains(source)))
                .map(|(_, output)| output.clone())
                .collect()
        };
        let Some(formats) = formats else {
            return Ok([
                (&self.json_events, false),
                (&self.text_events, false),
                (&self.summaries, true),
            ]
            .into_iter()
            .flat_map(|(o, summaries)| wanted(o, summaries))
            .collect());
        };
        let invalid = || {
            VectorError::Config(format!(
                "destination {name}: {FORMATS_KEY} must be a list of `json` and `text`"
            ))
        };
        let mut inputs = Vec::new();
        for format in formats.as_array().ok_or_else(invalid)? {
            match format.as_str() {
                Some("json") => {
                    inputs.extend(wanted(&self.json_events, false));
                    inputs.extend(wanted(&self.summaries, true));
                }
                Some("text") => {
                    // A text codec writes Vector's `message` field, so the line must be there.
                    let elsewhere = sources.iter().find(|s| {
                        only.is_none_or(|o| o.contains(&s.source.id))
                            && matches!(&s.source.format, SourceFormat::Text { field } if field.as_str() != "message")
                    });
                    if let Some(live) = elsewhere {
                        return Err(VectorError::Config(format!(
                            "destination {name} takes text sources as raw lines, but source {} \
                             keeps its line outside `message`",
                            live.source.id
                        )));
                    }
                    inputs.extend(wanted(&self.text_events, false));
                }
                _ => return Err(invalid()),
            }
        }
        Ok(inputs)
    }
}

/// One source's intake: the operator's Vector source, the archive of every event as it arrived,
/// the optional shaping, and the sampled tap. Returns the component everything downstream
/// reads: the shaping, or the source itself.
fn add_intake(
    pipeline: &mut Pipeline,
    live: &LiveSource<'_>,
    c: &Components,
    settings: &LiveSettings<'_>,
) -> String {
    pipeline
        .sources
        .insert(c.input.clone(), live.vector.clone());
    // Everything after the archive reads the shaped events, if the source has a shape.
    let entry = match live.shape {
        Some(program) => {
            let shape = c.shape();
            pipeline.transforms.insert(
                shape.clone(),
                json!({
                    "type": "remap",
                    "inputs": [c.input],
                    "source": program,
                    // A failed shaping still forwards the event rather than losing it.
                    "drop_on_error": false,
                }),
            );
            shape
        }
        None => c.input.clone(),
    };

    let sample = format!("sluice_{}_tap_sample", c.stem);
    pipeline.transforms.insert(
        sample.clone(),
        // No `sample_rate` field: the control plane must see events exactly as the
        // pipeline does, or its templates (key sets) would never match live traffic.
        json!({
            "type": "sample",
            "inputs": [entry],
            "rate": settings.tap_rate,
            "sample_rate_key": "",
        }),
    );
    let mut tap = json!({
        "type": "http",
        "inputs": [sample],
        "uri": format!("{}/tap/{}", settings.control_plane.trim_end_matches('/'), live.source.id),
        "method": "post",
        "encoding": { "codec": "json" },
        "framing": { "method": "newline_delimited" },
        "batch": { "max_events": 500, "timeout_secs": 1 },
    });
    if let Some(token) = settings.tap_token {
        tap["auth"] = json!({ "strategy": "bearer", "token": token });
    }
    pipeline.sinks.insert(format!("sluice_{}_tap", c.stem), tap);
    pipeline.sinks.insert(
        c.archive_sink(),
        json!({
            "type": "file",
            "inputs": [c.input],
            "path": format!("{}/{}/%Y-%m-%d/%H.ndjson.gz", settings.archive_dir, live.source.id),
            "encoding": { "codec": "json" },
            "compression": "gzip",
            // `sluice search` and `sluice replay` read the hour from the path: pin it to UTC
            // whatever the operator's global `timezone` is.
            "timezone": "UTC",
        }),
    );

    entry
}
/// One destination's sink: Sluice's keys removed, its inputs set from its rule profile's
/// outputs (or the unreduced sources), narrowed by its formats and sources.
fn destination(
    name: &str,
    sink: &Value,
    outputs: &BTreeMap<&str, Outputs>,
    unreduced: &Outputs,
    loaded: &[&str],
    sources: &[LiveSource<'_>],
) -> Result<Value, VectorError> {
    let profile = destination_profile(name, sink, loaded)?;
    let mut sink = sink.clone();
    let (formats, only, records) = sink.as_object_mut().map_or((None, None, None), |s| {
        s.remove(RULES_KEY);
        (
            s.remove(FORMATS_KEY),
            s.remove(SOURCES_KEY),
            s.remove(RECORDS_KEY),
        )
    });
    let only = destination_sources(name, only.as_ref(), sources)?;
    let records = Records::of(name, records.as_ref())?;
    let feeds = outputs.get(profile.as_str()).unwrap_or(unreduced);
    sink["inputs"] =
        json!(feeds.select(name, formats.as_ref(), only.as_ref(), records, sources)?);
    azure_batch_limit(name, &mut sink)?;
    Ok(sink)
}

/// Keeps an `azure_logs_ingestion` sink's batches below what Azure accepts: one without a limit
/// gets [`AZURE_MAX_BATCH_BYTES`], one above 1 MB is refused. Vector's default is larger, and a
/// refused batch is dropped, so a burst would never reach the SIEM.
fn azure_batch_limit(name: &str, sink: &mut Value) -> Result<(), VectorError> {
    if sink["type"] != "azure_logs_ingestion" {
        return Ok(());
    }
    if !(sink["batch"].is_null() || sink["batch"].is_object()) {
        return Err(VectorError::Config(format!(
            "destination {name}: batch must be a map"
        )));
    }
    match &sink["batch"]["max_bytes"] {
        Value::Null => {
            sink["batch"]["max_bytes"] = json!(AZURE_MAX_BATCH_BYTES);
            Ok(())
        }
        limit if limit.as_u64().is_some_and(|n| n <= AZURE_MAX_REQUEST_BYTES) => Ok(()),
        limit => Err(VectorError::Config(format!(
            "destination {name}: batch.max_bytes {limit} is above the {AZURE_MAX_REQUEST_BYTES} \
             bytes Azure's Logs Ingestion API accepts; Vector would drop every larger batch"
        ))),
    }
}

/// The sources a destination's `sluice_sources` names; `None` without the key.
fn destination_sources(
    name: &str,
    value: Option<&Value>,
    sources: &[LiveSource<'_>],
) -> Result<Option<BTreeSet<SourceId>>, VectorError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let invalid = || {
        VectorError::Config(format!(
            "destination {name}: {SOURCES_KEY} must be a non-empty list of configured source ids"
        ))
    };
    let ids: BTreeSet<SourceId> = value
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|id| {
            id.as_str()
                .filter(|id| sources.iter().any(|s| s.source.id.as_str() == *id))
                .map(SourceId::new)
                .ok_or_else(invalid)
        })
        .collect::<Result<_, _>>()?;
    if ids.is_empty() {
        return Err(invalid());
    }
    Ok(Some(ids))
}
#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};
    use sluice_core::logsource::LogSource;
    use sluice_core::schema::Schema;
    use sluice_core::source::{Source, SourceFormat};

    use super::*;

    #[test]
    fn tap_events_are_unchanged_and_destinations_get_every_output() {
        let source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Json,
        };
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let mut destinations = Map::new();
        destinations.insert("siem".into(), json!({"type": "blackhole"}));
        let settings = LiveSettings {
            control_plane: "http://127.0.0.1:8686",
            tap_rate: 10,
            archive_dir: "/archive",
            data_dir: "/data",
            destinations: &destinations,
            tap_token: None,
            secret_backends: &Map::new(),
        };
        let yaml = live_config(
            &[LiveSource {
                source: &source,
                vector: &vector,
                shape: None,
            }],
            &[],
            &["sigma"],
            &settings,
        )
        .unwrap();
        let config: Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            config["transforms"]["sluice_fw_tap_sample"]["sample_rate_key"],
            ""
        );
        assert_eq!(
            config["sinks"]["sluice_fw_tap"]["uri"],
            "http://127.0.0.1:8686/tap/fw"
        );
        assert_eq!(config["sinks"]["sluice_fw_archive"]["compression"], "gzip");
        assert_eq!(config["sinks"]["sluice_fw_archive"]["timezone"], "UTC");
        // Without a program, the source goes straight to the destinations.
        assert_eq!(
            config["sinks"]["siem"]["inputs"],
            json!(["sluice_fw_input"])
        );
    }

    #[test]
    fn destinations_can_take_only_json_or_only_text_sources() {
        let text = Source {
            id: "auth".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Text {
                field: "message".into(),
            },
        };
        let json_source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Json,
        };
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let destinations = crate::Target::Wazuh.destinations("wazuh", "/out/wazuh.ndjson");
        let settings = LiveSettings {
            control_plane: "http://127.0.0.1:8686",
            tap_rate: 10,
            archive_dir: "/archive",
            data_dir: "/data",
            destinations: &destinations,
            tap_token: None,
            secret_backends: &Map::new(),
        };
        let sources = [
            LiveSource {
                source: &text,
                vector: &vector,
                shape: None,
            },
            LiveSource {
                source: &json_source,
                vector: &vector,
                shape: None,
            },
        ];
        let yaml = live_config(&sources, &[], &["sigma"], &settings).unwrap();
        let config: Value = serde_yaml_ng::from_str(&yaml).unwrap();
        let sinks = &config["sinks"];
        assert_eq!(sinks["wazuh"]["inputs"], json!(["sluice_fw_input"]));
        assert_eq!(sinks["wazuh_lines"]["inputs"], json!(["sluice_auth_input"]));
        assert!(
            !yaml.contains(FORMATS_KEY),
            "Sluice's own key never reaches Vector"
        );
    }

    #[test]
    fn a_text_destination_needs_the_line_in_message() {
        let text = Source {
            id: "auth".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Text {
                field: "log".into(),
            },
        };
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let destinations = crate::Target::Wazuh.destinations("wazuh", "/out/wazuh.ndjson");
        let settings = LiveSettings {
            control_plane: "http://127.0.0.1:8686",
            tap_rate: 10,
            archive_dir: "/archive",
            data_dir: "/data",
            destinations: &destinations,
            tap_token: None,
            secret_backends: &Map::new(),
        };
        let sources = [LiveSource {
            source: &text,
            vector: &vector,
            shape: None,
        }];
        assert!(live_config(&sources, &[], &["sigma"], &settings).is_err());
    }

    #[test]
    fn each_destination_takes_only_the_sources_it_names() {
        let json_source = |id: &str| Source {
            id: id.into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Json,
        };
        let (security, events) = (
            json_source("windows-security"),
            json_source("windows-events"),
        );
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let sources = [
            LiveSource {
                source: &security,
                vector: &vector,
                shape: Some(".shaped = true"),
            },
            LiveSource {
                source: &events,
                vector: &vector,
                shape: None,
            },
        ];
        let mut destinations = Map::new();
        destinations.insert(
            "security_event".into(),
            json!({"type": "blackhole", "sluice_sources": ["windows-security"]}),
        );
        destinations.insert(
            "windows_event".into(),
            json!({"type": "blackhole", "sluice_sources": ["windows-events"]}),
        );
        destinations.insert("everything".into(), json!({"type": "blackhole"}));

        let yaml = live_config(&sources, &[], &["sigma"], &settings(&destinations)).unwrap();
        let config: Value = serde_yaml_ng::from_str(&yaml).unwrap();
        let sinks = &config["sinks"];
        // The archive keeps the original; the tap and the destinations read the shaped events.
        assert_eq!(
            sinks["security_event"]["inputs"],
            json!(["sluice_windows_security_shape"])
        );
        assert_eq!(
            sinks["sluice_windows_security_archive"]["inputs"],
            json!(["sluice_windows_security_input"])
        );
        let transforms = &config["transforms"];
        assert_eq!(
            transforms["sluice_windows_security_tap_sample"]["inputs"],
            json!(["sluice_windows_security_shape"])
        );
        assert_eq!(
            transforms["sluice_windows_security_shape"]["source"],
            ".shaped = true"
        );
        assert_eq!(
            transforms["sluice_windows_security_shape"]["drop_on_error"],
            false
        );
        assert_eq!(
            sinks["windows_event"]["inputs"],
            json!(["sluice_windows_events_input"])
        );
        assert_eq!(sinks["everything"]["inputs"].as_array().unwrap().len(), 2);
        assert!(!yaml.contains(SOURCES_KEY));

        for bad in [json!(["nope"]), json!([]), json!("windows-security")] {
            let mut destinations = Map::new();
            destinations.insert(
                "d".into(),
                json!({"type": "blackhole", "sluice_sources": bad}),
            );
            assert!(
                live_config(&sources, &[], &["sigma"], &settings(&destinations)).is_err(),
                "{bad}"
            );
        }
    }

    fn settings(destinations: &Map<String, Value>) -> LiveSettings<'_> {
        LiveSettings {
            control_plane: "http://127.0.0.1:8686",
            tap_rate: 10,
            archive_dir: "/archive",
            data_dir: "/data",
            destinations,
            tap_token: None,
            secret_backends: &EMPTY,
        }
    }

    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);

    #[test]
    fn each_destination_takes_the_profile_of_the_rules_its_siem_runs() {
        let loaded = ["sigma", "wazuh"];
        let profile = |sink: Value| destination_profile("d", &sink, &loaded);
        assert_eq!(
            profile(json!({"type": "blackhole"})).unwrap(),
            "sigma+wazuh"
        );
        assert_eq!(
            profile(json!({"sluice_rules": ["wazuh", "sigma"]})).unwrap(),
            "sigma+wazuh",
            "sorted"
        );
        assert_eq!(
            profile(json!({"sluice_rules": ["sigma"]})).unwrap(),
            "sigma"
        );
        assert!(profile(json!({"sluice_rules": []})).is_err());
        assert!(
            profile(json!({"sluice_rules": ["splunk"]})).is_err(),
            "not loaded"
        );
        assert!(profile(json!({"sluice_rules": "sigma"})).is_err());

        // A destination whose profile has no proven pipeline gets every source unreduced, and
        // Sluice's key never reaches Vector.
        let source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Json,
        };
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let mut destinations = Map::new();
        destinations.insert(
            "sentinel".into(),
            json!({"type": "blackhole", "sluice_rules": ["sigma"]}),
        );
        let settings = LiveSettings {
            control_plane: "http://127.0.0.1:8686",
            tap_rate: 10,
            archive_dir: "/archive",
            data_dir: "/data",
            destinations: &destinations,
            tap_token: None,
            secret_backends: &Map::new(),
        };
        let sources = [LiveSource {
            source: &source,
            vector: &vector,
            shape: None,
        }];
        let yaml = live_config(&sources, &[], &loaded, &settings).unwrap();
        let config: Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            config["sinks"]["sentinel"]["inputs"],
            json!(["sluice_fw_input"])
        );
        assert!(!yaml.contains(RULES_KEY));
    }

    #[test]
    fn c3_azure_batches_stay_below_what_azure_accepts() {
        let source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Json,
        };
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let sources = [LiveSource {
            source: &source,
            vector: &vector,
            shape: None,
        }];
        let render = |batch: Option<Value>| {
            let mut sink = json!({"type": "azure_logs_ingestion", "endpoint": "https://dce"});
            if let Some(batch) = batch {
                sink["batch"] = batch;
            }
            let mut destinations = Map::new();
            destinations.insert("sentinel".into(), sink);
            let settings = LiveSettings {
                control_plane: "http://127.0.0.1:8686",
                tap_rate: 10,
                archive_dir: "/archive",
                data_dir: "/data",
                destinations: &destinations,
                tap_token: None,
                secret_backends: &Map::new(),
            };
            live_config(&sources, &[], &["sigma"], &settings).map(|yaml| {
                let config: Value = serde_yaml_ng::from_str(&yaml).unwrap();
                config["sinks"]["sentinel"]["batch"].clone()
            })
        };
        assert_eq!(
            render(None).unwrap(),
            json!({"max_bytes": AZURE_MAX_BATCH_BYTES}),
            "Vector's default is larger than Azure accepts"
        );
        assert_eq!(
            render(Some(json!({"timeout_secs": 5}))).unwrap(),
            json!({"timeout_secs": 5, "max_bytes": AZURE_MAX_BATCH_BYTES})
        );
        assert_eq!(
            render(Some(json!({"max_bytes": 500_000}))).unwrap(),
            json!({"max_bytes": 500_000})
        );
        for refused in [
            json!({"max_bytes": 2_000_000}),
            json!({"max_bytes": "1MB"}),
            json!("big"),
        ] {
            assert!(render(Some(refused.clone())).is_err(), "{refused}");
        }
    }

    /// The names of every transform in a rendered configuration.
    fn transform_names(yaml: &str) -> Vec<String> {
        let config: Value = serde_yaml_ng::from_str(yaml).unwrap();
        config["transforms"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn components_carry_a_profile_tag_only_with_several_profiles_and_secrets_only_when_given() {
        let source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
            schema: Schema::default(),
            event_type: Vec::new(),
            format: SourceFormat::Json,
        };
        let vector = json!({"type": "http_server", "address": "127.0.0.1:9000"});
        let mut destinations = Map::new();
        destinations.insert("siem".into(), json!({"type": "blackhole"}));
        let program =
            crate::CompiledProgram::compile("p", "%sluice.route = \"forward\"".to_owned()).unwrap();
        let reducer = crate::VrlReducer::new([(source.id.clone(), program)].into());
        let profile = |name| LiveProfile {
            name,
            plans: &[],
            data_plane: &reducer,
        };
        let mut secrets = Map::new();
        secrets.insert(
            "siem".into(),
            json!({"type": "directory", "path": "/run/secrets/siem"}),
        );
        let settings = |secret_backends| LiveSettings {
            control_plane: "http://127.0.0.1:8686",
            tap_rate: 10,
            archive_dir: "/archive",
            data_dir: "/data",
            destinations: &destinations,
            tap_token: None,
            secret_backends,
        };
        let sources = [LiveSource {
            source: &source,
            vector: &vector,
            shape: None,
        }];
        let empty = Map::new();

        let one =
            live_config(&sources, &[profile("sigma")], &["sigma"], &settings(&empty)).unwrap();
        let names = transform_names(&one);
        assert!(names.iter().any(|n| n == "sluice_fw"), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("sigma")), "{names:?}");
        let config: Value = serde_yaml_ng::from_str(&one).unwrap();
        assert!(config.get("secret").is_none(), "no backends, no section");

        let two = live_config(
            &sources,
            &[profile("sigma"), profile("wazuh")],
            &["sigma", "wazuh"],
            &settings(&secrets),
        )
        .unwrap();
        let names = transform_names(&two);
        for tag in ["sigma", "wazuh"] {
            assert!(names.iter().any(|n| n.contains(tag)), "{tag}: {names:?}");
        }
        let config: Value = serde_yaml_ng::from_str(&two).unwrap();
        assert_eq!(config["secret"]["siem"]["type"], "directory");
    }

    #[test]
    fn a_destination_takes_the_kinds_of_record_it_names() {
        let outputs = Outputs {
            json_events: vec![("fw".into(), "fw_forward".into())],
            text_events: vec![("auth".into(), "auth_forward".into())],
            summaries: vec![("fw".into(), "fw_summaries".into())],
        };
        let select = |records: Value| {
            let records = Records::of("d", Some(&records))?;
            outputs.select("d", None, None, records, &[])
        };
        assert_eq!(
            select(json!(["events"])).unwrap(),
            ["fw_forward", "auth_forward"]
        );
        assert_eq!(select(json!(["summaries"])).unwrap(), ["fw_summaries"]);
        assert_eq!(select(json!(["summaries", "events"])).unwrap().len(), 3);
        for invalid in [json!([]), json!(["rows"]), json!("events")] {
            assert!(select(invalid.clone()).is_err(), "{invalid}");
        }
        let both = Records::of("d", None).unwrap();
        assert_eq!(outputs.select("d", None, None, both, &[]).unwrap().len(), 3);
    }
}
