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

use serde_json::{Map, Value, json};
use sluice_core::source::{Source, SourceFormat};

use crate::config::{Components, Pipeline};
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

/// Renders the live configuration.
///
/// # Errors
///
/// Returns [`VectorError::Config`] if the configuration cannot be serialized.
pub fn live_config(
    sources: &[LiveSource<'_>],
    plans: &[Plan<'_>],
    data_plane: &VrlReducer,
    settings: &LiveSettings<'_>,
) -> Result<String, VectorError> {
    let mut pipeline = Pipeline::default();
    let mut outputs = Outputs::default();
    for live in sources {
        let c = Components::for_source(&live.source.id);
        pipeline
            .sources
            .insert(c.input.clone(), live.vector.clone());

        let sample = format!("sluice_{}_tap_sample", c.stem);
        pipeline.transforms.insert(
            sample.clone(),
            // No `sample_rate` field: the control plane must see events exactly as the
            // pipeline does, or its templates (key sets) would never match live traffic.
            json!({
                "type": "sample",
                "inputs": [c.input],
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

        match data_plane.program(&live.source.id) {
            Some(program) => {
                pipeline.add_transforms(&c, &c.input, &live.source.id, program.source(), plans);
                outputs.add_events(
                    live.source,
                    [
                        format!("{}.{FORWARD}", c.split),
                        format!("{}._unmatched", c.split),
                        format!("{}.dropped", c.program),
                    ],
                );
                outputs.summaries.push(c.summaries.clone());
            }
            None => outputs.add_events(live.source, [c.input.clone()]),
        }
    }
    for (name, sink) in settings.destinations {
        let mut sink = sink.clone();
        let formats = sink.as_object_mut().and_then(|s| s.remove(FORMATS_KEY));
        sink["inputs"] = json!(outputs.select(name, formats.as_ref(), sources)?);
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

/// The component outputs that feed destinations, by kind.
#[derive(Default)]
struct Outputs {
    json_events: Vec<String>,
    text_events: Vec<String>,
    summaries: Vec<String>,
}

impl Outputs {
    fn add_events(&mut self, source: &Source, outputs: impl IntoIterator<Item = String>) {
        match source.format {
            SourceFormat::Json => self.json_events.extend(outputs),
            SourceFormat::Text { .. } => self.text_events.extend(outputs),
        }
    }

    /// The inputs of destination `name` given its `sluice_formats` (all outputs when absent).
    fn select(
        &self,
        name: &str,
        formats: Option<&Value>,
        sources: &[LiveSource<'_>],
    ) -> Result<Vec<String>, VectorError> {
        let Some(formats) = formats else {
            return Ok([&self.json_events, &self.text_events, &self.summaries]
                .into_iter()
                .flatten()
                .cloned()
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
                    inputs.extend(self.json_events.iter().cloned());
                    inputs.extend(self.summaries.iter().cloned());
                }
                Some("text") => {
                    // A text codec writes Vector's `message` field, so the line must be there.
                    let elsewhere = sources.iter().find(|s| {
                        matches!(&s.source.format, SourceFormat::Text { field } if field.as_str() != "message")
                    });
                    if let Some(live) = elsewhere {
                        return Err(VectorError::Config(format!(
                            "destination {name} takes text sources as raw lines, but source {} \
                             keeps its line outside `message`",
                            live.source.id
                        )));
                    }
                    inputs.extend(self.text_events.iter().cloned());
                }
                _ => return Err(invalid()),
            }
        }
        Ok(inputs)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};
    use sluice_core::logsource::LogSource;
    use sluice_core::source::{Source, SourceFormat};

    use super::*;

    #[test]
    fn tap_events_are_unchanged_and_destinations_get_every_output() {
        let source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
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
            }],
            &[],
            &VrlReducer::default(),
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
            format: SourceFormat::Text {
                field: "message".into(),
            },
        };
        let json_source = Source {
            id: "fw".into(),
            logsource: LogSource::default(),
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
            },
            LiveSource {
                source: &json_source,
                vector: &vector,
            },
        ];
        let yaml = live_config(&sources, &[], &VrlReducer::default(), &settings).unwrap();
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
        }];
        assert!(live_config(&sources, &[], &VrlReducer::default(), &settings).is_err());
    }
}
