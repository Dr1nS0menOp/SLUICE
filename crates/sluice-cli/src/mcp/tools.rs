//! The tools `sluice mcp` offers. Each reads the analysis, or proves a draft on the sample in the
//! engines the server was started with; none writes, deploys or reaches anything else.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::event::Event;
use sluice_mcp::Tool;

use super::{Advice, MAX_READ, Proving};

#[cfg(test)]
mod tests;

/// The largest kinds of event per source `summary` names.
const LARGEST: usize = 5;

/// The tools, over one analysis and, if given, a sample to prove on.
pub(crate) struct Sluice {
    pub(crate) advice: Advice,
    pub(crate) proving: Option<Proving>,
}

impl sluice_mcp::Tools for Sluice {
    fn list(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "summary",
                title: "Summary of the advice",
                description: "What the analysis proved: the saving in total and per kind of \
                    saving, the proof (alerts on full and on forwarded data), the problems by \
                    kind, and per source its saving and its largest savings. Call it first.",
                input_schema: schema(&[], &[]),
            },
            Tool {
                name: "source_plan",
                title: "The plan of a source",
                description: "The savings plan of one source as plan.json has it: per kind of \
                    event how it is recognised, what may be removed, which implied values, which \
                    events keep every field, what may be counted, where it can run and why. \
                    With `template`, only that kind of event.",
                input_schema: schema(
                    &[
                        ("source", "The source's id, as `summary` lists it."),
                        ("template", "A kind of event's id, to give only that one."),
                    ],
                    &["source"],
                ),
            },
            Tool {
                name: "problems",
                title: "Problems reading the rules",
                description: "What Sluice could not read or check in the rules and recipes, and \
                    per kind what it costs and what the user can do. Each was read as broadly as \
                    it could reach: it costs savings, never a detection. With `kind`, only that \
                    kind.",
                input_schema: schema(
                    &[(
                        "kind",
                        "unreadable, unknown_function, read_broadly, unchecked, shared_id, \
                         missing_rule, left_out or recipe.",
                    )],
                    &[],
                ),
            },
            Tool {
                name: "files",
                title: "Files the analysis wrote",
                description: "The configurations and files the analysis wrote (vector.yaml, \
                    sentinel/, elastic/, fluent-bit/, otel/, plan.json), with their sizes.",
                input_schema: schema(&[], &[]),
            },
            Tool {
                name: "read_file",
                title: "Read a file the analysis wrote",
                description: "The text of one file `files` lists, up to 1 MB.",
                input_schema: schema(&[("path", "The path as `files` gives it.")], &["path"]),
            },
            Tool {
                name: "prove_vector",
                title: "Prove a Vector configuration",
                description: "Proves a Vector configuration on the sample, as `sluice prove` \
                    does: Sluice's layout of vector.yaml, with its programs as generated or as \
                    you changed them. `holds` is true only when the rules raise exactly the same \
                    alerts on what it forwards as on the full sample. Needs the server started \
                    with --input, --sources and rules.",
                input_schema: schema(
                    &[("config", "The whole configuration, as YAML.")],
                    &["config"],
                ),
            },
            Tool {
                name: "prove_transform_kql",
                title: "Prove a data collection rule transformation",
                description: "Runs a transformKql on a source's sample records in the Kusto \
                    emulator, as a data collection rule would on its way into the source's \
                    Sentinel table, and checks it: at most 15,360 characters, no record \
                    dropped, and the Sentinel rules raise the same alerts on what it leaves. \
                    Gives the bytes before and after, the columns it empties, and the functions \
                    it calls beyond those Sluice's own transformations use \
                    (unverified_functions: check them against Microsoft's list of what a \
                    transformation supports). Needs the server started with --kusto, --sentinel-rules and \
                    --sentinel-table.",
                input_schema: schema(
                    &[
                        ("source", "A source named in --sentinel-table."),
                        ("kql", "The transformation, starting with `source`."),
                    ],
                    &["source", "kql"],
                ),
            },
        ]
    }

    fn call(&mut self, name: &str, arguments: &Map<String, Value>) -> Result<Value, String> {
        match name {
            "summary" => Ok(summary(&self.advice, self.proving.as_ref())),
            "source_plan" => source_plan(
                &self.advice.plan,
                text(arguments, "source")?,
                optional(arguments, "template")?,
            ),
            "problems" => Ok(problems(&self.advice.plan, optional(arguments, "kind")?)),
            "files" => Ok(json!({ "files": self.advice.files.iter()
                .map(|(path, bytes)| json!({ "path": path, "bytes": bytes }))
                .collect::<Vec<_>>() })),
            "read_file" => read_file(&self.advice, text(arguments, "path")?),
            "prove_vector" => prove_vector(self.proving.as_ref(), text(arguments, "config")?),
            "prove_transform_kql" => prove_transform_kql(
                self.proving.as_ref(),
                text(arguments, "source")?,
                text(arguments, "kql")?,
            ),
            other => Err(format!("no tool {other}")),
        }
    }
}

/// An object schema with string `properties` (name and description), of which `required` must
/// be given, and nothing else.
fn schema(properties: &[(&str, &str)], required: &[&str]) -> Value {
    let properties: Map<String, Value> = properties
        .iter()
        .map(|(name, description)| {
            (
                (*name).to_owned(),
                json!({ "type": "string", "description": description }),
            )
        })
        .collect();
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn text<'a>(arguments: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    optional(arguments, name)?.ok_or_else(|| format!("`{name}` is required"))
}

fn optional<'a>(arguments: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, String> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(format!("`{name}` must be a string")),
    }
}

/// `part` of `whole` as a percentage with one decimal; 0 for an empty whole.
#[allow(
    clippy::cast_precision_loss,
    reason = "a percentage for people, of byte counts far below 2^52"
)]
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 * 1000.0 / whole as f64).round() / 10.0
}

fn bytes(volume: &Value, key: &str) -> u64 {
    volume[key].as_u64().unwrap_or_default()
}

/// The plan in brief: the saving, the proof, the problems by kind, and per source its saving
/// and its largest savings.
fn summary(advice: &Advice, proving: Option<&Proving>) -> Value {
    let plan = &advice.plan;
    let (bytes_in, bytes_out) = (
        bytes(&plan["total"], "bytes_in"),
        bytes(&plan["total"], "bytes_out"),
    );
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for problem in plan["problems"].as_array().into_iter().flatten() {
        *by_kind
            .entry(problem["kind"].as_str().unwrap_or("?"))
            .or_default() += 1;
    }
    let sources: Vec<Value> = plan["sources"]
        .as_array()
        .into_iter()
        .flatten()
        .map(source_summary)
        .collect();
    json!({
        "directory": advice.dir.display().to_string(),
        "proof": plan["proof"],
        "total": plan["total"],
        "saved_percent": percent(bytes_in.saturating_sub(bytes_out), bytes_in),
        "saved_by_mode": plan["saved_by_mode"],
        "problems": by_kind,
        "sources": sources,
        "proving": proving.map(|p| json!({
            "events": p.events.len(),
            "sigma": p.sigma.is_some(),
            "sentinel_tables": p.sentinel.as_ref().map(|k| k.specs.clone()).unwrap_or_default(),
        })),
    })
}

fn source_summary(source: &Value) -> Value {
    let templates = source["templates"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let total = |key: &str| -> u64 { templates.iter().map(|t| bytes(&t["volume"], key)).sum() };
    let (bytes_in, bytes_out) = (total("bytes_in"), total("bytes_out"));
    let mut largest: Vec<(u64, &Value)> = templates
        .iter()
        .map(|t| {
            let saved =
                bytes(&t["volume"], "bytes_in").saturating_sub(bytes(&t["volume"], "bytes_out"));
            (saved, t)
        })
        .filter(|(saved, _)| *saved > 0)
        .collect();
    largest.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1["id"].as_str().cmp(&b.1["id"].as_str()))
    });
    json!({
        "id": source["id"],
        "logsource": source["logsource"],
        "schema": source["schema"],
        "kinds_of_event": templates.len(),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "saved_percent": percent(bytes_in.saturating_sub(bytes_out), bytes_in),
        "largest_savings": largest.iter().take(LARGEST).map(|(saved, t)| json!({
            "template": t["id"],
            "pattern": t["pattern"].as_str().map(|p| p.chars().take(160).collect::<String>()),
            "saved_bytes": saved,
            "runs_in": t["runs_in"],
        })).collect::<Vec<_>>(),
    })
}

fn source_plan(plan: &Value, source: &str, template: Option<&str>) -> Result<Value, String> {
    let sources = plan["sources"].as_array().map_or(&[][..], Vec::as_slice);
    let Some(found) = sources.iter().find(|s| s["id"] == source) else {
        let ids: Vec<&str> = sources.iter().filter_map(|s| s["id"].as_str()).collect();
        return Err(format!(
            "no source {source}; the plan has {}",
            ids.join(", ")
        ));
    };
    let Some(template) = template else {
        return Ok(found.clone());
    };
    found["templates"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|t| t["id"] == template)
        .cloned()
        .ok_or_else(|| format!("{source} has no kind of event {template}"))
}

fn problems(plan: &Value, kind: Option<&str>) -> Value {
    let listed: Vec<&Value> = plan["problems"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| kind.is_none_or(|kind| p["kind"] == kind))
        .collect();
    let advice: BTreeMap<&str, &str> = listed
        .iter()
        .filter_map(|p| p["kind"].as_str())
        .filter_map(|kind| Some((kind, sluice_autopilot::problem_advice(kind)?)))
        .collect();
    json!({ "problems": listed, "advice": advice })
}

fn read_file(advice: &Advice, path: &str) -> Result<Value, String> {
    let Some((path, size)) = advice.files.iter().find(|(listed, _)| listed == path) else {
        return Err(format!("{path} is not one of the files `files` lists"));
    };
    if *size > MAX_READ {
        return Err(format!(
            "{path} has {size} bytes, more than the {MAX_READ} read_file gives"
        ));
    }
    let text = std::fs::read_to_string(advice.dir.join(path))
        .map_err(|e| format!("reading {path}: {e}"))?;
    Ok(json!({ "path": path, "text": text }))
}

fn proving(proving: Option<&Proving>) -> Result<&Proving, String> {
    proving.ok_or_else(|| {
        "the server has no sample to prove on: start `sluice mcp` with --input and --sources, \
         and --rules or --sentinel-rules with --kusto"
            .to_owned()
    })
}

fn prove_vector(proving: Option<&Proving>, config: &str) -> Result<Value, String> {
    let proving = self::proving(proving)?;
    let mut engines: Vec<&dyn RuleEngine> = Vec::new();
    engines.extend(proving.sigma.as_ref().map(|e| e as &dyn RuleEngine));
    engines.extend(
        proving
            .sentinel
            .as_ref()
            .map(|k| &k.engine as &dyn RuleEngine),
    );
    let (proof, unreduced) =
        crate::prove::proof_of(config, &proving.sources, &proving.events, &Engines(engines))
            .map_err(|e| format!("{e:#}"))?;
    Ok(crate::prove::summary(&proof, &unreduced))
}

/// The first records whose events are named, at most this many.
const NAMED: usize = 10;

fn prove_transform_kql(
    proving: Option<&Proving>,
    source: &str,
    kql: &str,
) -> Result<Value, String> {
    let proving = self::proving(proving)?;
    let Some(kusto) = &proving.sentinel else {
        return Err(
            "the server has no Kusto emulator: start it with --kusto, --sentinel-rules \
                    and --sentinel-table"
                .to_owned(),
        );
    };
    let Some(spec) = kusto.specs.iter().find(|spec| {
        spec.split_once('=')
            .is_some_and(|(s, _)| s.trim() == source)
    }) else {
        return Err(format!("{source} is not named in --sentinel-table"));
    };
    let (_, table) =
        crate::engines::sentinel_table(spec, &proving.events).map_err(|e| format!("{e:#}"))?;
    let refused = refusals(kql);
    if !refused.is_empty() {
        return Ok(json!({
            "holds": false, "source": source, "table": table.name(), "refused": refused,
        }));
    }
    let events: Vec<&Event> = proving
        .events
        .iter()
        .filter(|e| e.source.as_str() == source)
        .collect();
    let runs = Runs::of(kusto, &table.stream_columns(), kql, &events)?;
    let full = kusto
        .engine
        .alerts(&runs.stored)
        .map_err(|e| format!("Sentinel rules on the records as stored: {e}"))?;
    let reduced = kusto
        .engine
        .alerts(&runs.transformed)
        .map_err(|e| format!("Sentinel rules on the transformed records: {e}"))?;
    let (before, after) = (
        records_bytes(&runs.stored),
        records_bytes(&runs.transformed),
    );
    Ok(json!({
        "holds": runs.dropped.is_empty() && full == reduced,
        "source": source,
        "table": table.name(),
        "records": events.len(),
        "dropped": runs.dropped.len(),
        "dropped_events": runs.dropped.iter().take(NAMED).collect::<Vec<_>>(),
        "alerts_full": full.len(),
        "alerts_after": reduced.len(),
        "missing_alerts": full.difference(&reduced).count(),
        "extra_alerts": reduced.difference(&full).count(),
        "bytes_before": before,
        "bytes_after": after,
        "saved_percent": percent(before.saturating_sub(after), before),
        "emptied_columns": runs.emptied,
        // Sluice's own transformations keep to a few functions it has seen Azure accept; others
        // may be fine, and Azure refuses one it does not support when the rule is deployed.
        "unverified_functions": sluice_kql::disallowed_functions(kql),
        "note": full.is_empty().then_some(sluice_autopilot::EMPTY_PROOF),
    }))
}

/// Why a data collection rule would refuse `kql`, before the emulator is asked.
fn refusals(kql: &str) -> Vec<String> {
    let mut refused = Vec::new();
    if kql.len() > sluice_kql::MAX_TRANSFORM_KQL {
        refused.push(format!(
            "{} characters, more than the {} a data collection rule takes",
            kql.len(),
            sluice_kql::MAX_TRANSFORM_KQL
        ));
    }
    if !kql.trim_start().starts_with("source") {
        refused.push("does not start with `source`".to_owned());
    }
    refused
}

/// A transformation run on a source's records in the emulator, next to the records as stored.
struct Runs {
    /// Each event, with its record as the table stores it without the transformation: what the
    /// rules are compared against, so a record the transformation drops counts too.
    stored: Vec<Event>,
    /// Each event the transformation keeps, with its record as the transformation leaves it.
    transformed: Vec<Event>,
    /// Events the transformation drops.
    dropped: Vec<String>,
    /// Each column the transformation empties, with the records it empties it on.
    emptied: BTreeMap<String, usize>,
}

impl Runs {
    fn of(
        kusto: &super::Kusto,
        columns: &[(&str, &str)],
        kql: &str,
        events: &[&Event],
    ) -> Result<Self, String> {
        let mut runs =
            sluice_kql::run_transformations(&kusto.url, columns, &["source", kql], events)
                .map_err(|e| format!("the emulator: {e}"))?;
        let (Some(after), Some(before)) = (runs.pop(), runs.pop()) else {
            return Err("the emulator returned no records".to_owned());
        };
        let mut found = Self {
            stored: Vec::new(),
            transformed: Vec::new(),
            dropped: Vec::new(),
            emptied: BTreeMap::new(),
        };
        for ((event, before), after) in events.iter().zip(before).zip(after) {
            // The table never gets a record the stream's own shape drops.
            let Some(before) = before else { continue };
            match after {
                Some(after) => {
                    for column in before.keys().filter(|c| !after.contains_key(*c)) {
                        *found.emptied.entry(column.clone()).or_default() += 1;
                    }
                    found.transformed.push(Event {
                        fields: after,
                        ..(*event).clone()
                    });
                }
                None => found.dropped.push(event.id.to_string()),
            }
            found.stored.push(Event {
                fields: before,
                ..(*event).clone()
            });
        }
        Ok(found)
    }
}

fn records_bytes(events: &[Event]) -> u64 {
    events
        .iter()
        .map(|e| serde_json::to_string(&e.fields).map_or(0, |s| s.len() as u64))
        .sum()
}
