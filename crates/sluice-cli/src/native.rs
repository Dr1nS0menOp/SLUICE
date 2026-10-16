//! `sluice analyze --sentinel-native`: the plan's field removals as a DCR transformation per
//! Sentinel source (ADR 0013), proven in the Kusto emulator before it is written as proven.
//!
//! The proof has two parts, both on the sample:
//! 1. **Never more than Vector.** Every column the transformation empties on a record is one the
//!    proven data plane removes from it too (or the data plane counts the event instead).
//! 2. **The same detections.** Microsoft's rules in the emulator raise the same alerts on the
//!    transformed records as on the full ones.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::event::Event;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_kql::{
    MAX_TRANSFORM_KQL, Table, TransformPlan, disallowed_functions, run_transformation,
    transformation,
};

/// Writes and proves a transformation for each `SOURCE=TABLE` in `specs`. `dcr` is the data
/// collection rule the records go through, if it has a stream of its own.
pub(crate) fn sentinel(
    analysis: &Analysis,
    input: Input<'_>,
    url: &str,
    specs: &[String],
    dcr: Option<&Path>,
    out: &Path,
) -> Result<()> {
    let dcr: Option<Value> = dcr
        .map(|path| -> Result<Value> {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("{}: not JSON", path.display()))
        })
        .transpose()?;
    for spec in specs {
        let (source, table) = spec
            .split_once('=')
            .with_context(|| format!("--sentinel-table {spec}: expected SOURCE=TABLE"))?;
        let table = Table::from_name(table.trim())
            .with_context(|| format!("--sentinel-table {spec}: unknown table"))?;
        let flow = Flow::of(dcr.as_ref(), table)?;
        one(analysis, input, url, source.trim(), table, &flow, out)?;
    }
    Ok(())
}

/// What a data flow into `table` gives the transformation: the stream's columns, and the
/// transformation the flow already has, which Sluice's runs after.
struct Flow {
    /// Name and type of each column, as the stream declares it.
    stream: Vec<(String, String)>,
    before: String,
}

impl Flow {
    fn of(dcr: Option<&Value>, table: Table) -> Result<Self> {
        let Some(dcr) = dcr else {
            return Ok(Self {
                stream: table
                    .column_types()
                    .into_iter()
                    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
                    .collect(),
                before: "source".to_owned(),
            });
        };
        let output = format!("Microsoft-{}", table.name());
        let properties = &dcr["properties"];
        let flow = properties["dataFlows"]
            .as_array()
            .and_then(|flows| flows.iter().find(|f| f["outputStream"] == output.as_str()))
            .with_context(|| format!("the data collection rule has no data flow into {output}"))?;
        let stream = flow["streams"][0]
            .as_str()
            .context("the data flow names no stream")?;
        let stream: Vec<(String, String)> = properties["streamDeclarations"][stream]["columns"]
            .as_array()
            .with_context(|| format!("the data collection rule does not declare {stream}"))?
            .iter()
            .filter_map(|c| {
                Some((
                    c["name"].as_str()?.to_owned(),
                    c["type"].as_str()?.to_owned(),
                ))
            })
            .collect();
        let before = flow["transformKql"]
            .as_str()
            .unwrap_or("source")
            .trim()
            .to_owned();
        if !before.starts_with("source") {
            bail!(
                "the data flow into {output} has a transformation that does not start with `source`"
            );
        }
        Ok(Self { stream, before })
    }

    /// The flow's transformation followed by `kql` (which starts with `source`).
    fn then(&self, kql: &str) -> String {
        if kql == "source" {
            return self.before.clone();
        }
        format!("{}{}", self.before, &kql["source".len()..])
    }
}

fn one(
    analysis: &Analysis,
    input: Input<'_>,
    url: &str,
    source: &str,
    table: Table,
    flow: &Flow,
    out: &Path,
) -> Result<()> {
    let events: Vec<&Event> = input
        .events
        .iter()
        .filter(|e| e.source.as_str() == source)
        .collect();
    if let Some(event) = events.iter().find(|e| e.fields.values().any(is_empty)) {
        println!(
            "  native  {source}: not generated: event {} has an empty field, so its kinds of event \
             were not discovered on records as {} stores them (where empty and missing are the \
             same). Read the sample from the workspace (scripts/real-data/collect-sentinel.sh).",
            event.id,
            table.name()
        );
        return Ok(());
    }
    let plans: Vec<TransformPlan<'_>> = analysis
        .discovery
        .templates
        .iter()
        .zip(&analysis.selection.recipes)
        .filter(|(template, _)| template.source.as_str() == source)
        .map(|(template, recipe)| TransformPlan { template, recipe })
        .collect();
    let stream: Vec<&str> = flow.stream.iter().map(|(name, _)| name.as_str()).collect();
    let declared: Vec<(&str, &str)> = flow
        .stream
        .iter()
        .map(|(name, kind)| (name.as_str(), kind.as_str()))
        .collect();
    let generated = transformation(table, &stream, &plans);
    let unsupported = disallowed_functions(&generated.kql);
    if !unsupported.is_empty() {
        bail!(
            "{source}: the transformation calls {unsupported:?}, which DCRs refuse (a Sluice bug)"
        );
    }
    let kql = flow.then(&generated.kql);
    if kql.len() > MAX_TRANSFORM_KQL {
        println!(
            "  native  {source}: not written: with the data flow's own transformation it would be \
             {} characters, more than the {MAX_TRANSFORM_KQL} a data collection rule takes",
            kql.len()
        );
        return Ok(());
    }

    let after = run_transformation(url, &declared, &kql, &events)
        .with_context(|| format!("{source}: running the transformation in the emulator"))?;
    let violations = beyond_vector(analysis, &events, &after, &generated.columns)?;
    if let Some(first) = violations.first() {
        bail!(
            "{source}: the transformation empties {} column(s) the proven data plane keeps, first {first}; \
             nothing was written",
            violations.len()
        );
    }
    let alerts = same_alerts(input, source, &events, &after)?;

    let path = out.join("sentinel").join(format!("{source}.transform.kql"));
    crate::output::write(&path, &(kql.clone() + "\n"))?;
    // Both sides as the engine holds them: typed values, table columns only.
    let untouched = run_transformation(url, &declared, &flow.before, &events)
        .with_context(|| format!("{source}: reading the records in the emulator"))?;
    let before: usize = untouched.iter().map(size).sum();
    let kept: usize = after.iter().map(size).sum();
    println!(
        "  native  {source} → {}: {} kinds of event, columns {}; {} → {} ({}), every emptied \
         column also removed by Vector{}; wrote {}",
        table.name(),
        generated.templates.len(),
        list(&generated.columns),
        megabytes(before),
        megabytes(kept),
        saved(before, kept),
        alerts.map_or_else(
            || " (no Sentinel rules to prove alerts on)".to_owned(),
            |n| format!(", {n} = {n} alerts")
        ),
        path.display()
    );
    if alerts == Some(0) {
        println!("          {}", sluice_autopilot::EMPTY_PROOF);
    }
    for reason in generated.left_out.iter().take(5) {
        println!("          left to a pipeline tool: {reason}");
    }
    if generated.left_out.len() > 5 {
        println!("          … and {} more", generated.left_out.len() - 5);
    }
    Ok(())
}

/// The alerts Microsoft's rules raise on the full records, if they raise the same on the
/// transformed ones; `None` without Sentinel rules to run.
fn same_alerts(
    input: Input<'_>,
    source: &str,
    events: &[&Event],
    after: &[Map<String, Value>],
) -> Result<Option<usize>> {
    let Some(engine) = input.sentinel.and_then(|s| s.engine) else {
        return Ok(None);
    };
    let transformed: Vec<Event> = events
        .iter()
        .zip(after)
        .map(|(event, record)| Event {
            fields: record.clone(),
            ..(*event).clone()
        })
        .collect();
    let full = engine
        .alerts_refs(events)
        .context("rules on the full records")?;
    let changed = engine
        .alerts(&transformed)
        .context("rules on the transformed records")?;
    if full != changed {
        bail!(
            "{source}: the transformation changes detections ({} alerts on full records, {} on \
             transformed ones); nothing was written",
            full.len(),
            changed.len()
        );
    }
    Ok(Some(full.len()))
}

/// Columns the transformation emptied on a record that the data plane keeps on it.
fn beyond_vector(
    analysis: &Analysis,
    events: &[&Event],
    after: &[Map<String, Value>],
    columns: &BTreeSet<String>,
) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for (event, record) in events.iter().zip(after) {
        let reduced = analysis
            .data_plane
            .reduce(event)
            .with_context(|| format!("the data plane on event {}", event.id))?;
        let Outcome::Forwarded(body) = reduced.outcome else {
            continue; // Vector counts it instead of sending it.
        };
        for column in columns {
            let emptied = event.fields.get(column).is_some_and(|v| !is_empty(v))
                && !record.contains_key(column);
            if emptied && body.contains_key(column) {
                violations.push(format!("{column} on event {}", event.id));
            }
        }
    }
    Ok(violations)
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn size(fields: &Map<String, Value>) -> usize {
    serde_json::to_string(fields).map_or(0, |s| s.len())
}

#[allow(
    clippy::cast_precision_loss,
    reason = "sample sizes stay far below 2^52 bytes"
)]
fn megabytes(bytes: usize) -> String {
    format!("{:.1} MB", bytes as f64 / 1e6)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "sample sizes stay far below 2^52 bytes"
)]
fn saved(before: usize, after: usize) -> String {
    if before == 0 {
        return "0.0% saved".to_owned();
    }
    format!(
        "{:.1}% saved",
        (before.saturating_sub(after)) as f64 * 100.0 / before as f64
    )
}

fn list(columns: &BTreeSet<String>) -> String {
    if columns.is_empty() {
        "none".to_owned()
    } else {
        columns.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}
