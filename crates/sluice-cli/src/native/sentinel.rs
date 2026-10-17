//! `sluice analyze --sentinel-native`: the plan's field removals as a DCR transformation per
//! Sentinel source (ADR 0013), proven in the Kusto emulator with Microsoft's rules.
//!
//! What is written is one data collection rule: each proven transformation in its table's data
//! flow, and next to it a flow of the same stream, untransformed, into an archive table of the
//! low-cost Auxiliary plan, so every record is kept whole (contract rule 2).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use sluice_autopilot::{Analysis, Input};
use sluice_core::event::Event;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_kql::{
    MAX_TRANSFORM_KQL, SLUICE_PART, SLUICE_PART_END, Table, TransformPlan, Transformation,
    disallowed_functions, run_transformations, transformation, transformation_on,
};

use super::{is_empty, list, megabytes, saved, size};

/// Proves a transformation for each `SOURCE=TABLE` in `specs`, and writes those that remove
/// something into `dcr`, the data collection rule the records go through.
pub(crate) fn sentinel(
    analysis: &Analysis,
    input: Input<'_>,
    url: &str,
    specs: &[String],
    dcr: Option<&Path>,
    out: &Path,
) -> Result<()> {
    let rule: Option<Value> = dcr
        .map(|path| -> Result<Value> {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("{}: not JSON", path.display()))
        })
        .transpose()?;
    let mut proven = Vec::new();
    for spec in specs {
        let (source, table) = crate::input::sentinel_table(spec, input.events)?;
        let flow = Flow::of(rule.as_ref(), &table)?;
        if let Some(one) = prove(analysis, input, url, source.as_str(), table, &flow)?
            && !one.generated.columns.is_empty()
        {
            proven.push((one, flow));
        }
    }
    if proven.is_empty() {
        return Ok(());
    }
    let Some(rule) = rule else {
        println!(
            "  native  proven, not written: give the data collection rule the records go through \
             (--sentinel-dcr RULE.json), and Sluice writes it with the transformation and an \
             untransformed flow into an archive table (ADR 0013, contract rule 2)"
        );
        return Ok(());
    };
    write(rule, &proven, &out.join("sentinel"))
}

/// What a data flow into a table gives the transformation: the stream's columns, and the
/// transformation the flow already has, which Sluice's runs after.
struct Flow {
    /// Name and type of each column, as the stream declares it.
    stream: Vec<(String, String)>,
    before: String,
    /// Sluice's part runs before the flow's own transformation, on the stream's names: a
    /// custom table's flow renames fields that are no valid column names, and Vector removes
    /// fields before the flow sees them too.
    first: bool,
    /// The stream's name, when the records go through a rule of their own.
    name: Option<String>,
}

impl Flow {
    fn of(rule: Option<&Value>, table: &Table) -> Result<Self> {
        let Some(rule) = rule else {
            return Ok(Self {
                stream: table
                    .stream_columns()
                    .into_iter()
                    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
                    .collect(),
                before: "source".to_owned(),
                name: None,
                first: matches!(table, Table::Custom(_)),
            });
        };
        let output = table.output_stream();
        let properties = &rule["properties"];
        let flow = properties["dataFlows"]
            .as_array()
            .and_then(|flows| flows.iter().find(|f| f["outputStream"] == output.as_str()))
            .with_context(|| format!("the data collection rule has no data flow into {output}"))?;
        let name = flow["streams"][0]
            .as_str()
            .context("the data flow names no stream")?;
        let stream: Vec<(String, String)> = properties["streamDeclarations"][name]["columns"]
            .as_array()
            .with_context(|| format!("the data collection rule does not declare {name}"))?
            .iter()
            .filter_map(|c| {
                Some((
                    c["name"].as_str()?.to_owned(),
                    c["type"].as_str()?.to_owned(),
                ))
            })
            .collect();
        let before = flow["transformKql"].as_str().unwrap_or("source").trim();
        // A rule Sluice wrote before: its own part goes, so a new one replaces it.
        let before = without_sluice_part(before);
        let before = before.as_str();
        if !before.starts_with("source") {
            bail!(
                "the data flow into {output} has a transformation that does not start with `source`"
            );
        }
        Ok(Self {
            stream,
            before: before.to_owned(),
            name: Some(name.to_owned()),
            first: matches!(table, Table::Custom(_)),
        })
    }

    /// The flow's transformation and `kql` (both start with `source`), in the order they run.
    fn then(&self, kql: &str) -> String {
        if kql == "source" {
            return self.before.clone();
        }
        if self.first {
            format!("{kql}{}", &self.before["source".len()..])
        } else {
            format!("{}{}", self.before, &kql["source".len()..])
        }
    }

    fn declared(&self) -> Vec<(&str, &str)> {
        self.stream
            .iter()
            .map(|(name, kind)| (name.as_str(), kind.as_str()))
            .collect()
    }
}

/// `kql` without the part Sluice wrote into it before: from [`SLUICE_PART`] to the end of
/// [`SLUICE_PART_END`] when the flow's own part follows it, else to the end.
fn without_sluice_part(kql: &str) -> String {
    let Some(at) = kql.find(SLUICE_PART) else {
        return kql.to_owned();
    };
    let head = kql[..at].trim_end();
    match kql[at..].find(SLUICE_PART_END) {
        Some(end) => format!(
            "{head} {}",
            kql[at + end + SLUICE_PART_END.len()..].trim_start()
        )
        .trim_end()
        .to_owned(),
        None => head.to_owned(),
    }
}

/// The archive table of `table`: `Sluice<Table>Archive_CL`, a custom table's name without its
/// `_CL`.
fn archive(table: &Table) -> String {
    let name = table.name();
    format!(
        "Sluice{}Archive_CL",
        name.strip_suffix("_CL").unwrap_or(name)
    )
}

/// A proven transformation.
struct Proven {
    source: String,
    table: Table,
    generated: Transformation,
    /// The whole `transformKql`, the flow's own transformation first.
    kql: String,
}

/// Generates and proves the transformation for `source`; `None` (with the reason printed) when
/// it cannot be generated or would not fit a rule.
fn prove(
    analysis: &Analysis,
    input: Input<'_>,
    url: &str,
    source: &str,
    table: Table,
    flow: &Flow,
) -> Result<Option<Proven>> {
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
        return Ok(None);
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
    let generated = if flow.first {
        transformation_on(table.name(), &flow.declared(), &stream, &plans)
    } else {
        transformation(&table, &stream, &plans)
    };
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
        return Ok(None);
    }
    let declared = flow.declared();
    // Both in one query: the flow's own transformation may read the clock (`now()`).
    // Sluice's part alone too, where it runs first: there the columns have the stream's names.
    let mut kqls = vec![flow.before.as_str(), kql.as_str()];
    if flow.first {
        kqls.push(&generated.kql);
    }
    let mut runs = run_transformations(url, &declared, &kqls, &events)
        .with_context(|| format!("{source}: running the transformation in the emulator"))?;
    let alone = if flow.first { runs.pop() } else { None };
    let (Some(after), Some(untouched)) = (runs.pop(), runs.pop()) else {
        bail!("{source}: the emulator returned no records");
    };
    let named_as_stream = alone.as_ref().unwrap_or(&after);
    let violations = beyond_vector(analysis, &events, named_as_stream, &generated.columns)?;
    if let Some(first) = violations.first() {
        bail!(
            "{source}: the transformation empties {} column(s) the proven data plane keeps, \
             first {first}; nothing was written",
            violations.len()
        );
    }
    // The rules on the records as the table gets them, without Sluice's part and with it.
    let stored: Vec<Event> = events
        .iter()
        .zip(&untouched)
        .map(|(event, record)| Event {
            fields: record.clone(),
            ..(*event).clone()
        })
        .collect();
    let stored: Vec<&Event> = stored.iter().collect();
    let alerts = input
        .sentinel
        .and_then(|s| s.engine)
        .map(|engine| super::same_alerts(engine, source, &stored, &after))
        .transpose()?;
    let proven = Proven {
        source: source.to_owned(),
        table,
        generated,
        kql,
    };
    summary(&proven, &untouched, &after, alerts);
    Ok(Some(proven))
}

fn summary(
    proven: &Proven,
    untouched: &[Map<String, Value>],
    after: &[Map<String, Value>],
    alerts: Option<usize>,
) {
    let before: usize = untouched.iter().map(size).sum();
    let kept: usize = after.iter().map(size).sum();
    let generated = &proven.generated;
    println!(
        "  native  {} → {}: {} kinds of event, columns {}; {} → {} ({}), every emptied column \
         also removed by Vector{}",
        proven.source,
        proven.table.name(),
        generated.templates.len(),
        list(&generated.columns),
        megabytes(before),
        megabytes(kept),
        saved(before, kept),
        alerts.map_or_else(
            || " (no Sentinel rules to prove alerts on)".to_owned(),
            |n| format!(", {n} = {n} alerts")
        ),
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
}

/// Writes `rule` with every proven transformation in its table's data flow and an archive flow
/// next to each, the archive tables' definitions, and the transformations themselves.
fn write(rule: Value, proven: &[(Proven, Flow)], dir: &Path) -> Result<()> {
    let rule = deployment(rule, proven)?;
    for (one, flow) in proven {
        crate::output::write(
            &dir.join(format!("{}.table.json", archive(&one.table))),
            &(serde_json::to_string_pretty(&archive_table(&one.table, flow))? + "\n"),
        )?;
        crate::output::write(
            &dir.join(format!("{}.transform.kql", one.source)),
            &(one.kql.clone() + "\n"),
        )?;
    }
    let path = dir.join("dcr.json");
    crate::output::write(&path, &(serde_json::to_string_pretty(&rule)? + "\n"))?;
    let tables: Vec<String> = proven.iter().map(|(one, _)| archive(&one.table)).collect();
    println!(
        "  native  wrote {}: first create {} from the .table.json next to it (Auxiliary plan, \
         every record kept whole), then update the rule with it",
        path.display(),
        tables.join(", ")
    );
    Ok(())
}

/// `rule` as it can be put back: each proven transformation in its table's data flow, and one
/// untransformed flow of the same stream into the table's archive.
fn deployment(mut rule: Value, proven: &[(Proven, Flow)]) -> Result<Value> {
    if let Some(object) = rule.as_object_mut() {
        for key in ["id", "name", "type", "etag", "systemData"] {
            object.remove(key);
        }
    }
    if let Some(properties) = rule["properties"].as_object_mut() {
        for key in ["immutableId", "endpoints", "provisioningState"] {
            properties.remove(key);
        }
    }
    let flows = rule["properties"]["dataFlows"]
        .as_array_mut()
        .context("the data collection rule has no data flows")?;
    for (one, flow) in proven {
        let output = one.table.output_stream();
        let archived = format!("Custom-{}", archive(&one.table));
        let destinations = flows
            .iter()
            .find(|f| f["outputStream"] == output.as_str())
            .map(|f| f["destinations"].clone())
            .with_context(|| format!("the data collection rule has no data flow into {output}"))?;
        flows.retain(|f| f["outputStream"] != archived.as_str());
        for f in flows.iter_mut() {
            if f["outputStream"] == output.as_str() {
                f["transformKql"] = Value::String(one.kql.clone());
            }
        }
        flows.push(json!({
            "streams": [flow.name],
            "destinations": destinations,
            "transformKql": "source",
            "outputStream": archived,
        }));
    }
    Ok(rule)
}

/// The archive table for the tables API: the stream's columns, on the Auxiliary plan.
fn archive_table(table: &Table, flow: &Flow) -> Value {
    let mut columns: Vec<Value> = flow
        .stream
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    if !flow.stream.iter().any(|(name, _)| name == "TimeGenerated") {
        columns.insert(0, json!({ "name": "TimeGenerated", "type": "datetime" }));
    }
    json!({
        "properties": {
            "plan": "Auxiliary",
            "totalRetentionInDays": 365,
            "schema": { "name": archive(table), "columns": columns },
        }
    })
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

#[cfg(test)]
mod tests;
