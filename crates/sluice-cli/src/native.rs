//! `sluice analyze --sentinel-native`: the plan's field removals as a DCR transformation per
//! Sentinel source (ADR 0013), proven in the Kusto emulator before anything is written.
//!
//! The proof has two parts, both on the sample:
//! 1. **Never more than Vector.** Every column the transformation empties on a record is one the
//!    proven data plane removes from it too (or the data plane counts the event instead).
//! 2. **The same detections.** Microsoft's rules in the emulator raise the same alerts on the
//!    transformed records as on the full ones.
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
    MAX_TRANSFORM_KQL, SLUICE_PART, Table, TransformPlan, Transformation, disallowed_functions,
    run_transformation, transformation,
};

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
        let (source, table) = spec
            .split_once('=')
            .with_context(|| format!("--sentinel-table {spec}: expected SOURCE=TABLE"))?;
        let table = Table::from_name(table.trim())
            .with_context(|| format!("--sentinel-table {spec}: unknown table"))?;
        let flow = Flow::of(rule.as_ref(), table)?;
        if let Some(one) = prove(analysis, input, url, source.trim(), table, &flow)?
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
    /// The stream's name, when the records go through a rule of their own.
    name: Option<String>,
}

impl Flow {
    fn of(rule: Option<&Value>, table: Table) -> Result<Self> {
        let Some(rule) = rule else {
            return Ok(Self {
                stream: table
                    .column_types()
                    .into_iter()
                    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
                    .collect(),
                before: "source".to_owned(),
                name: None,
            });
        };
        let output = output(table);
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
        let before = before
            .find(SLUICE_PART)
            .map_or(before, |at| before[..at].trim_end());
        if !before.starts_with("source") {
            bail!(
                "the data flow into {output} has a transformation that does not start with `source`"
            );
        }
        Ok(Self {
            stream,
            before: before.to_owned(),
            name: Some(name.to_owned()),
        })
    }

    /// The flow's transformation followed by `kql` (which starts with `source`).
    fn then(&self, kql: &str) -> String {
        if kql == "source" {
            return self.before.clone();
        }
        format!("{}{}", self.before, &kql["source".len()..])
    }

    fn declared(&self) -> Vec<(&str, &str)> {
        self.stream
            .iter()
            .map(|(name, kind)| (name.as_str(), kind.as_str()))
            .collect()
    }
}

fn output(table: Table) -> String {
    format!("Microsoft-{}", table.name())
}

fn archive(table: Table) -> String {
    format!("Sluice{}Archive_CL", table.name())
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
        return Ok(None);
    }
    let declared = flow.declared();
    let after = run_transformation(url, &declared, &kql, &events)
        .with_context(|| format!("{source}: running the transformation in the emulator"))?;
    let violations = beyond_vector(analysis, &events, &after, &generated.columns)?;
    if let Some(first) = violations.first() {
        bail!(
            "{source}: the transformation empties {} column(s) the proven data plane keeps, \
             first {first}; nothing was written",
            violations.len()
        );
    }
    let alerts = same_alerts(input, source, &events, &after)?;
    // Both sides as the engine holds them: typed values, the stream's columns only.
    let untouched = run_transformation(url, &declared, &flow.before, &events)
        .with_context(|| format!("{source}: reading the records in the emulator"))?;
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
            &dir.join(format!("{}.table.json", archive(one.table))),
            &(serde_json::to_string_pretty(&archive_table(one.table, flow))? + "\n"),
        )?;
        crate::output::write(
            &dir.join(format!("{}.transform.kql", one.source)),
            &(one.kql.clone() + "\n"),
        )?;
    }
    let path = dir.join("dcr.json");
    crate::output::write(&path, &(serde_json::to_string_pretty(&rule)? + "\n"))?;
    let tables: Vec<String> = proven.iter().map(|(one, _)| archive(one.table)).collect();
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
        let output = output(one.table);
        let archived = format!("Custom-{}", archive(one.table));
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
fn archive_table(table: Table, flow: &Flow) -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Value {
        json!({
            "id": "/subscriptions/x/dataCollectionRules/r",
            "location": "westeurope",
            "properties": {
                "immutableId": "dcr-1",
                "streamDeclarations": { "Custom-S": { "columns": [
                    { "name": "EventID", "type": "int" },
                    { "name": "EventData", "type": "string" },
                ] } },
                "dataFlows": [
                    { "streams": ["Custom-S"], "destinations": ["ws"],
                      "transformKql": "source | extend X = 1",
                      "outputStream": "Microsoft-SecurityEvent" },
                    { "streams": ["Custom-W"], "destinations": ["ws"],
                      "transformKql": "source", "outputStream": "Microsoft-WindowsEvent" },
                ],
            },
        })
    }

    const GENERATED: &str = "source\n| extend __sluice_s = \"1\"\n| extend EventData = \"\"";

    fn proven(flow: &Flow) -> Proven {
        Proven {
            source: "win".to_owned(),
            table: Table::SecurityEvent,
            generated: Transformation {
                kql: GENERATED.to_owned(),
                templates: BTreeSet::new(),
                columns: BTreeSet::from(["EventData".to_owned()]),
                left_out: Vec::new(),
            },
            kql: flow.then(GENERATED),
        }
    }

    fn flow(rule: &Value) -> Flow {
        Flow::of(Some(rule), Table::SecurityEvent).expect("the rule has a flow into the table")
    }

    #[test]
    fn c2_every_transformed_stream_also_flows_whole_into_an_archive() {
        let flow = flow(&rule());
        let one = proven(&flow);
        let written = deployment(rule(), &[(one, flow)]).expect("a deployable rule");
        let flows = written["properties"]["dataFlows"]
            .as_array()
            .expect("flows");
        assert_eq!(flows.len(), 3);
        assert_eq!(
            flows[0]["transformKql"],
            "source | extend X = 1\n| extend __sluice_s = \"1\"\n| extend EventData = \"\""
        );
        assert_eq!(flows[1]["transformKql"], "source");
        assert_eq!(
            flows[2],
            json!({
                "streams": ["Custom-S"],
                "destinations": ["ws"],
                "transformKql": "source",
                "outputStream": "Custom-SluiceSecurityEventArchive_CL",
            })
        );
        assert!(written.get("id").is_none());
        assert!(written["properties"].get("immutableId").is_none());
    }

    #[test]
    fn c2_a_rule_written_twice_keeps_one_archive_flow() {
        let first = flow(&rule());
        let once = deployment(rule(), &[(proven(&first), first)]).expect("a deployable rule");
        let second = flow(&once);
        let twice = deployment(once.clone(), &[(proven(&second), second)]).expect("again");
        let archives = twice["properties"]["dataFlows"]
            .as_array()
            .expect("flows")
            .iter()
            .filter(|f| f["outputStream"] == "Custom-SluiceSecurityEventArchive_CL")
            .count();
        assert_eq!(archives, 1);
        assert_eq!(
            twice, once,
            "the second run replaces Sluice's part instead of adding one"
        );
    }

    #[test]
    fn the_archive_table_has_the_stream_columns_and_a_time() {
        let table = archive_table(Table::SecurityEvent, &flow(&rule()));
        assert_eq!(table["properties"]["plan"], "Auxiliary");
        let names: Vec<&str> = table["properties"]["schema"]["columns"]
            .as_array()
            .expect("columns")
            .iter()
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert_eq!(names, ["TimeGenerated", "EventID", "EventData"]);
    }

    #[test]
    fn a_rule_without_a_flow_into_the_table_is_refused() {
        assert!(Flow::of(Some(&rule()), Table::Syslog).is_err());
    }
}
