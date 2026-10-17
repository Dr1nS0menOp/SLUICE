//! `sluice analyze --otel-native`: the plan's field removals as `transform` processor statements
//! (OTTL) per source (ADR 0028), proven in a real OpenTelemetry Collector with the rules of the
//! analysis.
//!
//! The collector changes some records on its own (its JSON parser makes every number a double),
//! so the proof compares the records as the collector forwards them with the statements against
//! the same records through the collector without them: the statements remove nothing Vector
//! keeps, change no other value, and the rules raise the same alerts.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::event::Event;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_otel::{Collector, Statements, TransformPlan, processor, transform};

use super::{list, megabytes, saved, size};

/// Proves transform statements for every source whose plan removes fields, and writes the
/// processors of those that remove something to `out/otel/processors.yaml`.
pub(crate) fn otel(
    analysis: &Analysis,
    input: Input<'_>,
    command: &Path,
    out: &Path,
) -> Result<()> {
    let sigma = input
        .sigma
        .engine(input.sources)
        .context("compiling the Sigma rules")?;
    let mut engines: Vec<&dyn RuleEngine> = vec![&sigma];
    engines.extend(input.sentinel.and_then(|s| s.engine));
    engines.extend(input.elastic.and_then(|e| e.engine));
    let engine = Engines(engines);
    let collector = Collector::new(command);
    let mut written = Vec::new();
    for source in input.sources {
        let source = source.id.as_str();
        let plans: Vec<TransformPlan<'_>> = analysis
            .discovery
            .templates
            .iter()
            .zip(&analysis.selection.recipes)
            .filter(|(template, _)| template.source.as_str() == source)
            .map(|(template, recipe)| TransformPlan { template, recipe })
            .collect();
        let generated = transform(&plans);
        if generated.statements.is_empty() {
            if let Some(reason) = generated.left_out.first() {
                println!(
                    "  otel    {source}: nothing removed in the collector: {reason}{}",
                    match generated.left_out.len() {
                        1 => String::new(),
                        n => format!(" (and {} more)", n - 1),
                    }
                );
            }
            continue;
        }
        let events: Vec<&Event> = input
            .events
            .iter()
            .filter(|e| e.source.as_str() == source)
            .collect();
        let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
        let before = collector
            .run(None, &records)
            .with_context(|| format!("{source}: running the collector"))?;
        let after = collector
            .run(Some(&generated.statements), &records)
            .with_context(|| format!("{source}: running the statements in the collector"))?;
        let violations = beyond_vector(analysis, &events, &before, &after)?;
        if let Some(first) = violations.first() {
            bail!(
                "{source}: the statements change {} field(s) the proven data plane keeps, first \
                 {first}; nothing was written",
                violations.len()
            );
        }
        let forwarded: Vec<Event> = events
            .iter()
            .zip(&before)
            .map(|(event, record)| Event {
                fields: record.clone(),
                ..(*event).clone()
            })
            .collect();
        let forwarded: Vec<&Event> = forwarded.iter().collect();
        let alerts = super::same_alerts(&engine, source, &forwarded, &after)?;
        summary(source, &generated, &before, &after, alerts);
        let name = format!(
            "sluice_{}",
            source.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
        );
        written.push(processor(&name, &generated.statements));
    }
    if !written.is_empty() {
        let path = out.join("otel").join("processors.yaml");
        crate::output::write(&path, &format!("processors:\n{}", written.concat()))?;
        println!(
            "  otel    wrote {} processor(s) in {}: add each to the logs pipeline of its source, \
             whose filelog receiver parses JSON into the body (`json_parser` with `parse_to: \
             body`)",
            written.len(),
            path.display()
        );
    }
    Ok(())
}

fn summary(
    source: &str,
    generated: &Statements,
    before: &[Map<String, Value>],
    after: &[Map<String, Value>],
    alerts: usize,
) {
    let bytes_before: usize = before.iter().map(size).sum();
    let bytes_after: usize = after.iter().map(size).sum();
    println!(
        "  otel    {source}: {} kinds of event, fields {}{}; {} → {} ({}), every removed field \
         also removed by Vector, {alerts} = {alerts} alerts",
        generated.templates.len(),
        list(&generated.fields),
        if generated.empty_fields {
            " and empty ones"
        } else {
            ""
        },
        megabytes(bytes_before),
        megabytes(bytes_after),
        saved(bytes_before, bytes_after),
    );
    if alerts == 0 {
        println!("          {}", sluice_autopilot::EMPTY_PROOF);
    }
    for reason in generated.left_out.iter().take(5) {
        println!("          left to a pipeline tool: {reason}");
    }
    if generated.left_out.len() > 5 {
        println!("          … and {} more", generated.left_out.len() - 5);
    }
}

/// Fields the statements removed from a record that the data plane keeps on it, and values they
/// changed: compared with the same record through the collector without them.
fn beyond_vector(
    analysis: &Analysis,
    events: &[&Event],
    before: &[Map<String, Value>],
    after: &[Map<String, Value>],
) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for ((event, before), after) in events.iter().zip(before).zip(after) {
        let was = leaf_values(before);
        let now = leaf_values(after);
        for (path, value) in &now {
            match was.get(path) {
                Some(old) if same(old, value) => {}
                // An object whose last field went is a leaf of its own, as in Vector.
                None if *value == Value::Object(Map::new()) => {}
                _ => violations.push(format!("{path} changed on event {}", event.id)),
            }
        }
        let removed: Vec<&String> = was.keys().filter(|p| !now.contains_key(*p)).collect();
        if removed.is_empty() {
            continue;
        }
        let reduced = analysis
            .data_plane
            .reduce(event)
            .with_context(|| format!("the data plane on event {}", event.id))?;
        let Outcome::Forwarded(body) = reduced.outcome else {
            continue; // Vector counts it instead of sending it.
        };
        let forwarded = leaf_values(&body);
        for path in removed {
            if forwarded.contains_key(path) {
                violations.push(format!("{path} on event {}", event.id));
            }
        }
    }
    Ok(violations)
}

/// Whether the value came back: the same, or exactly the same number.
#[allow(clippy::float_cmp, reason = "the number must come back exactly")]
fn same(old: &Value, new: &Value) -> bool {
    old == new || old.as_f64().zip(new.as_f64()).is_some_and(|(a, b)| a == b)
}

/// Each leaf path of a record with its value, as VRL's `flatten` makes them; an empty object
/// is a leaf of its own here, so one that appears or goes is seen.
fn leaf_values(record: &Map<String, Value>) -> BTreeMap<String, Value> {
    fn walk(prefix: String, value: &Value, out: &mut BTreeMap<String, Value>) {
        match value {
            Value::Object(map) if !map.is_empty() => {
                for (key, value) in map {
                    walk(format!("{prefix}.{key}"), value, out);
                }
            }
            other => {
                out.insert(prefix, other.clone());
            }
        }
    }
    let mut out = BTreeMap::new();
    for (key, value) in record {
        walk(key.clone(), value, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn values_compare_as_numbers_and_empty_objects_are_leaves() {
        assert!(same(&json!(2.0), &json!(2)));
        assert!(!same(&json!(2.5), &json!(2)));
        assert!(!same(&json!("2"), &json!(2)));
        let record = json!({"a": {"b": 1, "c": {}}, "d": [1]});
        let paths: Vec<String> = leaf_values(record.as_object().expect("an object"))
            .into_keys()
            .collect();
        assert_eq!(paths, ["a.b", "a.c", "d"]);
    }
}
