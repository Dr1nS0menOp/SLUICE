//! `sluice analyze --native sentinel,elastic,fluent-bit,otel`: the plan's field removals in a
//! SIEM's own ingestion or in the agent, proven in that engine before anything is written.
//!
//! The proof has two parts, both on the sample:
//! 1. **Never more than Vector.** Every field the generated code removes from a record is one
//!    the proven data plane removes from it too (or the data plane counts the event instead).
//! 2. **The same detections.** The rules raise the same alerts on the records as the SIEM's
//!    ingestion leaves them as on the full ones.

pub(crate) mod elastic;
pub(crate) mod fluentbit;
pub(crate) mod otel;
pub(crate) mod sentinel;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::RuleEngine;
use sluice_core::event::Event;
use sluice_core::field::FieldPath;
use sluice_core::guard::Plan;
use sluice_core::reduce::{Outcome, Reducer};

/// The alerts `engine` raises on the full records, if it raises the same on the records as
/// ingestion leaves them (`after`, in the same order).
fn same_alerts(
    engine: &dyn RuleEngine,
    source: &str,
    events: &[&Event],
    after: &[Map<String, Value>],
) -> Result<usize> {
    let changed = with_fields(events, after);
    let full = engine
        .alerts_refs(events)
        .context("rules on the full records")?;
    let reduced = engine
        .alerts(&changed)
        .context("rules on the reduced records")?;
    if full != reduced {
        bail!(
            "{source}: the generated code changes detections ({} alerts on full records, {} on \
             reduced ones); nothing was written",
            full.len(),
            reduced.len()
        );
    }
    Ok(full.len())
}

/// The plans of `source`'s templates, in discovery's order: what each generator carries out.
fn plans_for<'a>(analysis: &'a Analysis, source: &str) -> Vec<Plan<'a>> {
    analysis
        .plans()
        .into_iter()
        .filter(|plan| plan.template.source.as_str() == source)
        .collect()
}

/// The events of `source`, in the sample's order.
fn source_events<'a>(input: Input<'a>, source: &str) -> Vec<&'a Event> {
    input
        .events
        .iter()
        .filter(|e| e.source.as_str() == source)
        .collect()
}

/// `events` as an engine forwards them: each with the fields of its record in `records`.
fn with_fields(events: &[&Event], records: &[Map<String, Value>]) -> Vec<Event> {
    events
        .iter()
        .zip(records)
        .map(|(event, record)| Event {
            fields: record.clone(),
            ..(*event).clone()
        })
        .collect()
}

/// Fields the generated code removed from a record that the data plane keeps on it, and values
/// it changed: each record `after` the code compared with the same record `before` it (through
/// the engine without the code, or as the sample has it).
fn beyond_vector<'a>(
    analysis: &Analysis,
    events: &[&Event],
    before: impl IntoIterator<Item = &'a Map<String, Value>>,
    after: &[Map<String, Value>],
) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for ((event, before), after) in events.iter().zip(before).zip(after) {
        let was = leaf_values(before);
        let now = leaf_values(after);
        for (path, value) in &now {
            match was.get(path) {
                Some(old) if same(old, value) => {}
                // An object whose last field went: the generators remove it, as Vector does,
                // and one kept as `{}` holds nothing either.
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

/// Whether an engine gave the value back: the same, or exactly the same number.
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

/// Prints why `place` removes nothing for `source`: the first reason, and how many more.
fn print_nothing_removed(label: &str, source: &str, place: &str, left_out: &[String]) {
    if let Some(reason) = left_out.first() {
        println!(
            "  {label} {source}: nothing removed in {place}: {reason}{}",
            match left_out.len() {
                1 => String::new(),
                n => format!(" (and {} more)", n - 1),
            }
        );
    }
}

/// What a generator made for one source, as its summary shows it.
struct Generated<'a> {
    templates: usize,
    fields: &'a BTreeSet<FieldPath>,
    empty_fields: bool,
    left_out: &'a [String],
}

/// Prints what the generated code saves on the sample (`bytes` before and after it), that it
/// removes nothing Vector keeps, the alerts, and what it leaves to a pipeline tool.
fn print_summary(
    label: &str,
    source: &str,
    generated: &Generated<'_>,
    (before, after): (usize, usize),
    alerts: usize,
) {
    println!(
        "  {label} {source}: {} kinds of event, fields {}{}; {} → {} ({}), every removed field \
         also removed by Vector, {alerts} = {alerts} alerts",
        generated.templates,
        list(generated.fields),
        if generated.empty_fields {
            " and empty ones"
        } else {
            ""
        },
        megabytes(before),
        megabytes(after),
        saved(before, after),
    );
    if alerts == 0 {
        println!("          {}", sluice_autopilot::EMPTY_PROOF);
    }
    print_left_out(generated.left_out);
}

/// Prints the first five parts of the plan left to a pipeline tool, and how many more.
fn print_left_out(left_out: &[String]) {
    for reason in left_out.iter().take(5) {
        println!("          left to a pipeline tool: {reason}");
    }
    if left_out.len() > 5 {
        println!("          … and {} more", left_out.len() - 5);
    }
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

/// The bytes of `records`, serialized.
fn bytes<'a>(records: impl IntoIterator<Item = &'a Map<String, Value>>) -> usize {
    records.into_iter().map(size).sum()
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

fn list<T: std::fmt::Display>(items: &BTreeSet<T>) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
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
