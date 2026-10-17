//! `sluice analyze --sentinel-native`, `--elastic-native`, `--fluent-bit-native` and `--otel-native`: the plan's
//! field removals in a SIEM's own ingestion or in the agent, proven in that engine before
//! anything is written.
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

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_core::alert::RuleEngine;
use sluice_core::event::Event;

/// The alerts `engine` raises on the full records, if it raises the same on the records as
/// ingestion leaves them (`after`, in the same order).
fn same_alerts(
    engine: &dyn RuleEngine,
    source: &str,
    events: &[&Event],
    after: &[Map<String, Value>],
) -> Result<usize> {
    let changed: Vec<Event> = events
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
