//! `sluice analyze --native sentinel`: the plan's field removals as a DCR transformation per
//! Sentinel source (ADR 0013), proven in the Kusto emulator with Microsoft's rules.
//!
//! What is written is one data collection rule: each proven transformation in its table's data
//! flow, and next to it a flow of the same stream, untransformed, into an archive table of the
//! low-cost Auxiliary plan, so every record is kept whole (contract rule 2).

mod dcr;

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::event::Event;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_kql::{
    MAX_TRANSFORM_KQL, Table, Transformation, disallowed_functions, routed_on_within,
    routed_within, run_transformations,
};

use self::dcr::{Flow, write};
use super::{is_empty, list, megabytes, saved, size};
use crate::stdout::out;

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
            serde_json::from_str(&text)
                .map(dcr::arm_shape)
                .with_context(|| format!("{}: not JSON", path.display()))
        })
        .transpose()?;
    let mut proven = Vec::new();
    for spec in specs {
        let (source, table) = crate::engines::sentinel_table(spec, input.events)?;
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
        out!(
            "  native  proven, not written: give the data collection rule the records go through \
             (--sentinel-dcr RULE.json), and Sluice writes it with the transformation and an \
             untransformed flow into an archive table (ADR 0013, contract rule 2)"
        );
        return Ok(());
    };
    write(rule, &proven, &out.join("sentinel"))
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
    let events = super::source_events(input, source);
    if let Some(event) = events.iter().find(|e| e.fields.values().any(is_empty)) {
        out!(
            "  native  {source}: not generated: event {} has an empty field, so its kinds of event \
             were not discovered on records as {} stores them (where empty and missing are the \
             same). Read the sample from the workspace (scripts/real-data/collect-sentinel.sh).",
            event.id,
            table.name()
        );
        return Ok(None);
    }
    let plans = super::plans_for(analysis, source);
    let stream: Vec<&str> = flow.stream.iter().map(|(name, _)| name.as_str()).collect();
    // The data flow's own transformation takes part of what a rule allows.
    let budget = MAX_TRANSFORM_KQL.saturating_sub(flow.before.len() + 1);
    // The rule Sluice writes always has the archive flow next to this one (contract rule 2), so
    // records no rule could match may stay out of the table (ADR 0036).
    let generated = if flow.first {
        routed_on_within(table.name(), &flow.declared(), &stream, &plans, budget)
    } else {
        routed_within(&table, &stream, &plans, budget)
    };
    let unsupported = disallowed_functions(&generated.kql);
    if !unsupported.is_empty() {
        bail!(
            "{source}: the transformation calls {unsupported:?}, which DCRs refuse (a Sluice bug)"
        );
    }
    let kql = flow.then(&generated.kql);
    if kql.len() > MAX_TRANSFORM_KQL {
        out!(
            "  native  {source}: not written: with the data flow's own transformation it would be \
             {} characters, more than the {MAX_TRANSFORM_KQL} a data collection rule takes",
            kql.len()
        );
        return Ok(None);
    }
    // The rules on the records as the table gets them, without Sluice's part and with it.
    let kept = through_flow(analysis, url, source, flow, (&generated.kql, &kql), &events)?;
    let alerts = input
        .sentinel
        .and_then(|s| s.engine)
        .map(|engine| same_alerts(engine, source, &kept))
        .transpose()?;
    let proven = Proven {
        source: source.to_owned(),
        table,
        generated,
        kql,
    };
    summary(&proven, &kept, alerts);
    Ok(Some(proven))
}

/// The alerts the Sentinel rules raise on every record as the table stores it without Sluice's
/// part, if they raise the same on what the part leaves in the table.
fn same_alerts(
    engine: &dyn sluice_core::alert::RuleEngine,
    source: &str,
    records: &[Stored],
) -> Result<usize> {
    let stored: Vec<&Event> = records.iter().map(|(event, _)| event).collect();
    let left: Vec<Event> = records
        .iter()
        .filter_map(|(event, after)| {
            after.as_ref().map(|fields| Event {
                fields: fields.clone(),
                ..event.clone()
            })
        })
        .collect();
    let full = engine
        .alerts_refs(&stored)
        .context("rules on the full records")?;
    let reduced = engine
        .alerts(&left)
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

/// Runs the flow with and without Sluice's part (`kqls`: the part, and the whole
/// `transformKql`) on `events` in the emulator, and returns each event the table gets without
/// the part, with its record as stored and, unless the part keeps it out, as the part leaves it.
/// Refuses a part that keeps out an event Vector sends (it may only keep out what Vector counts
/// instead: ADR 0036), makes the flow keep one it drops, or empties a column Vector keeps.
fn through_flow(
    analysis: &Analysis,
    url: &str,
    source: &str,
    flow: &Flow,
    (part, whole): (&str, &str),
    events: &[&Event],
) -> Result<Vec<Stored>> {
    let declared = flow.declared();
    // Both in one query: the flow's own transformation may read the clock (`now()`). Where
    // Sluice's part runs first, the columns have the stream's names there: it also runs alone,
    // next to the records as loaded, to see exactly what it removes.
    let mut kqls = vec![flow.before.as_str(), whole];
    if flow.first {
        kqls.push(part);
        kqls.push("source");
    }
    let mut runs = run_transformations(url, &declared, &kqls, events)
        .with_context(|| format!("{source}: running the transformation in the emulator"))?;
    let (loaded, alone) = if flow.first {
        (runs.pop(), runs.pop())
    } else {
        (None, None)
    };
    let (Some(after), Some(untouched)) = (runs.pop(), runs.pop()) else {
        bail!("{source}: the emulator returned no records");
    };
    // What Sluice's part gets, and what it leaves.
    let (given, left) = match (&loaded, &alone) {
        (Some(loaded), Some(alone)) => (loaded, alone),
        _ => (&untouched, &after),
    };
    for n in dropped(given, left)
        .into_iter()
        .chain(dropped(&untouched, &after))
    {
        let event = events[n];
        let reduced = analysis
            .data_plane
            .reduce(event)
            .with_context(|| format!("the data plane on event {}", event.id))?;
        if matches!(reduced.outcome, Outcome::Forwarded(_)) {
            bail!(
                "{source}: the transformation keeps event {} out of the table, which Vector sends; \
                 nothing was written",
                event.id
            );
        }
    }
    if let Some(&n) = dropped(&after, &untouched).first() {
        bail!(
            "{source}: with the transformation the data flow keeps event {}, which it drops \
             otherwise; nothing was written",
            events[n].id
        );
    }
    let violations = beyond_vector(analysis, events, given, left)?;
    if let Some(first) = violations.first() {
        bail!(
            "{source}: the transformation empties {} column(s) the proven data plane keeps, \
             first {first}; nothing was written",
            violations.len()
        );
    }
    // A record the flow's own transformation drops reaches the table in neither.
    Ok(events
        .iter()
        .zip(untouched.iter().zip(&after))
        .filter_map(|(event, (untouched, after))| {
            untouched.as_ref().map(|untouched| {
                (
                    Event {
                        fields: untouched.clone(),
                        ..(*event).clone()
                    },
                    after.clone(),
                )
            })
        })
        .collect())
}

/// An event's record after a transformation, if it kept the event.
type Record = Option<Map<String, Value>>;

/// An event as the table stores it without Sluice's part, and its record with the part, unless the
/// part keeps it out of the table.
type Stored = (Event, Record);

/// The events whose record `before` holds and `after` does not: those dropped in between.
fn dropped(before: &[Record], after: &[Record]) -> Vec<usize> {
    before
        .iter()
        .zip(after)
        .enumerate()
        .filter(|(_, (before, after))| before.is_some() && after.is_none())
        .map(|(n, _)| n)
        .collect()
}

/// Prints what the transformation saves on the records the table gets: each event as stored
/// without Sluice's part, and with it.
fn summary(proven: &Proven, records: &[Stored], alerts: Option<usize>) {
    let before: usize = records.iter().map(|(event, _)| size(&event.fields)).sum();
    let kept: usize = records.iter().flat_map(|(_, after)| after).map(size).sum();
    let outside = records.iter().filter(|(_, after)| after.is_none()).count();
    let generated = &proven.generated;
    out!(
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
    if outside > 0 {
        out!(
            "          {outside} records no rule could match stay out of the table, as Vector counts \
             them instead of sending them; the archive flow keeps them whole (ADR 0036)"
        );
    }
    if alerts == Some(0) {
        out!("          {}", sluice_autopilot::EMPTY_PROOF);
    }
    super::print_left_out(&generated.left_out);
}

/// Columns Sluice's part emptied on a record that the data plane keeps on it: every column the
/// record holds before the part (`given`) and lacks after it (`left`), not only those the
/// transformation names, so the check does not rest on the code it checks.
fn beyond_vector(
    analysis: &Analysis,
    events: &[&Event],
    given: &[Record],
    left: &[Record],
) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for ((event, given), left) in events.iter().zip(given).zip(left) {
        let (Some(given), Some(left)) = (given, left) else {
            continue; // Dropped by the flow's own transformation: the table gets neither.
        };
        let reduced = analysis
            .data_plane
            .reduce(event)
            .with_context(|| format!("the data plane on event {}", event.id))?;
        let Outcome::Forwarded(body) = reduced.outcome else {
            continue; // Vector counts it instead of sending it.
        };
        for column in given.keys().filter(|column| !left.contains_key(*column)) {
            if body.contains_key(column) {
                violations.push(format!("{column} on event {}", event.id));
            }
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests;
