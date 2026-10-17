//! `sluice analyze --fluent-bit-native`: the plan's field removals as a Fluent Bit Lua filter
//! per source (ADR 0027), proven in a real Fluent Bit with the rules of the analysis.
//!
//! Fluent Bit changes some records on its own (it reads `1e21` as `1`, and saturates integers
//! past 2^63), so the proof compares the records as Fluent Bit forwards them with the filter
//! against the same records through Fluent Bit without it: the filter removes nothing Vector
//! keeps, changes no other value (a whole float may come back as an integer, the same number),
//! and the rules raise the same alerts.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::event::Event;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_fluentbit::{FilterPlan, FluentBit, LuaFilter, filter_section, lua_filter};

use super::{list, megabytes, saved, size};

/// Proves a Lua filter for every source whose plan removes fields, and writes each one that
/// removes something to `out/fluent-bit/SOURCE.lua`.
pub(crate) fn fluent_bit(
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
    let fluent_bit = FluentBit::new(command);
    let mut written = Vec::new();
    for source in input.sources {
        let source = source.id.as_str();
        let plans: Vec<FilterPlan<'_>> = analysis
            .discovery
            .templates
            .iter()
            .zip(&analysis.selection.recipes)
            .filter(|(template, _)| template.source.as_str() == source)
            .map(|(template, recipe)| FilterPlan { template, recipe })
            .collect();
        let generated = lua_filter(
            &format!("Sluice: proven field removals for {source} (ADR 0027)"),
            &plans,
        );
        let Some(script) = &generated.script else {
            if let Some(reason) = generated.left_out.first() {
                println!(
                    "  fluent-bit {source}: nothing removed in the agent: {reason}{}",
                    match generated.left_out.len() {
                        1 => String::new(),
                        n => format!(" (and {} more)", n - 1),
                    }
                );
            }
            continue;
        };
        let events: Vec<&Event> = input
            .events
            .iter()
            .filter(|e| e.source.as_str() == source)
            .collect();
        let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
        let before = fluent_bit
            .run(None, &records)
            .with_context(|| format!("{source}: running Fluent Bit"))?;
        let after = fluent_bit
            .run(Some(script), &records)
            .with_context(|| format!("{source}: running the filter in Fluent Bit"))?;
        let violations = beyond_vector(analysis, &events, &before, &after)?;
        if let Some(first) = violations.first() {
            bail!(
                "{source}: the filter changes {} field(s) the proven data plane keeps, first \
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
        let path = out.join("fluent-bit").join(format!("{source}.lua"));
        crate::output::write(&path, script)?;
        written.push((source.to_owned(), path));
    }
    if !written.is_empty() {
        let sections: String = written
            .iter()
            .map(|(source, path)| filter_section(source, &path.display().to_string()))
            .collect();
        let conf = out.join("fluent-bit").join("filters.conf");
        crate::output::write(&conf, &sections)?;
        println!(
            "  fluent-bit wrote {} filter(s) and {}: add each section to the agent's \
             configuration, with `Match` set to the tag of that source's input",
            written.len(),
            conf.display()
        );
    }
    Ok(())
}

fn summary(
    source: &str,
    generated: &LuaFilter,
    before: &[Map<String, Value>],
    after: &[Map<String, Value>],
    alerts: usize,
) {
    let bytes_before: usize = before.iter().map(size).sum();
    let bytes_after: usize = after.iter().map(size).sum();
    println!(
        "  fluent-bit {source}: {} kinds of event, fields {}{}; {} → {} ({}), every removed field \
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

/// Fields the filter removed from a record that the data plane keeps on it, and values it
/// changed: compared with the same record through Fluent Bit without the filter.
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

/// Whether Lua gave the value back: the same, or exactly the same number.
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
