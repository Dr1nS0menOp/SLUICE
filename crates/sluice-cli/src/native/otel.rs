//! `sluice analyze --otel-native`: the plan's field removals as `transform` processor statements
//! (OTTL) per source (ADR 0028), proven in a real OpenTelemetry Collector with the rules of the
//! analysis.
//!
//! The collector changes some records on its own (its JSON parser makes every number a double),
//! so the proof compares the records as the collector forwards them with the statements against
//! the same records through the collector without them: the statements remove nothing Vector
//! keeps, change no other value, and the rules raise the same alerts.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::event::Event;
use sluice_otel::{Collector, TransformPlan, processor, transform};

use super::Generated;

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
            super::print_nothing_removed("otel   ", source, "the collector", &generated.left_out);
            continue;
        }
        let events = super::source_events(input, source);
        let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
        let before = collector
            .run(None, &records)
            .with_context(|| format!("{source}: running the collector"))?;
        let after = collector
            .run(Some(&generated.statements), &records)
            .with_context(|| format!("{source}: running the statements in the collector"))?;
        let violations = super::beyond_vector(analysis, &events, &before, &after)?;
        if let Some(first) = violations.first() {
            bail!(
                "{source}: the statements change {} field(s) the proven data plane keeps, first \
                 {first}; nothing was written",
                violations.len()
            );
        }
        let forwarded = super::with_fields(&events, &before);
        let forwarded: Vec<&Event> = forwarded.iter().collect();
        let alerts = super::same_alerts(&engine, source, &forwarded, &after)?;
        let shown = Generated {
            templates: generated.templates.len(),
            fields: &generated.fields,
            empty_fields: generated.empty_fields,
            left_out: &generated.left_out,
        };
        let bytes = (super::bytes(&before), super::bytes(&after));
        super::print_summary("otel   ", source, &shown, bytes, alerts);
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
