//! `sluice analyze --fluent-bit-native`: the plan's field removals as a Fluent Bit Lua filter
//! per source (ADR 0027), proven in a real Fluent Bit with the rules of the analysis.
//!
//! Fluent Bit changes some records on its own (it reads `1e21` as `1`, and saturates integers
//! past 2^63), so the proof compares the records as Fluent Bit forwards them with the filter
//! against the same records through Fluent Bit without it: the filter removes nothing Vector
//! keeps, changes no other value (a whole float may come back as an integer, the same number),
//! and the rules raise the same alerts.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::event::Event;
use sluice_fluentbit::{FilterPlan, FluentBit, filter_section, lua_filter};

use super::Generated;

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
            super::print_nothing_removed("fluent-bit", source, "the agent", &generated.left_out);
            continue;
        };
        let events = super::source_events(input, source);
        let records: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
        let before = fluent_bit
            .run(None, &records)
            .with_context(|| format!("{source}: running Fluent Bit"))?;
        let after = fluent_bit
            .run(Some(script), &records)
            .with_context(|| format!("{source}: running the filter in Fluent Bit"))?;
        let violations = super::beyond_vector(analysis, &events, &before, &after)?;
        if let Some(first) = violations.first() {
            bail!(
                "{source}: the filter changes {} field(s) the proven data plane keeps, first \
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
        super::print_summary("fluent-bit", source, &shown, bytes, alerts);
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
