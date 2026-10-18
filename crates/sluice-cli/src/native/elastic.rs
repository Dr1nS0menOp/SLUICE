//! `sluice analyze --elastic-native`: the plan's field removals as an Elasticsearch ingest
//! pipeline per source (ADR 0024), proven in `--elasticsearch` with the Sigma rules and, where
//! they run there, Elastic's own (ADR 0025).
//!
//! The sample must be documents as the index stores them (`_source`, after any integration
//! pipeline), because that is what a pipeline run last sees: Sluice's is meant for the
//! `<type>-<dataset>@custom` hook that Elastic's integration pipelines end with. The proof
//! compares each document as the pipeline leaves it with the document itself: it removes
//! nothing Vector keeps, changes no other value, and the rules raise the same alerts.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_elastic::{PipelinePlan, ingest_pipeline, simulate};

use super::Generated;

/// Proves an ingest pipeline for every source whose plan removes fields, and writes each one
/// that removes something to `out/elastic/SOURCE.pipeline.json`.
pub(crate) fn elastic(analysis: &Analysis, input: Input<'_>, url: &str, out: &Path) -> Result<()> {
    let sigma = input
        .sigma
        .engine(input.sources)
        .context("compiling the Sigma rules")?;
    // Elastic's own rules too, where they run in Elasticsearch (ADR 0025).
    let mut engines: Vec<&dyn RuleEngine> = vec![&sigma];
    engines.extend(input.elastic.and_then(|e| e.engine));
    let engine = Engines(engines);
    let mut written = Vec::new();
    for source in input.sources {
        let source = source.id.as_str();
        let plans: Vec<PipelinePlan<'_>> = analysis
            .discovery
            .templates
            .iter()
            .zip(&analysis.selection.recipes)
            .filter(|(template, _)| template.source.as_str() == source)
            .map(|(template, recipe)| PipelinePlan { template, recipe })
            .collect();
        let generated = ingest_pipeline(
            &format!("Sluice: proven field removals for {source} (ADR 0024)"),
            &plans,
        );
        if generated.templates.is_empty() {
            super::print_nothing_removed("elastic", source, "Elasticsearch", &generated.left_out);
            continue;
        }
        let events = super::source_events(input, source);
        let documents: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
        let after = simulate(url, &generated.body, &documents)
            .with_context(|| format!("{source}: running the pipeline in Elasticsearch"))?;
        let violations =
            super::beyond_vector(analysis, &events, documents.iter().copied(), &after)?;
        if let Some(first) = violations.first() {
            bail!(
                "{source}: the pipeline changes {} field(s) the proven data plane keeps, first \
                 {first}; nothing was written",
                violations.len()
            );
        }
        let alerts = super::same_alerts(&engine, source, &events, &after)?;
        let shown = Generated {
            templates: generated.templates.len(),
            fields: &generated.fields,
            empty_fields: generated.empty_fields,
            left_out: &generated.left_out,
        };
        let bytes = (
            super::bytes(documents.iter().copied()),
            super::bytes(&after),
        );
        super::print_summary("elastic", source, &shown, bytes, alerts);
        let path = out.join("elastic").join(format!("{source}.pipeline.json"));
        crate::output::write(
            &path,
            &(serde_json::to_string_pretty(&generated.body)? + "\n"),
        )?;
        written.push(path);
    }
    if let Some(first) = written.first() {
        println!(
            "  elastic wrote {} pipeline(s) in {}: install each with PUT _ingest/pipeline/sluice-SOURCE \
             and call it last, from the `<type>-<dataset>@custom` pipeline of the data stream",
            written.len(),
            first.parent().unwrap_or(first).display()
        );
    }
    Ok(())
}
