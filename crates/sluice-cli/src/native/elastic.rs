//! `sluice analyze --elastic-native URL`: the plan's field removals as an Elasticsearch ingest
//! pipeline per source (ADR 0024), proven in the Elasticsearch at `URL` with the Sigma rules.
//!
//! The sample must be documents as the index stores them (`_source`, after any integration
//! pipeline), because that is what a pipeline run last sees: Sluice's is meant for the
//! `<type>-<dataset>@custom` hook that Elastic's integration pipelines end with.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::event::Event;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_elastic::{IngestPipeline, PipelinePlan, ingest_pipeline, simulate};

use super::{list, megabytes, saved, size};

/// Proves an ingest pipeline for every source whose plan removes fields, and writes each one
/// that removes something to `out/elastic/SOURCE.pipeline.json`.
pub(crate) fn elastic(analysis: &Analysis, input: Input<'_>, url: &str, out: &Path) -> Result<()> {
    let engine = input
        .sigma
        .engine(input.sources)
        .context("compiling the Sigma rules")?;
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
            if let Some(reason) = generated.left_out.first() {
                println!(
                    "  elastic {source}: nothing removed in Elasticsearch: {reason}{}",
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
        let documents: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
        let after = simulate(url, &generated.body, &documents)
            .with_context(|| format!("{source}: running the pipeline in Elasticsearch"))?;
        let violations = beyond_vector(analysis, &events, &after)?;
        if let Some(first) = violations.first() {
            bail!(
                "{source}: the pipeline removes {} field(s) the proven data plane keeps, first \
                 {first}; nothing was written",
                violations.len()
            );
        }
        let alerts = super::same_alerts(&engine, source, &events, &after)?;
        summary(source, &generated, &documents, &after, alerts);
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

fn summary(
    source: &str,
    generated: &IngestPipeline,
    before: &[&Map<String, Value>],
    after: &[Map<String, Value>],
    alerts: usize,
) {
    let bytes_before: usize = before.iter().map(|d| size(d)).sum();
    let bytes_after: usize = after.iter().map(size).sum();
    println!(
        "  elastic {source}: {} kinds of event, fields {}{}; {} → {} ({}), every removed field \
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

/// Fields the pipeline removed from a document that the data plane keeps on it.
fn beyond_vector(
    analysis: &Analysis,
    events: &[&Event],
    after: &[Map<String, Value>],
) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for (event, document) in events.iter().zip(after) {
        let reduced = analysis
            .data_plane
            .reduce(event)
            .with_context(|| format!("the data plane on event {}", event.id))?;
        let Outcome::Forwarded(body) = reduced.outcome else {
            continue; // Vector counts it instead of sending it.
        };
        let kept = leaves(document);
        let forwarded = leaves(&body);
        for path in leaves(&event.fields) {
            if !kept.contains(&path) && forwarded.contains(&path) {
                violations.push(format!("{path} on event {}", event.id));
            }
        }
    }
    Ok(violations)
}

/// The leaf paths of a document, as VRL's `flatten` makes them.
fn leaves(document: &Map<String, Value>) -> BTreeSet<String> {
    fn walk(prefix: String, value: &Value, out: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    walk(format!("{prefix}.{key}"), value, out);
                }
            }
            _ => {
                out.insert(prefix);
            }
        }
    }
    let mut out = BTreeSet::new();
    for (key, value) in document {
        walk(key.clone(), value, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn leaves_are_flattened_paths_without_empty_objects() {
        let document = json!({"a": {"b": 1, "c": {}}, "d": [1], "e": null});
        let paths: Vec<String> = leaves(document.as_object().expect("an object"))
            .into_iter()
            .collect();
        assert_eq!(paths, ["a.b", "d", "e"]);
    }
}
