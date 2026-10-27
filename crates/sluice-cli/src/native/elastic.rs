//! `sluice analyze --native elastic`: the plan's field removals as an Elasticsearch ingest
//! pipeline per source (ADR 0024), proven in `--elasticsearch` with the Sigma rules and, where
//! they run there, Elastic's own (ADR 0025).
//!
//! The sample must be documents as the index stores them (`_source`, after any integration
//! pipeline), because that is what a pipeline run last sees: Sluice's is meant for the
//! `<type>-<dataset>@custom` hook that Elastic's integration pipelines end with. The proof
//! compares each document as the pipeline leaves it with the document itself: it removes
//! nothing Vector keeps, changes no other value, and the rules raise the same alerts.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_autopilot::{Analysis, Input};
use sluice_core::alert::{Engines, RuleEngine};
use sluice_elastic::{Rebuild, ingest_pipeline, rebuild, rebuilt, simulate};

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
        let plans = super::plans_for(analysis, source);
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
        let rebuild = rebuild(&plans, &generated);
        runtime_fields(url, source, rebuild, &documents, &after, out)?;
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

/// Proves the runtime fields that put `source`'s implied values back: on the sample they must
/// read every forwarded document as they read the full one. Those that do are written to
/// `out/elastic/SOURCE.runtime.json`; any other is left out, and said so.
fn runtime_fields(
    url: &str,
    source: &str,
    mut rebuild: Rebuild,
    full: &[&Map<String, Value>],
    sent: &[Map<String, Value>],
    out: &Path,
) -> Result<()> {
    if rebuild.is_empty() {
        return Ok(());
    }
    let sent: Vec<&Map<String, Value>> = sent.iter().collect();
    let expected = rebuilt(url, &rebuild, full)
        .with_context(|| format!("{source}: reading the full documents' runtime fields"))?;
    let read = rebuilt(url, &rebuild, &sent)
        .with_context(|| format!("{source}: reading the forwarded documents' runtime fields"))?;
    let differ: BTreeSet<&String> = expected
        .iter()
        .zip(&read)
        .flat_map(|(want, got)| want.iter().filter(move |(k, v)| got.get(*k) != Some(*v)))
        .map(|(field, _)| field)
        .collect();
    rebuild.retain(
        |field| !differ.iter().any(|d| d.as_str() == field),
        "on the sample it would read a forwarded document differently from the full one",
    );
    let fields: Vec<&str> = rebuild.fields().collect();
    let left = match rebuild.left_out.len() {
        0 => String::new(),
        n => format!(
            "; {n} left out, first {}",
            rebuild.left_out.first().map_or("", String::as_str)
        ),
    };
    if fields.is_empty() {
        println!("  elastic {source}: no implied value put back at query time{left}");
        return Ok(());
    }
    let path = out.join("elastic").join(format!("{source}.runtime.json"));
    crate::output::write(
        &path,
        &(serde_json::to_string_pretty(&rebuild.runtime_mappings())? + "\n"),
    )?;
    println!(
        "  elastic {source}: {} implied field(s) put back at query time by {} (a search's \
         `runtime_mappings`, or runtime fields of a Kibana data view), proven on the sample{left}",
        fields.len(),
        path.display()
    );
    Ok(())
}
