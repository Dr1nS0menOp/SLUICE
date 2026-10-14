//! Reading sources, samples, rules and recipes from disk.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::DateTime;
use serde::Deserialize;
use serde_json::Value;
use sluice_core::event::{Event, Timestamp};
use sluice_core::ids::EventId;
use sluice_core::source::{Source, SourceFormat};

/// The sources file: `sources: [{ id, logsource, format }]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcesFile {
    sources: Vec<Source>,
}

pub(crate) fn sources(path: &Path) -> Result<Vec<Source>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file: SourcesFile =
        serde_yaml_ng::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if file.sources.is_empty() {
        bail!("{} declares no sources", path.display());
    }
    Ok(file.sources)
}

/// Reads `<dir>/<source>.ndjson` for every source, orders all events by `@timestamp` (events
/// without one keep their file order at time 0), and numbers them.
pub(crate) fn events(dir: &Path, sources: &[Source]) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    for source in sources {
        let path = dir.join(format!("{}.ndjson", source.id));
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        for (number, line) in text
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let Value::Object(fields) = serde_json::from_str(line)
                .with_context(|| format!("{}:{}: not JSON", path.display(), number + 1))?
            else {
                bail!("{}:{}: not a JSON object", path.display(), number + 1);
            };
            let timestamp = fields
                .get("@timestamp")
                .and_then(Value::as_str)
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map_or(0, |t| t.timestamp());
            events.push(Event {
                id: EventId(0),
                timestamp: Timestamp(timestamp),
                source: source.id.clone(),
                fields,
            });
        }
    }
    events.sort_by_key(|e| e.timestamp);
    for (event, n) in events.iter_mut().zip(0u64..) {
        event.id = EventId(n);
    }
    Ok(events)
}

/// Tells the operator which JSON sources have not declared the field naming convention of their
/// records. Sigma rules cannot be compared with such a source (ADR 0018), so nothing a Sigma rule
/// could read is cut there; the hint says how to change that.
pub(crate) fn hint_undeclared_schemas(sources: &[Source], sigma: &sluice_rules::SigmaRules) {
    if sigma.requirements().is_empty() {
        return;
    }
    for source in sources
        .iter()
        .filter(|s| matches!(s.format, SourceFormat::Json) && !sigma.reads(s.schema))
    {
        if source.schema.is_declared() {
            eprintln!(
                "hint: source {} declares `schema: {}`, but no --sigma-pipeline maps the Sigma \
                 rules onto it, so nothing they could read is cut there. Add the pipeline your \
                 SIEM converts Sigma rules with, such as `--sigma-pipeline {}=ecs_windows` for \
                 Elastic (docs/guide.md, \"Field names\").",
                source.id, source.schema, source.schema
            );
        } else {
            eprintln!(
                "hint: source {} does not declare `schema`, so Sigma rules cannot be compared \
                 with its field names and nothing they could read is cut. Add `schema: sigma` \
                 if its records use the names your Sigma rules use, or the convention they \
                 follow plus a --sigma-pipeline (docs/guide.md, \"Field names\").",
                source.id
            );
        }
    }
}

/// The pipelines of `--sigma-pipeline SCHEMA=PIPELINE`: a built-in name or a pipeline file.
pub(crate) fn sigma_pipelines(specs: &[String]) -> Result<Vec<sluice_rules::SigmaPipeline>> {
    specs
        .iter()
        .map(|spec| {
            let (schema, pipeline) = spec
                .split_once('=')
                .with_context(|| format!("--sigma-pipeline {spec}: expected SCHEMA=PIPELINE"))?;
            let schema: sluice_core::schema::Schema = serde_json::from_value(Value::String(
                schema.trim().to_owned(),
            ))
            .with_context(|| format!("--sigma-pipeline {spec}: unknown schema `{schema}`"))?;
            let path = Path::new(pipeline);
            if path.is_file() {
                let yaml = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                Ok(sluice_rules::SigmaPipeline::parse(schema, pipeline, &yaml)?)
            } else {
                Ok(sluice_rules::SigmaPipeline::builtin(schema, pipeline)?)
            }
        })
        .collect()
}

/// Wazuh rules from `rules`, bounded by the decoders in `decoders` if given.
pub(crate) fn wazuh(
    rules: Option<&Path>,
    decoders: Option<&Path>,
) -> Result<Option<sluice_rules::WazuhRules>> {
    let Some(rules) = rules else {
        return Ok(None);
    };
    let rule_files = files(rules, &["xml"])?;
    let decoder_files = if let Some(dir) = decoders {
        files(dir, &["xml"])?
    } else {
        eprintln!(
            "hint: without --wazuh-decoders, Wazuh rules are not bounded by <decoded_as> and \
             apply to every template"
        );
        Vec::new()
    };
    Ok(Some(sluice_rules::WazuhRules::parse_with_decoders(
        rule_files.iter().map(|(_, text)| text.as_str()),
        decoder_files.iter().map(|(_, text)| text.as_str()),
    )?))
}

/// Sentinel analytics rules, hunting queries and functions from `dir`, if given; problems are
/// printed as warnings.
pub(crate) fn sentinel(dir: Option<&Path>) -> Result<Option<sluice_rules::SentinelRules>> {
    let Some(dir) = dir else {
        return Ok(None);
    };
    let files = files(dir, &["yaml", "yml"])?;
    let rules = sluice_rules::SentinelRules::parse(
        files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    );
    for problem in rules.problems() {
        eprintln!("warning: {problem}");
    }
    Ok(Some(rules))
}

/// The Kusto emulator at `url`, running `rules` on the sources `--sentinel-table` names.
pub(crate) fn kusto(
    url: &str,
    rules: &sluice_rules::SentinelRules,
    specs: &[String],
) -> Result<sluice_kql::KustoEngine> {
    let tables = specs
        .iter()
        .map(|spec| {
            let (source, table) = spec
                .split_once('=')
                .with_context(|| format!("--sentinel-table {spec}: expected SOURCE=TABLE"))?;
            let table = sluice_kql::Table::from_name(table.trim()).with_context(|| {
                format!("--sentinel-table {spec}: Sluice cannot load table `{table}`")
            })?;
            Ok((sluice_core::ids::SourceId::new(source.trim()), table))
        })
        .collect::<Result<_>>()?;
    let engine = sluice_kql::KustoEngine::connect(url, rules.queries(), tables)
        .with_context(|| format!("connecting to the Kusto emulator at {url}"))?;
    eprintln!(
        "Sentinel: {} rules run in the emulator, {} cannot run there and are covered by their \
         requirements only",
        engine.rules().count(),
        engine.skipped().len()
    );
    Ok(engine)
}

/// Every file under `dir` with one of `extensions`, as `(path, contents)`, sorted by path.
pub(crate) fn files(dir: &Path, extensions: &[&str]) -> Result<Vec<(String, String)>> {
    let mut paths = Vec::new();
    collect(dir, extensions, &mut paths).with_context(|| format!("reading {}", dir.display()))?;
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            Ok((path.display().to_string(), text))
        })
        .collect()
}

fn collect(dir: &Path, extensions: &[&str], out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, extensions, out)?;
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| extensions.contains(&e))
        {
            out.push(path);
        }
    }
    Ok(())
}
