//! `sluice init`: a sources file proposed from a sample (ADR 0044).
//!
//! Writing `sources.yaml` by hand is the step new users find hardest, and a wrong `schema` is
//! the one mistake the proof cannot notice. `init` reads the first events of each
//! `<source>.ndjson`, and proposes per source its format, the parser pack its lines fit, its
//! Sigma log source and the convention of its field names, each with how it came to it. It is a
//! proposal to check, never a declaration: nothing it writes is trusted until a person keeps it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_core::logsource::LogSource;
use sluice_core::schema::Schema;
use sluice_rules::{Pack, ParserBook};

use crate::cli::InitArgs;
use crate::stdout::out;

/// Events read per source: enough to see its kinds, few enough to stay quick.
const READ: usize = 2_000;

/// A pack is proposed when it parses at least this share of a source's lines, in percent.
const PARSED_PERCENT: usize = 90;

/// Fields that may hold a text source's line, in the order they are tried.
const LINE_FIELDS: [&str; 4] = ["message", "event.original", "_raw", "log"];

/// Envelope fields that may name the program a line came from (`/var/log/nginx/access.log`).
const HINT_FIELDS: [&str; 7] = [
    "log.file.path",
    "event.module",
    "event.dataset",
    "fileset.module",
    "service.type",
    "source",
    "program",
];

/// The top-level fields of an envelope a shipper puts around a line (Beats, Fluent Bit, syslog).
const ENVELOPE: [&str; 20] = [
    "@timestamp",
    "timestamp",
    "time",
    "agent",
    "ecs",
    "host",
    "hostname",
    "input",
    "log",
    "event",
    "fileset",
    "service",
    "tags",
    "cloud",
    "data_stream",
    "message",
    "_raw",
    "source",
    "program",
    "syslog",
];

/// Fields whose presence says a record is structured, not a line in an envelope.
const STRUCTURED: [&str; 8] = [
    "EventID",
    "event.code",
    "event.action",
    "eventName",
    "Channel",
    "winlog.channel",
    "Type",
    "class_uid",
];

/// One source, as proposed.
struct Proposal {
    id: String,
    logsource: LogSource,
    /// `None` for JSON; else the field with the line, and the pack it fits.
    text: Option<(String, Option<String>)>,
    schema: Schema,
    /// How it came to it, for the comment above the source.
    notes: Vec<String>,
}

pub(crate) fn init(args: &InitArgs) -> Result<()> {
    if args.out.exists() {
        bail!(
            "{} exists; give another --out, or remove it first",
            args.out.display()
        );
    }
    let book = ParserBook::embedded()?;
    let mut files: Vec<_> = std::fs::read_dir(&args.input)
        .with_context(|| format!("reading {}", args.input.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "ndjson"))
        .collect();
    files.sort();
    if files.is_empty() {
        bail!(
            "{} has no <source>.ndjson file: put one file per source there",
            args.input.display()
        );
    }
    let proposals = files
        .iter()
        .map(|path| propose(path, &book))
        .collect::<Result<Vec<_>>>()?;
    std::fs::write(&args.out, yaml(&proposals))
        .with_context(|| format!("writing {}", args.out.display()))?;
    for proposal in &proposals {
        out!("  {:<24} {}", proposal.id, proposal.notes.join("; "));
    }
    out!(
        "wrote {}: check each source, then run sluice analyze --input {} --sources {}",
        args.out.display(),
        args.input.display(),
        args.out.display()
    );
    Ok(())
}

fn propose(path: &Path, book: &ParserBook) -> Result<Proposal> {
    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("a sample file name that is not UTF-8")?
        .to_owned();
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let records: Vec<Map<String, Value>> = text
        .trim_start_matches('\u{feff}')
        .lines()
        .filter_map(|line| match serde_json::from_str(line) {
            Ok(Value::Object(record)) => Some(record),
            _ => None,
        })
        .take(READ)
        .collect();
    if records.is_empty() {
        bail!("{}: no JSON object to read", path.display());
    }
    let mut notes = vec![format!("{} events read", records.len())];
    let fields: BTreeSet<String> = records.iter().flat_map(|r| paths(r, "")).collect();
    // A line in an envelope has few fields of its own: any top-level field outside the envelope
    // (`action`, `src_ip`) says the record is already structured.
    let structured = STRUCTURED.iter().any(|f| fields.contains(*f))
        || records
            .iter()
            .flat_map(Map::keys)
            .any(|key| !ENVELOPE.contains(&key.as_str()));
    let line = (!structured)
        .then(|| {
            LINE_FIELDS
                .iter()
                .find(|f| share(&records, |r| text_at(r, f).is_some()) >= PARSED_PERCENT)
        })
        .flatten();
    if let Some(line) = line {
        let lines: Vec<&str> = records.iter().filter_map(|r| text_at(r, line)).collect();
        let hints: String = records
            .iter()
            .take(50)
            .flat_map(|r| HINT_FIELDS.iter().filter_map(|f| text_at(r, f)))
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let pack = best_pack(book, &lines, &hints);
        let (logsource, schema, parser) = if let Some((pack, parsed)) = pack {
            notes.push(format!(
                "text in `{line}`; {parsed}% of the lines fit the parser pack {}",
                pack.parser.id
            ));
            (
                pack.logsource.clone(),
                pack.parser.convention,
                Some(pack.parser.id.clone()),
            )
        } else {
            notes.push(format!(
                "text in `{line}`; no parser pack fits: rules on fields the SIEM parses keep \
                 every line (a pack of your own: parser: my-pack.yaml)"
            ));
            (LogSource::default(), Schema::Sigma, None)
        };
        return Ok(Proposal {
            id,
            logsource,
            text: Some(((*line).to_owned(), parser)),
            schema,
            notes,
        });
    }
    let (logsource, said) = json_logsource(&records);
    notes.push(said);
    let schema = Schema::guess(fields.iter().map(String::as_str)).unwrap_or_default();
    notes.push(if schema.is_declared() {
        format!("field names look like `{schema}`")
    } else {
        "field names fit no convention Sluice knows: set `schema` yourself".to_owned()
    });
    Ok(Proposal {
        id,
        logsource,
        text: None,
        schema,
        notes,
    })
}

/// The pack that parses the most of `lines`, if it parses at least [`PARSED_PERCENT`] of them,
/// with that share. Of packs that parse alike, one that includes others is preferred: it reads
/// every kind of line of a mixed log.
fn best_pack<'a>(book: &'a ParserBook, lines: &[&str], hints: &str) -> Option<(&'a Pack, usize)> {
    book.packs()
        .map(|pack| {
            let parsed = lines.iter().filter(|l| pack.parse(l).is_some()).count();
            (pack, parsed * 100 / lines.len().max(1))
        })
        .filter(|(_, parsed)| *parsed >= PARSED_PERCENT)
        .max_by_key(|(pack, parsed)| {
            // nginx and Apache write the same line: the file or module the record names tells.
            let named = pack
                .logsource
                .product
                .as_deref()
                .is_some_and(|product| hints.contains(product));
            (
                *parsed,
                named,
                pack.included.len(),
                std::cmp::Reverse(pack.parser.id.clone()),
            )
        })
}

/// The Sigma log source a JSON source's records name, and how that was found.
fn json_logsource(records: &[Map<String, Value>]) -> (LogSource, String) {
    let most = |field: &str| -> Option<String> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for record in records {
            if let Some(value) = text_at(record, field) {
                *counts.entry(value).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(value, _)| value.to_owned())
    };
    let windows = |service: &str| LogSource {
        product: Some("windows".to_owned()),
        service: Some(service.to_owned()),
        ..LogSource::default()
    };
    for field in ["Channel", "winlog.channel"] {
        if let Some(channel) = most(field) {
            let service = match channel.to_lowercase().as_str() {
                "security" => Some("security"),
                "system" => Some("system"),
                "application" => Some("application"),
                "microsoft-windows-sysmon/operational" => Some("sysmon"),
                "windows powershell" => Some("powershell-classic"),
                "microsoft-windows-powershell/operational" => Some("powershell"),
                _ => None,
            };
            if let Some(service) = service {
                return (windows(service), format!("`{field}` says {channel}"));
            }
        }
    }
    if let Some(table) = most("Type") {
        let found = match table.as_str() {
            "SecurityEvent" => Some(windows("security")),
            "Syslog" => Some(LogSource {
                product: Some("linux".to_owned()),
                ..LogSource::default()
            }),
            "CommonSecurityLog" => Some(LogSource {
                category: Some("firewall".to_owned()),
                ..LogSource::default()
            }),
            _ => None,
        };
        if let Some(logsource) = found {
            return (logsource, format!("the Sentinel table {table}"));
        }
    }
    if let Some(dataset) = most("event.dataset")
        && let Some((product, service)) = dataset.split_once('.')
    {
        return (
            LogSource {
                product: Some(product.to_lowercase()),
                service: Some(service.to_lowercase()),
                ..LogSource::default()
            },
            format!("`event.dataset` says {dataset}"),
        );
    }
    if let Some(module) = most("event.module") {
        return (
            LogSource {
                product: Some(module.to_lowercase()),
                ..LogSource::default()
            },
            format!("`event.module` says {module}"),
        );
    }
    if most("eventSource").is_some() && most("awsRegion").is_some() {
        return (
            LogSource {
                product: Some("aws".to_owned()),
                service: Some("cloudtrail".to_owned()),
                ..LogSource::default()
            },
            "the fields of AWS CloudTrail".to_owned(),
        );
    }
    (
        LogSource::default(),
        "no field names its product: fill in its logsource".to_owned(),
    )
}

/// The share of `records` for which `test` holds, in percent.
fn share(records: &[Map<String, Value>], test: impl Fn(&Map<String, Value>) -> bool) -> usize {
    records.iter().filter(|r| test(r)).count() * 100 / records.len().max(1)
}

/// The string at a dotted `path`, following nested objects.
fn text_at<'a>(record: &'a Map<String, Value>, path: &str) -> Option<&'a str> {
    let mut segments = path.split('.');
    let mut value = record.get(segments.next()?)?;
    for segment in segments {
        value = value.as_object()?.get(segment)?;
    }
    value.as_str().filter(|s| !s.is_empty())
}

/// Every leaf path of `record`, nested objects joined with dots.
fn paths(record: &Map<String, Value>, prefix: &str) -> Vec<String> {
    record
        .iter()
        .flat_map(|(key, value)| {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            match value {
                Value::Object(inner) => paths(inner, &path),
                _ => vec![path],
            }
        })
        .collect()
}

/// The sources file: each source with the notes on how it was proposed above it.
fn yaml(proposals: &[Proposal]) -> String {
    let mut out = String::from(
        "# Proposed by `sluice init` from the sample. Check every source: a wrong `schema` or\n\
         # `logsource` is the mistake the proof cannot notice (docs/guide.md, \"Describing your\n\
         # sources\").\n\
         sources:\n",
    );
    for proposal in proposals {
        for note in &proposal.notes {
            let _ = writeln!(out, "  # {note}");
        }
        let _ = writeln!(out, "  - id: {}", scalar(&proposal.id));
        let _ = writeln!(out, "    logsource: {}", logsource(&proposal.logsource));
        match &proposal.text {
            None => out.push_str("    format: { kind: json }\n"),
            Some((field, parser)) => {
                let parser = parser
                    .as_ref()
                    .map_or_else(String::new, |p| format!(", parser: {}", scalar(p)));
                let _ = writeln!(
                    out,
                    "    format: {{ kind: text, field: {}{parser} }}",
                    scalar(field)
                );
            }
        }
        let _ = writeln!(out, "    schema: {}", proposal.schema);
    }
    out
}

fn logsource(logsource: &LogSource) -> String {
    let parts: Vec<String> = [
        ("product", &logsource.product),
        ("service", &logsource.service),
        ("category", &logsource.category),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_ref().map(|v| format!("{key}: {}", scalar(v))))
    .collect();
    format!("{{ {} }}", parts.join(", "))
}

/// `text` as a YAML scalar: plain when it is safe, quoted otherwise.
fn scalar(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
    if plain {
        text.to_owned()
    } else {
        serde_json::Value::String(text.to_owned()).to_string()
    }
}

#[cfg(test)]
mod tests;
