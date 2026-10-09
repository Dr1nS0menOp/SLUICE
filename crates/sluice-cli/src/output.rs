//! Writing results and printing the summary.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use sluice_autopilot::Report;
use sluice_core::event::Event;
use sluice_core::source::Source;

pub(crate) fn write(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Writes a sample as `<dir>/<source>.ndjson` files, one JSON body per line.
pub(crate) fn samples(dir: &Path, sources: &[Source], events: &[Event]) -> Result<()> {
    for source in sources {
        let mut lines = String::new();
        for event in events.iter().filter(|e| e.source == source.id) {
            lines.push_str(&serde_json::to_string(&event.fields)?);
            lines.push('\n');
        }
        write(&dir.join(format!("{}.ndjson", source.id)), &lines)?;
    }
    Ok(())
}

/// Writes the sources file `sluice analyze --sources` reads.
pub(crate) fn sources(path: &Path, sources: &[Source]) -> Result<()> {
    #[derive(Serialize)]
    struct SourcesFile<'a> {
        sources: &'a [Source],
    }
    write(path, &serde_yaml_ng::to_string(&SourcesFile { sources })?)
}

pub(crate) fn summary(report: &Report, templates: usize, sources: usize) {
    let t = &report.total;
    println!(
        "{} events from {sources} sources, {templates} templates",
        group(t.events)
    );
    println!(
        "  ingest  {} → {}  ({:.1}% saved, {} events summarized)",
        mb(t.bytes_in),
        mb(t.bytes_out),
        report.saved_percent(),
        group(t.summarized)
    );
    let verdict = if report.proven {
        "✓ no detection changed"
    } else {
        "✗ DETECTIONS CHANGED"
    };
    println!(
        "  proof   {} alerts on full data, {} on forwarded data  {verdict}",
        report.alerts_full, report.alerts_forwarded
    );
    let rules: Vec<String> = report
        .rules
        .iter()
        .map(|(e, n)| format!("{n} {e}"))
        .collect();
    println!("  rules   {}", rules.join(", "));
    if let Some(check) = &report.spot_check {
        println!(
            "  siem    logtest compared {} events, rolled back {} templates",
            check.checked,
            check.rolled_back.len()
        );
    }
    if !report.coverage_gaps.is_empty() {
        println!(
            "  gaps    {} rules see no data in this sample",
            report.coverage_gaps.len()
        );
    }
    if !report.problems.is_empty() {
        println!("  issues  {} (see report)", report.problems.len());
    }
}

/// Bytes as megabytes with one decimal. Sample sizes are far below 2^52, so the conversion is
/// exact in practice.
#[allow(clippy::cast_precision_loss)]
fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
}

/// `80536` → `80,536`.
fn group(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_thousands() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(80_536), "80,536");
        assert_eq!(group(1_234_567), "1,234,567");
    }
}
