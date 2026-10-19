//! `sluice connect sentinel`: the Microsoft Sentinel tables and data collection rules a source
//! needs, as JSON files to create in Azure.

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_vector::CustomTable;
use sluice_vector::summary_table::{SUMMARY_COUNTS, SUMMARY_TABLE, summary_dcr, summary_table};

use crate::cli::{ConnectArgs, ConnectTarget};

pub(crate) fn connect(args: &ConnectArgs) -> Result<()> {
    let ConnectTarget::Sentinel = args.target;
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("creating {}", args.out.display()))?;
    let mut wrote = false;
    if let Some(table) = custom_table(args)? {
        println!(
            "Create the table {} from {}, then the data collection rule from {} ({} columns).",
            table.table_name(),
            args.out
                .join(format!("{}.table.json", table.table_name()))
                .display(),
            args.out
                .join(format!(
                    "{}.dcr.json",
                    args.table.as_deref().unwrap_or_default()
                ))
                .display(),
            table.columns().len()
        );
        wrote = true;
    }
    if args.summary_table {
        write_summary_table(args)?;
        wrote = true;
    }
    if !wrote {
        bail!("nothing to write: give --sample and --table, or --summary-table");
    }
    Ok(())
}

/// With `--summary-table`, writes the summary table, its data collection rule and the
/// `SluiceCounts` function.
fn write_summary_table(args: &ConnectArgs) -> Result<()> {
    let out = &args.out;
    write_json(
        &out.join(format!("{SUMMARY_TABLE}.table.json")),
        &summary_table(),
    )?;
    write_json(
        &out.join("SluiceSummary.dcr.json"),
        &summary_dcr(&args.location, workspace(args)),
    )?;
    crate::output::write(&out.join("SluiceCounts.kql"), SUMMARY_COUNTS)?;
    println!(
        "Summaries: create {SUMMARY_TABLE} from {0}/{SUMMARY_TABLE}.table.json and the rule \
         from {0}/SluiceSummary.dcr.json, and save {0}/SluiceCounts.kql as the workspace \
         function SluiceCounts (ADR 0029).",
        out.display()
    );
    Ok(())
}

/// The workspace resource ID given, or a placeholder.
fn workspace(args: &ConnectArgs) -> &str {
    args.workspace.as_deref().unwrap_or(
        "/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.OperationalInsights/workspaces/<workspace>",
    )
}

/// With `--sample`, derives the custom table and writes it and its data collection rule.
fn custom_table(args: &ConnectArgs) -> Result<Option<CustomTable>> {
    let (Some(sample), Some(table)) = (&args.sample, &args.table) else {
        return Ok(None);
    };
    let text =
        std::fs::read_to_string(sample).with_context(|| format!("reading {}", sample.display()))?;
    // Editors on Windows write a byte order mark; it is not part of the first record.
    let records: Vec<Map<String, Value>> = text
        .trim_start_matches('\u{feff}')
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(n, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("{} line {}: not a JSON object", sample.display(), n + 1))
        })
        .collect::<Result<_>>()?;
    let custom = CustomTable::infer(table, &records)?;
    write_json(
        &args.out.join(format!("{}.table.json", custom.table_name())),
        &custom.table(),
    )?;
    write_json(
        &args.out.join(format!("{table}.dcr.json")),
        &custom.dcr(&args.location, workspace(args), args.time_field.as_deref()),
    )?;
    Ok(Some(custom))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    crate::output::write(path, &(serde_json::to_string_pretty(value)? + "\n"))
}
