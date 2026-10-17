//! `sluice connect sentinel`: the Microsoft Sentinel tables and data collection rules a source
//! needs, as JSON files to create in Azure.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sluice_vector::CustomTable;
use sluice_vector::summary_table::{SUMMARY_COUNTS, SUMMARY_TABLE, summary_dcr, summary_table};

use crate::cli::{ConnectArgs, ConnectTarget, StandardTable};

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
    if let Some(table) = args.standard_table {
        let (path, shape) = standard_table_dcr(args, table)?;
        println!(
            "Create the data collection rule from {}; records sent to it must be shaped as \
             `{shape}`.",
            path.display()
        );
        wrote = true;
    }
    if args.summary_table {
        write_summary_table(args)?;
        wrote = true;
    }
    if !wrote {
        bail!("nothing to write: give --sample and --table, --standard-table, or --summary-table");
    }
    Ok(())
}

/// With `--standard-table`, writes the data collection rule that stores records of that shape
/// in the table. Returns the file and the shape.
fn standard_table_dcr(args: &ConnectArgs, table: StandardTable) -> Result<(PathBuf, &'static str)> {
    let (file, shape, dcr) = match table {
        StandardTable::Syslog => (
            "Syslog.dcr.json",
            "sentinel_syslog",
            sluice_vector::syslog::syslog_dcr(&args.location, workspace(args)),
        ),
        StandardTable::CommonSecurityLog => (
            "CommonSecurityLog.dcr.json",
            "sentinel_common_security_log",
            sluice_vector::common_security_log::common_security_log_dcr(
                &args.location,
                workspace(args),
            ),
        ),
        StandardTable::AsimNetworkSession => (
            "ASimNetworkSessionLogs.dcr.json",
            "sentinel_asim_network_session",
            sluice_vector::asim_network_session::asim_network_session_dcr(
                &args.location,
                workspace(args),
            ),
        ),
        StandardTable::AsimDns => (
            "ASimDnsActivityLogs.dcr.json",
            "sentinel_asim_dns",
            sluice_vector::asim_dns::asim_dns_dcr(&args.location, workspace(args)),
        ),
        StandardTable::AsimWebSession => (
            "ASimWebSessionLogs.dcr.json",
            "sentinel_asim_web_session",
            sluice_vector::asim_web_session::asim_web_session_dcr(&args.location, workspace(args)),
        ),
    };
    let path = args.out.join(file);
    write_json(&path, &dcr)?;
    Ok((path, shape))
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
    write(&out.join("SluiceCounts.kql"), SUMMARY_COUNTS)?;
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
    let records: Vec<Map<String, Value>> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
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
    write(path, &(serde_json::to_string_pretty(value)? + "\n"))
}

fn write(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}
