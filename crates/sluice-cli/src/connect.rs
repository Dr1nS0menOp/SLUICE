//! `sluice connect`: a destination block to paste into the `sluice up` configuration.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use sluice_vector::{CustomTable, Target};

use crate::cli::{ConnectArgs, ConnectTarget, StandardTable};

pub(crate) fn connect(args: &ConnectArgs) -> Result<()> {
    let target = match args.target {
        ConnectTarget::Splunk => Target::Splunk,
        ConnectTarget::Elastic => Target::Elastic,
        ConnectTarget::Sentinel => Target::Sentinel,
        ConnectTarget::Chronicle => Target::Chronicle,
        ConnectTarget::Wazuh => Target::Wazuh,
        ConnectTarget::Http => Target::Http,
    };
    let endpoint = args
        .endpoint
        .as_deref()
        .unwrap_or_else(|| target.example_endpoint());
    let name = args.name.as_deref().unwrap_or_else(|| target.name());
    let mut destinations = target.destinations(name, endpoint);
    let table = custom_table(args, target)?;
    if let Some(table) = &table {
        destinations[name]["stream_name"] = json!(table.stream_name());
    }
    if let Some(table) = args.standard_table {
        let stream = standard_table_dcr(args, target, table)?;
        destinations[name]["stream_name"] = json!(stream);
    }
    let mut config = json!({ "destinations": destinations });
    if let Some((backend, settings)) = target.secret_backend() {
        config["vector_secrets"] = json!({ backend: settings });
    }
    let yaml = serde_yaml_ng::to_string(&config)?;

    // Everything is YAML, the notes as comments, so the output can be appended to a config.
    println!(
        "# `sluice connect {}`: add to your `sluice up` configuration.",
        target.name()
    );
    if args.endpoint.is_none() {
        println!("# Replace the placeholder endpoint (or pass --endpoint).");
    }
    if let Some((_, settings)) = target.secret_backend() {
        println!(
            "# Secrets (never in this file): one file each in {}, readable only by the user \
             running Sluice: {}",
            settings["path"].as_str().unwrap_or_default(),
            target.secrets().join(", ")
        );
    }
    for line in target.notes(endpoint).lines() {
        println!("# {line}");
    }
    if let (Some(table), Some(out)) = (&table, &args.out) {
        println!(
            "# Create the table {} from {}/{}.table.json, then the data collection rule from \
             {}/{}.dcr.json; set `dcr_immutable_id` and the endpoint from the rule. {} columns.",
            table.table_name(),
            out.display(),
            table.table_name(),
            out.display(),
            args.table.as_deref().unwrap_or_default(),
            table.columns().len()
        );
    }
    print!("{yaml}");
    Ok(())
}

/// With `--standard-table`, writes the data collection rule that stores records of that shape
/// in the table. Returns the stream to send them to.
fn standard_table_dcr(
    args: &ConnectArgs,
    target: Target,
    table: StandardTable,
) -> Result<&'static str> {
    if target != Target::Sentinel {
        bail!(
            "--standard-table writes a Sentinel data collection rule; it only applies to `sentinel`"
        );
    }
    let out = args
        .out
        .as_deref()
        .context("--standard-table needs --out")?;
    let (file, shape, stream, dcr) = match table {
        StandardTable::Syslog => (
            "Syslog.dcr.json",
            "sentinel_syslog",
            sluice_vector::syslog::SYSLOG_STREAM,
            sluice_vector::syslog::syslog_dcr(&args.location, workspace(args)),
        ),
        StandardTable::CommonSecurityLog => (
            "CommonSecurityLog.dcr.json",
            "sentinel_common_security_log",
            sluice_vector::common_security_log::COMMON_SECURITY_LOG_STREAM,
            sluice_vector::common_security_log::common_security_log_dcr(
                &args.location,
                workspace(args),
            ),
        ),
        StandardTable::AsimNetworkSession => (
            "ASimNetworkSessionLogs.dcr.json",
            "sentinel_asim_network_session",
            sluice_vector::asim_network_session::ASIM_NETWORK_SESSION_STREAM,
            sluice_vector::asim_network_session::asim_network_session_dcr(
                &args.location,
                workspace(args),
            ),
        ),
    };
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let path = out.join(file);
    std::fs::write(&path, serde_json::to_string_pretty(&dcr)? + "\n")
        .with_context(|| format!("writing {}", path.display()))?;
    println!(
        "# Create the data collection rule from {}; set `dcr_immutable_id` and the endpoint \
         from it. Give the sources `shape: {shape}`.",
        path.display()
    );
    Ok(stream)
}

/// The workspace resource ID given, or a placeholder.
fn workspace(args: &ConnectArgs) -> &str {
    args.workspace.as_deref().unwrap_or(
        "/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.OperationalInsights/workspaces/<workspace>",
    )
}

/// With `--sample`, derives the Sentinel custom table and writes it and its DCR to `--out`.
fn custom_table(args: &ConnectArgs, target: Target) -> Result<Option<CustomTable>> {
    let (Some(sample), Some(table), Some(out)) = (&args.sample, &args.table, &args.out) else {
        return Ok(None);
    };
    if target != Target::Sentinel {
        bail!("--sample derives a Sentinel custom table; it only applies to `sentinel`");
    }
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
    let workspace = workspace(args);
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let write = |file: String, value: &Value| -> Result<()> {
        let path = out.join(file);
        std::fs::write(&path, serde_json::to_string_pretty(value)? + "\n")
            .with_context(|| format!("writing {}", path.display()))
    };
    write(
        format!("{}.table.json", custom.table_name()),
        &custom.table(),
    )?;
    write(
        format!("{table}.dcr.json"),
        &custom.dcr(&args.location, workspace, args.time_field.as_deref()),
    )?;
    Ok(Some(custom))
}
