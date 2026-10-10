//! `sluice connect`: a destination block to paste into the `sluice up` configuration.

use anyhow::Result;
use serde_json::json;
use sluice_vector::Target;

use crate::cli::{ConnectArgs, ConnectTarget};

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
    let destinations = target.destinations(name, endpoint);
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
    print!("{yaml}");
    Ok(())
}
