//! `sluice connect`: a destination block to paste into the `sluice up` configuration.

use anyhow::Result;
use serde_json::{Map, json};
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
    let mut destinations = Map::new();
    destinations.insert(name.to_owned(), target.sink(endpoint));
    let yaml = serde_yaml_ng::to_string(&json!({ "destinations": destinations }))?;

    // Everything is YAML, the notes as comments, so the output can be appended to a config.
    println!(
        "# `sluice connect {}`: add to your `sluice up` configuration.",
        target.name()
    );
    if args.endpoint.is_none() {
        println!("# Replace the placeholder endpoint (or pass --endpoint).");
    }
    if !target.secrets().is_empty() {
        println!(
            "# Set for Vector's environment (never in this file): {}",
            target.secrets().join(", ")
        );
    }
    for line in target.notes(endpoint).lines() {
        println!("# {line}");
    }
    print!("{yaml}");
    Ok(())
}
