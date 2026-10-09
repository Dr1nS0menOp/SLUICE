//! `sluice`: open-source autopilot for security data.

use clap::Parser;

/// Shrink SIEM ingest without changing a single detection.
#[derive(Debug, Parser)]
#[command(name = "sluice", version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
