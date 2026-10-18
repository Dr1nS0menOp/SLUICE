//! `sluice`: finds what a SIEM can stop ingesting without changing a detection, and writes the
//! configuration that does it.

// Printing to the terminal is this binary's job.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod ai;
mod cli;
mod commands;
mod connect;
mod engines;
mod input;
mod inventory;
mod native;
mod output;
mod prove;
mod recipes;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Demo(args) => commands::demo(&args),
        Command::Analyze(args) => commands::analyze(&args),
        Command::Recipes(args) => recipes::recipes(&args),
        Command::Rules(args) => commands::rules(&args),
        Command::Prove(args) => prove::prove(&args),
        Command::Connect(args) => connect::connect(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
