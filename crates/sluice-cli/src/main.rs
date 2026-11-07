//! `sluice`: finds what a SIEM can stop ingesting without changing a detection, and writes the
//! configuration that does it.

// Printing to the terminal is this binary's job; standard output goes through `stdout::out!`.
#![allow(clippy::print_stderr)]

mod ai;
mod cli;
mod commands;
mod connect;
mod engines;
mod input;
mod inventory;
mod mcp;
mod native;
mod output;
mod prove;
mod recipes;
mod stdout;
mod verify;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Verify(args) => {
            return match verify::verify(&args) {
                Ok(sluice_autopilot::Verdict::Holds) => ExitCode::SUCCESS,
                Ok(sluice_autopilot::Verdict::OutOfDate) => ExitCode::from(verify::OUT_OF_DATE),
                Ok(sluice_autopilot::Verdict::DoesNotHold) => ExitCode::FAILURE,
                Err(error) => {
                    eprintln!("error: {error:#}");
                    ExitCode::FAILURE
                }
            };
        }
        Command::Demo(args) => commands::demo(&args),
        Command::Analyze(args) => commands::analyze(&args),
        Command::Recipes(args) => recipes::recipes(&args),
        Command::Rules(args) => commands::rules(&args),
        Command::Prove(args) => prove::prove(&args),
        Command::Connect(args) => connect::connect(&args),
        Command::Mcp(args) => mcp::mcp(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
