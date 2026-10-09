//! `sluice`: open-source autopilot for security data.

// Printing to the terminal is this binary's job.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod ai;
mod archive;
mod cli;
mod commands;
mod connect;
mod input;
mod live;
mod output;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Demo(args) => commands::demo(&args),
        Command::Analyze(args) => commands::analyze(&args),
        Command::Recipes(args) => commands::recipes(&args),
        Command::Rules(args) => commands::rules(&args),
        Command::Up(args) => live::up(&args),
        Command::Status(args) => live::status(&args),
        Command::Search(args) => archive::search(&args),
        Command::Replay(args) => archive::replay(&args),
        Command::Connect(args) => connect::connect(&args),
        Command::Mcp(args) => live::mcp(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
