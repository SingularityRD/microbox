mod args;
mod bench;
mod config;
mod doctor;
mod runner;
mod validate;
mod workspace;

use args::{Cli, Commands};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Run(args) => match runner::run(args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("microbox: {}", error);
                if matches!(error, microbox_core::SandboxError::TimedOut) {
                    124
                } else {
                    1
                }
            }
        },
        Commands::Validate(args) => match validate::run(args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("microbox: {}", error);
                1
            }
        },
        Commands::Bench(args) => match bench::run(args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("microbox: {}", error);
                1
            }
        },
        Commands::Doctor(args) => match doctor::run(args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("microbox: {}", error);
                1
            }
        },
        Commands::Workspace(args) => match workspace::run(args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("microbox: {}", error);
                1
            }
        },
    };

    std::process::exit(code);
}
