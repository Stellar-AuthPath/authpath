//! Offline command-line entry point for Stellar AuthPath.
//!
//! The command implementations are added in focused units. Argument parsing
//! is kept separate from the model and analysis crates so those crates remain
//! usable without a CLI or file-system dependency.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "authpath",
    version,
    about = "Offline inspection and conditional Stellar authorization analysis"
)]
struct Cli {
    /// Select terminal or machine-readable output.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
    /// Atomically install output at this path instead of writing it to stdout.
    #[arg(long, global = true, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Permit replacing an existing output file.
    #[arg(long, global = true)]
    force: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect one validated account snapshot JSON document.
    Inspect {
        /// The local account snapshot file.
        input: PathBuf,
    },
    /// Analyze one versioned rotation-plan JSON document.
    Analyze {
        /// The local rotation-plan file.
        input: PathBuf,
    },
    /// Explain one previously generated AuthPath analysis report.
    Explain {
        /// The local analysis-report file.
        input: PathBuf,
    },
    /// Compare a modeled report configuration with an observed snapshot.
    Verify {
        /// The local AuthPath analysis-report file.
        #[arg(long)]
        report: PathBuf,
        /// The independently supplied observed-configuration file.
        #[arg(long)]
        observed: PathBuf,
    },
}

fn main() {
    let _ = Cli::parse();
}
