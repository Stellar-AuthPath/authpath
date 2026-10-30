//! Offline command-line entry point for Stellar AuthPath.
//!
//! The command implementations are added in focused units. Argument parsing
//! is kept separate from the model and analysis crates so those crates remain
//! usable without a CLI or file-system dependency.

use std::{path::PathBuf, process};

use clap::{Parser, Subcommand, ValueEnum};

mod error;
mod input;
mod output;
mod report;

use error::{AppError, EXIT_SUCCESS};

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
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(error.exit_code());
        }
    }
}

fn run(cli: Cli) -> Result<i32, AppError> {
    let Cli {
        format,
        output,
        force,
        command,
    } = cli;

    match command {
        Command::Inspect { input } => {
            let snapshot = input::load_account(&input)?;
            let text = match format {
                OutputFormat::Human => report::render_inspect(&snapshot),
                OutputFormat::Json => {
                    output::json(&report::AccountFileJson::from_model(&snapshot))?
                }
            };
            output::write(&text, output.as_deref(), force)?;
            Ok(EXIT_SUCCESS)
        }
        Command::Analyze { input } => {
            let plan = input::load_plan(&input)?;
            let analysis = authpath_analysis::rotation::analyze_rotation(&plan);
            let document = report::AnalysisReportJson::from_model(&analysis);
            let text = match format {
                OutputFormat::Human => report::render_analysis(&document),
                OutputFormat::Json => output::json(&document)?,
            };
            output::write(&text, output.as_deref(), force)?;
            Ok(analysis_exit_code(analysis.classification()))
        }
        Command::Explain { input } => {
            let report = report::load_report(&input)?;
            let explanation = report::render_explanation(&report);
            let text = match format {
                OutputFormat::Human => report::render_human_explanation(&explanation),
                OutputFormat::Json => output::json(&explanation)?,
            };
            output::write(&text, output.as_deref(), force)?;
            Ok(analysis_exit_code(report::parse_report_classification(
                &report.classification,
            )?))
        }
        Command::Verify { .. } => Err(AppError::operational(
            "verify is implemented in a later C4 unit",
        )),
    }
}

fn analysis_exit_code(classification: authpath_analysis::rotation::SafetyClassification) -> i32 {
    match classification {
        authpath_analysis::rotation::SafetyClassification::SupportedReachable => EXIT_SUCCESS,
        authpath_analysis::rotation::SafetyClassification::Inconclusive => error::EXIT_INCONCLUSIVE,
        authpath_analysis::rotation::SafetyClassification::LockoutRisk
        | authpath_analysis::rotation::SafetyClassification::InvalidTransition
        | authpath_analysis::rotation::SafetyClassification::Blocked => error::EXIT_FINDING,
    }
}
