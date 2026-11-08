use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use rulebench::RuleSet;
use rulebench::coverage::{CoverageReport, analyze};
use rulebench::eve::read_eve;
use rulebench::report::{
    check_json, check_markdown, check_text, coverage_json, coverage_markdown, coverage_text,
};

/// Suricata rule validator and alert-coverage analyzer.
#[derive(Parser)]
#[command(name = "rulebench", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate rules: syntax, duplicate SIDs, and missing classtype.
    Check(CheckArgs),
    /// Cross-reference a ruleset with eve.json alerts: dead rules, noise, stale alerts.
    Coverage(CoverageArgs),
}

#[derive(Args)]
struct CheckArgs {
    /// Rule files or directories (directories are walked for *.rules).
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Maximum entries to list per section.
    #[arg(long, default_value_t = 10)]
    top: usize,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
    /// Emit Markdown.
    #[arg(long)]
    md: bool,
    /// Exit 1 also on warnings (duplicate SIDs, missing classtype, disabled conflicts).
    #[arg(long)]
    strict: bool,
}

#[derive(Args)]
struct CoverageArgs {
    /// Rule files or directories.
    #[arg(long = "rules", required = true, value_name = "PATH")]
    rules: Vec<PathBuf>,
    /// eve.json files (Suricata EVE JSON, one event per line).
    #[arg(long = "eve", required = true, value_name = "PATH")]
    eve: Vec<PathBuf>,
    /// Maximum entries to list per section.
    #[arg(long, default_value_t = 10)]
    top: usize,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
    /// Emit Markdown.
    #[arg(long)]
    md: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("rulebench: {err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Check(args) => run_check(args),
        Command::Coverage(args) => run_coverage(args),
    }
}

fn run_check(args: CheckArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if args.json && args.md {
        return Err("--json and --md are mutually exclusive".into());
    }
    let set = RuleSet::load(&args.paths)?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&check_json(&set, args.top))?
        );
    } else if args.md {
        print!("{}", check_markdown(&set, args.top));
    } else {
        print!("{}", check_text(&set, args.top));
    }

    let warnings = set.duplicate_sids().len()
        + set.conflicting_disabled().len()
        + set.missing_classtype().len();

    if !set.invalid.is_empty() || (args.strict && warnings > 0) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_coverage(args: CoverageArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if args.json && args.md {
        return Err("--json and --md are mutually exclusive".into());
    }
    let set = RuleSet::load(&args.rules)?;
    let eve = read_eve(&args.eve)?;
    let report: CoverageReport = analyze(&set, &eve, args.top);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&coverage_json(&report))?);
    } else if args.md {
        print!("{}", coverage_markdown(&report, args.top));
    } else {
        print!("{}", coverage_text(&report, args.top));
    }
    Ok(ExitCode::SUCCESS)
}
