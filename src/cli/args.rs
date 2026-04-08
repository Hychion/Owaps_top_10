use clap::{Args, Parser, Subcommand};

use crate::core::reporter::OutputFormat;

#[derive(Debug, Parser)]
#[command(
    name = "owasp-tester",
    version,
    author,
    about = "Automated OWASP Testing Guide tool for authorized security assessments",
    long_about = None,
)]
pub struct Cli {
    /// Increase verbosity (use multiple times: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run OWASP test modules against a target
    Scan(ScanArgs),

    /// List all available OWASP test modules
    List,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Target URL (must be authorized for testing)
    #[arg(short, long)]
    pub target: String,

    /// Run all available modules
    #[arg(long, conflicts_with = "modules")]
    pub all: bool,

    /// Comma-separated list of module IDs to run (e.g. OTG-INFO-001,OTG-SESS-001)
    #[arg(short, long, value_delimiter = ',', conflicts_with = "all")]
    pub modules: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Output file path (required for json/html formats)
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,

    /// Bearer token or session cookie for authenticated scans
    #[arg(long)]
    pub auth_token: Option<String>,

    /// Skip TLS certificate verification (use only on internal labs)
    #[arg(long, default_value = "false")]
    pub insecure: bool,
}
