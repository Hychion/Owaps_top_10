use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

mod cli;
mod core;
mod modules;

use cli::args::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing based on verbosity flag.
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .compact()
        .init();

    cli::dispatch(cli.command).await
}
