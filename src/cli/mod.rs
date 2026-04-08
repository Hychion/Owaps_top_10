pub mod args;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Table};
use tracing::info;

use crate::{
    cli::args::{Command, ScanArgs},
    core::{
        models::Target,
        reporter::{OutputFormat, Reporter},
        scanner::Scanner,
        session::Session,
    },
    modules,
};

pub async fn run_scan(args: ScanArgs) -> Result<()> {
    // Validate target URL.
    let mut target =
        Target::new(&args.target).with_context(|| format!("Invalid target URL: {}", args.target))?;

    if let Some(token) = args.auth_token {
        target = target.with_auth(token);
    }

    // Select modules.
    let selected = if args.all {
        modules::all_modules()
    } else if !args.modules.is_empty() {
        let loaded = modules::modules_by_id(&args.modules);
        if loaded.is_empty() {
            bail!(
                "None of the specified module IDs matched. Run `owasp-tester list` to see available modules."
            );
        }
        loaded
    } else {
        bail!("Specify --all or at least one --modules ID.");
    };

    println!(
        "{} {} module(s) against {}",
        "Running".bold().green(),
        selected.len(),
        args.target.cyan()
    );

    let session = Session::new(target, 15, !args.insecure)
        .context("Failed to initialize HTTP session")?;

    let scanner = Scanner::new(session, selected, 5);
    let report = scanner.run().await;

    info!(findings = report.finding_count(), "Scan complete");

    match args.format {
        OutputFormat::Terminal => Reporter::print_terminal(&report),
        OutputFormat::Json => {
            let path = require_output(args.output)?;
            Reporter::write_json(&report, &path)
                .with_context(|| format!("Failed to write JSON to {}", path.display()))?;
            println!("Report written to {}", path.display());
        }
        OutputFormat::Html => {
            let path = require_output(args.output)?;
            Reporter::write_html(&report, &path)
                .with_context(|| format!("Failed to write HTML to {}", path.display()))?;
            println!("Report written to {}", path.display());
        }
    }

    Ok(())
}

pub fn run_list() {
    let all = modules::all_modules();
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec!["OWASP Top 10 ID", "Name", "Description"]);

    for m in &all {
        table.add_row(vec![
            m.top10_id().to_string().as_str(),
            m.name(),
            m.description(),
        ]);
    }

    println!("\n{table}\n");
    println!("Total: {} module(s)", all.len());
}

fn require_output(output: Option<PathBuf>) -> Result<PathBuf> {
    output.ok_or_else(|| {
        anyhow::anyhow!("--output <FILE> is required when using json or html format")
    })
}

pub async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Scan(args) => run_scan(args).await,
        Command::List => {
            run_list();
            Ok(())
        }
    }
}
