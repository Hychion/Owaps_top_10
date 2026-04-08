use std::{fs, path::Path};

use colored::Colorize;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use thiserror::Error;

use crate::core::models::{Report, Severity};

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("I/O error writing report: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Supported output formats.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Html,
}

/// Render and optionally persist a [`Report`].
pub struct Reporter;

impl Reporter {
    /// Print a formatted table to stdout.
    pub fn print_terminal(report: &Report) {
        let total = report.finding_count();
        println!(
            "\n{} {} findings on {}\n",
            "OWASP Tester".bold(),
            total.to_string().yellow().bold(),
            report.target.cyan()
        );

        if total == 0 {
            println!("{}", "No findings.".green());
            return;
        }

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec!["OTG ID", "Severity", "Title", "URL"]);

        for f in &report.findings {
            let severity_cell = match f.severity {
                Severity::Critical => Cell::new(&f.severity).fg(Color::Magenta),
                Severity::High => Cell::new(&f.severity).fg(Color::Red),
                Severity::Medium => Cell::new(&f.severity).fg(Color::Yellow),
                Severity::Low => Cell::new(&f.severity).fg(Color::Cyan),
                Severity::Info => Cell::new(&f.severity).fg(Color::White),
            };
            table.add_row(vec![
                Cell::new(&f.top10_id),
                severity_cell,
                Cell::new(&f.title),
                Cell::new(&f.url),
            ]);
        }
        println!("{table}");
    }

    /// Serialize the report as pretty-printed JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialization or file I/O fails.
    pub fn write_json(report: &Report, output: &Path) -> Result<(), ReportError> {
        let json = serde_json::to_string_pretty(report)?;
        fs::write(output, json)?;
        Ok(())
    }

    /// Generate a minimal HTML report.
    ///
    /// # Errors
    /// Returns an error if file I/O fails.
    pub fn write_html(report: &Report, output: &Path) -> Result<(), ReportError> {
        let rows: String = report
            .findings
            .iter()
            .map(|f| {
                let color = match f.severity {
                    Severity::Critical => "#9b59b6",
                    Severity::High => "#e74c3c",
                    Severity::Medium => "#f39c12",
                    Severity::Low => "#3498db",
                    Severity::Info => "#95a5a6",
                };
                format!(
                    "<tr>\
                        <td>{}</td>\
                        <td style='color:{color};font-weight:bold'>{}</td>\
                        <td>{}</td>\
                        <td><code>{}</code></td>\
                    </tr>",
                    f.top10_id, f.severity, f.title, f.url
                )
            })
            .collect();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>OWASP Tester Report — {target}</title>
  <style>
    body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 2rem; }}
    h1 {{ color: #ce9178; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #444; padding: 0.5rem 1rem; text-align: left; }}
    th {{ background: #2d2d2d; }}
    tr:nth-child(even) {{ background: #252525; }}
  </style>
</head>
<body>
  <h1>OWASP Tester Report</h1>
  <p>Target: <strong>{target}</strong> &mdash; Date: {date}</p>
  <table>
    <thead><tr><th>OTG ID</th><th>Severity</th><th>Title</th><th>URL</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"#,
            target = report.target,
            date = report.scan_date,
        );

        fs::write(output, html)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{Finding, Target};

    fn sample_report() -> Report {
        let target = Target::new("https://example.com").unwrap();
        let mut r = Report::new(&target);
        r.push(Finding {
            top10_id: "A05:2021".into(),
            title: "Security misconfiguration".into(),
            severity: Severity::Low,
            url: "https://example.com".into(),
            evidence: "Server: Apache/2.4.51".into(),
            remediation: "Remove Server header.".into(),
        });
        r
    }

    #[test]
    fn json_roundtrip() {
        let report = sample_report();
        let json = serde_json::to_string(&report).unwrap();
        let decoded: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.finding_count(), 1);
    }

    #[test]
    fn write_json_creates_file() {
        let report = sample_report();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        Reporter::write_json(&report, &path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_html_creates_file() {
        let report = sample_report();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.html");
        Reporter::write_html(&report, &path).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("A05:2021"));
    }
}
