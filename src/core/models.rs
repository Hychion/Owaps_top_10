use serde::{Deserialize, Serialize};
use url::Url;

/// Severity level of a finding, following OWASP risk rating conventions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        };
        write!(f, "{s}")
    }
}

/// The target of a scan — validated URL with optional auth context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub url: Url,
    /// Optional bearer token or session cookie for authenticated scans.
    pub auth_token: Option<String>,
}

impl Target {
    /// Create a new Target from a URL string.
    ///
    /// # Errors
    /// Returns an error if the URL is invalid or uses an unsupported scheme.
    pub fn new(raw_url: &str) -> Result<Self, url::ParseError> {
        let url = Url::parse(raw_url)?;
        Ok(Self { url, auth_token: None })
    }

    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

/// A single vulnerability or observation produced by an OWASP Top 10 module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// OWASP Top 10 ID, e.g. "A01:2021".
    pub top10_id: String,
    /// Human-readable title.
    pub title: String,
    /// Severity rating.
    pub severity: Severity,
    /// URL where the issue was observed.
    pub url: String,
    /// Technical evidence: HTTP response snippet, payload used, etc.
    pub evidence: String,
    /// Remediation recommendation.
    pub remediation: String,
}

/// Aggregated result of a complete scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub scan_date: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(target: &Target) -> Self {
        Self {
            target: target.url.to_string(),
            scan_date: chrono_now(),
            findings: Vec::new(),
        }
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

fn chrono_now() -> String {
    // Use std only — avoids pulling in chrono for a simple timestamp.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_new_valid_url() {
        let t = Target::new("https://example.com").unwrap();
        assert_eq!(t.url.host_str(), Some("example.com"));
    }

    #[test]
    fn target_new_invalid_url() {
        assert!(Target::new("not a url").is_err());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Info < Severity::Low);
    }

    #[test]
    fn report_push_finding() {
        let target = Target::new("https://example.com").unwrap();
        let mut report = Report::new(&target);
        report.push(Finding {
            top10_id: "A05:2021".into(),
            title: "Test".into(),
            severity: Severity::Info,
            url: "https://example.com".into(),
            evidence: "Missing CSP header".into(),
            remediation: "Add Content-Security-Policy header.".into(),
        });
        assert_eq!(report.finding_count(), 1);
    }
}
