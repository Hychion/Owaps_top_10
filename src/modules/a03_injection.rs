//! A03:2021 — Injection
//!
//! Tests:
//!   1. SQL Injection — error-based detection via query parameter fuzzing.
//!   2. Reflected XSS — unencoded payload echo in response body.
//!   3. Server-Side Template Injection (SSTI) — math expression evaluation probe.

use async_trait::async_trait;
use tracing::debug;

use crate::{
    core::{
        error::ScanError,
        models::{Finding, Severity, Target},
        session::Session,
    },
    modules::base::{OwaspModule, Top10Id},
};

// ── SQLi ─────────────────────────────────────────────────────────────────────

/// Error messages that indicate an SQL error was triggered.
const SQLI_ERROR_SIGNATURES: &[&str] = &[
    "sql syntax",
    "mysql_fetch",
    "ora-01756",
    "sqlite3.operationalerror",
    "pg::syntaxerror",
    "unclosed quotation mark",
    "you have an error in your sql",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "postgresql query failed",
    "db error",
];

const SQLI_PROBES: &[&str] = &["'", "''", "`", "' OR '1'='1", "\" OR 1=1--", "' AND 1=2--"];

// ── XSS ──────────────────────────────────────────────────────────────────────

const XSS_PROBES: &[&str] = &[
    "<owasp-xss-probe>",
    "\"owasp-xss-probe\"",
    "'owasp-xss-probe'",
];

// ── SSTI ─────────────────────────────────────────────────────────────────────

/// Probes that evaluate to a known numeric result in common template engines.
/// Jinja2/Twig: {{7*7}} → 49 | Freemarker: ${7*7} → 49
const SSTI_PROBES: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
];

pub struct A03Injection;

#[async_trait]
impl OwaspModule for A03Injection {
    fn top10_id(&self) -> Top10Id { Top10Id::A03 }

    fn name(&self) -> &'static str {
        "Injection"
    }

    fn description(&self) -> &'static str {
        "SQL injection (error-based), reflected XSS, Server-Side Template Injection (SSTI)"
    }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        let base = target.url.as_str().trim_end_matches('/');
        let mut findings: Vec<(Severity, String)> = Vec::new();

        // ── SQLi ──────────────────────────────────────────────────────────────
        for probe in SQLI_PROBES {
            let url = format!("{base}?id={}", urlencoding::encode(probe));
            debug!(url, "SQLi probe");
            let resp = session.client.get(&url).send().await?;
            let body = resp.text().await.unwrap_or_default().to_lowercase();
            if SQLI_ERROR_SIGNATURES.iter().any(|sig| body.contains(sig)) {
                findings.push((
                    Severity::Critical,
                    format!("SQL Injection: probe `{probe}` triggered DB error in response"),
                ));
                break;
            }
        }

        // ── XSS ───────────────────────────────────────────────────────────────
        for probe in XSS_PROBES {
            let url = format!("{base}?q={}", urlencoding::encode(probe));
            debug!(url, "XSS probe");
            let resp = session.client.get(&url).send().await?;
            let body = resp.text().await.unwrap_or_default();
            if body.contains(probe) {
                findings.push((
                    Severity::High,
                    format!("Reflected XSS: payload `{probe}` echoed unencoded in response"),
                ));
                break;
            }
        }

        // ── SSTI ──────────────────────────────────────────────────────────────
        for (probe, expected) in SSTI_PROBES {
            let url = format!("{base}?name={}", urlencoding::encode(probe));
            debug!(url, "SSTI probe");
            let resp = session.client.get(&url).send().await?;
            let body = resp.text().await.unwrap_or_default();
            if body.contains(expected) && !body.contains(probe) {
                findings.push((
                    Severity::Critical,
                    format!("SSTI: probe `{probe}` evaluated to `{expected}` — template engine executes user input"),
                ));
                break;
            }
        }

        if findings.is_empty() {
            return Ok(None);
        }

        let max_severity = findings
            .iter()
            .map(|(s, _)| s.clone())
            .max()
            .unwrap_or(Severity::Medium);

        let evidence = findings.into_iter().map(|(_, e)| e).collect::<Vec<_>>().join("\n");

        Ok(Some(Finding {
            top10_id: self.top10_id().to_string(),
            title: "Injection vulnerability detected".into(),
            severity: max_severity,
            url: base.into(),
            evidence,
            remediation: "Use parameterized queries / prepared statements for SQL. \
                          HTML-encode all user output. Disable or sandbox template engines \
                          from user input. Apply input validation and allowlisting."
                .into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path, query_param_contains},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn detects_sqli_error_in_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param_contains("id", "'"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string("You have an error in your SQL syntax near '''"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A03Injection.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.contains("SQL Injection"));
    }

    #[tokio::test]
    async fn detects_reflected_xss() {
        let server = MockServer::start().await;
        let probe = XSS_PROBES[0];
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param_contains("q", "owasp-xss-probe"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!("<html>Result: {probe}</html>")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A03Injection.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert!(f.evidence.contains("XSS"));
    }

    #[tokio::test]
    async fn detects_ssti_expression_evaluation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param_contains("name", "7*7"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<html>Hello 49</html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A03Injection.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert!(f.evidence.contains("SSTI"));
    }

    #[tokio::test]
    async fn no_finding_on_clean_app() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>clean</html>"))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A03Injection.run(&target, &session).await.unwrap();

        assert!(result.is_none());
    }
}
