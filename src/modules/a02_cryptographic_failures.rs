//! A02:2021 — Cryptographic Failures
//!
//! Tests:
//!   1. HTTP used instead of HTTPS (plaintext transport).
//!   2. Missing or weak HSTS header (Strict-Transport-Security).
//!   3. Cookie missing Secure flag (sent over HTTP).
//!   4. Sensitive data patterns in URL query parameters (tokens, passwords).
//!   5. Missing security headers: X-Content-Type-Options, X-Frame-Options.

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

const SENSITIVE_PARAM_PATTERNS: &[&str] = &[
    "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
    "auth", "access_token", "refresh_token", "session",
];

pub struct A02CryptographicFailures;

#[async_trait]
impl OwaspModule for A02CryptographicFailures {
    fn top10_id(&self) -> Top10Id { Top10Id::A02 }

    fn name(&self) -> &'static str {
        "Cryptographic Failures"
    }

    fn description(&self) -> &'static str {
        "HTTP instead of HTTPS, missing HSTS, insecure cookies, sensitive data in URLs"
    }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        let url = target.url.as_str();
        let mut issues: Vec<String> = Vec::new();
        let mut max_severity = Severity::Low;

        // ── 1. HTTP scheme ────────────────────────────────────────────────────
        if target.url.scheme() == "http" {
            issues.push("Transport: target uses HTTP (plaintext) instead of HTTPS".into());
            max_severity = Severity::High;
        }

        // ── 2. Sensitive data in query string ─────────────────────────────────
        if let Some(query) = target.url.query() {
            let lower = query.to_lowercase();
            for pattern in SENSITIVE_PARAM_PATTERNS {
                if lower.contains(pattern) {
                    issues.push(format!(
                        "Sensitive parameter `{pattern}` found in URL query string"
                    ));
                    max_severity = Severity::High;
                }
            }
        }

        debug!(url, "Fetching response headers for crypto checks");
        let resp = session.client.get(url).send().await?;
        let headers = resp.headers();

        // ── 3. HSTS header ────────────────────────────────────────────────────
        match headers.get("strict-transport-security") {
            None => {
                issues.push("Missing Strict-Transport-Security (HSTS) header".into());
                if max_severity < Severity::Medium { max_severity = Severity::Medium; }
            }
            Some(val) => {
                let hsts = val.to_str().unwrap_or("");
                // max-age should be at least 6 months (15768000 seconds)
                if let Some(age) = extract_max_age(hsts) {
                    if age < 15_768_000 {
                        issues.push(format!(
                            "HSTS max-age too short: {age}s (minimum recommended: 15768000s)"
                        ));
                        if max_severity < Severity::Low { max_severity = Severity::Low; }
                    }
                }
            }
        }

        // ── 4. Cookies missing Secure flag ────────────────────────────────────
        for val in headers.get_all("set-cookie").iter() {
            let raw = val.to_str().unwrap_or("");
            if !raw.to_lowercase().contains("secure") {
                issues.push(format!("Cookie without Secure flag: {raw}"));
                if max_severity < Severity::Medium { max_severity = Severity::Medium; }
            }
        }

        // ── 5. Missing security headers ───────────────────────────────────────
        let required_headers = [
            ("x-content-type-options", "Missing X-Content-Type-Options: nosniff"),
            ("x-frame-options", "Missing X-Frame-Options header (clickjacking risk)"),
        ];
        for (h, msg) in required_headers {
            if headers.get(h).is_none() {
                issues.push(msg.into());
                if max_severity < Severity::Low { max_severity = Severity::Low; }
            }
        }

        if issues.is_empty() {
            return Ok(None);
        }

        Ok(Some(Finding {
            top10_id: self.top10_id().to_string(),
            title: "Cryptographic Failures — data exposed or weakly protected".into(),
            severity: max_severity,
            url: url.into(),
            evidence: issues.join("\n"),
            remediation: "Enforce HTTPS everywhere. Set HSTS with max-age ≥ 15768000. \
                          Mark all cookies Secure. Never pass sensitive values in URLs. \
                          Add X-Content-Type-Options and X-Frame-Options headers."
                .into(),
        }))
    }
}

fn extract_max_age(hsts: &str) -> Option<u64> {
    for part in hsts.split(';') {
        let trimmed = part.trim().to_lowercase();
        if let Some(val) = trimmed.strip_prefix("max-age=") {
            return val.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn detects_http_scheme() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // MockServer uses HTTP by default
        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A02CryptographicFailures.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert!(f.evidence.contains("plaintext"));
    }

    #[tokio::test]
    async fn detects_missing_hsts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A02CryptographicFailures.run(&target, &session).await.unwrap();

        let f = result.unwrap();
        assert!(f.evidence.contains("HSTS"));
    }

    #[tokio::test]
    async fn detects_insecure_cookie() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("Set-Cookie", "session=abc; Path=/"),
            )
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A02CryptographicFailures.run(&target, &session).await.unwrap();

        let f = result.unwrap();
        assert!(f.evidence.to_lowercase().contains("cookie"));
    }

    #[tokio::test]
    async fn detects_sensitive_param_in_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let raw = format!("{}?token=supersecret", server.uri());
        let target = Target::new(&raw).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A02CryptographicFailures.run(&target, &session).await.unwrap();

        let f = result.unwrap();
        assert!(f.evidence.contains("token"));
    }

    #[test]
    fn extract_max_age_parses_correctly() {
        assert_eq!(extract_max_age("max-age=31536000; includeSubDomains"), Some(31_536_000));
        assert_eq!(extract_max_age("max-age=0"), Some(0));
        assert_eq!(extract_max_age("includeSubDomains"), None);
    }
}
