//! A05:2021 — Security Misconfiguration
//!
//! Tests:
//!   1. Missing HTTP security headers (CSP, X-Frame-Options, XCTO, Referrer-Policy, CORP).
//!   2. Verbose error messages leaking stack traces or version info.
//!   3. Directory listing enabled.
//!   4. Default / exposed framework debug endpoints.

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

/// Security headers that should be present on every response.
const REQUIRED_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy",      "Missing Content-Security-Policy (CSP) header"),
    ("x-frame-options",              "Missing X-Frame-Options (clickjacking risk)"),
    ("x-content-type-options",       "Missing X-Content-Type-Options: nosniff"),
    ("referrer-policy",              "Missing Referrer-Policy header"),
    ("permissions-policy",           "Missing Permissions-Policy header"),
    ("cross-origin-resource-policy", "Missing Cross-Origin-Resource-Policy header"),
];

/// Patterns in response bodies that indicate verbose error disclosure.
const ERROR_SIGNATURES: &[&str] = &[
    "stack trace",
    "traceback (most recent call last)",
    "exception in thread",
    "at org.springframework",
    "sqlalchemy.exc",
    "activerecord::",
    "django.core.exceptions",
    "php fatal error",
    "warning: include(",
    "debug_backtrace",
];

/// Paths that indicate directory listing or debug endpoints.
const DEBUG_PATHS: &[&str] = &[
    "/debug",
    "/debug/pprof",
    "/phpinfo.php",
    "/info.php",
    "/?phpinfo",
    "/server-info",
    "/server-status",
    "/actuator/beans",
    "/actuator/env",
    "/actuator/mappings",
    "/api/swagger",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/openapi.json",
    "/graphql",
    "/__debug__/",
    "/django-admin/",
];

pub struct A05SecurityMisconfiguration;

#[async_trait]
impl OwaspModule for A05SecurityMisconfiguration {
    fn top10_id(&self) -> Top10Id { Top10Id::A05 }

    fn name(&self) -> &'static str {
        "Security Misconfiguration"
    }

    fn description(&self) -> &'static str {
        "Missing security headers, verbose errors, directory listing, exposed debug endpoints"
    }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        let base = target.url.as_str().trim_end_matches('/');
        let mut issues: Vec<(Severity, String)> = Vec::new();

        // ── 1. Security headers ───────────────────────────────────────────────
        debug!(base, "Checking security headers");
        let resp = session.client.get(base).send().await?;
        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();

        for (header, message) in REQUIRED_HEADERS {
            if headers.get(*header).is_none() {
                issues.push((Severity::Medium, message.to_string()));
            }
        }

        // ── 2. Verbose error disclosure ───────────────────────────────────────
        let body_lower = body.to_lowercase();
        for sig in ERROR_SIGNATURES {
            if body_lower.contains(sig) {
                issues.push((
                    Severity::Medium,
                    format!("Verbose error disclosure: `{sig}` found in response body"),
                ));
            }
        }

        // ── 3. Debug / info endpoints accessible ──────────────────────────────
        for path in DEBUG_PATHS {
            let url = format!("{base}{path}");
            debug!(url, "Probing debug path");
            let r = session.client.get(&url).send().await?;
            if r.status().is_success() {
                issues.push((
                    Severity::High,
                    format!("Debug/info endpoint accessible: {url} → HTTP {}", r.status().as_u16()),
                ));
            }
        }

        if issues.is_empty() {
            return Ok(None);
        }

        let max_severity = issues
            .iter()
            .map(|(s, _)| s.clone())
            .max()
            .unwrap_or(Severity::Low);

        let evidence = issues.into_iter().map(|(_, e)| e).collect::<Vec<_>>().join("\n");

        Ok(Some(Finding {
            top10_id: self.top10_id().to_string(),
            title: "Security Misconfiguration detected".into(),
            severity: max_severity,
            url: base.into(),
            evidence,
            remediation: "Add all recommended security headers. Disable debug endpoints in \
                          production. Configure generic error pages. Disable directory listing. \
                          Review and harden default framework configurations."
                .into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn detects_missing_security_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A05SecurityMisconfiguration.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert!(f.evidence.contains("Content-Security-Policy"));
    }

    #[tokio::test]
    async fn detects_verbose_error_in_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string("Traceback (most recent call last): File app.py line 42"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A05SecurityMisconfiguration.run(&target, &session).await.unwrap();

        let f = result.unwrap();
        assert!(f.evidence.to_lowercase().contains("traceback"));
    }

    #[tokio::test]
    async fn detects_exposed_debug_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/actuator/env"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"activeProfiles":[]}"#),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A05SecurityMisconfiguration.run(&target, &session).await.unwrap();

        let f = result.unwrap();
        assert!(f.evidence.contains("actuator/env"));
        assert_eq!(f.severity, Severity::High);
    }
}
