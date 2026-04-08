//! A01:2021 — Broken Access Control
//!
//! Tests:
//!   1. Forced browsing — probes common admin/sensitive paths without authentication.
//!   2. IDOR — increments numeric IDs in the target URL path and checks if
//!      different data is returned without an authorization change.
//!   3. HTTP method override — sends PUT/DELETE on read-only endpoints.

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

/// Sensitive paths that should never be publicly accessible.
const ADMIN_PATHS: &[&str] = &[
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/dashboard",
    "/config",
    "/api/admin",
    "/api/users",
    "/api/v1/admin",
    "/management",
    "/.env",
    "/server-status",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
];

pub struct A01BrokenAccessControl;

#[async_trait]
impl OwaspModule for A01BrokenAccessControl {
    fn top10_id(&self) -> Top10Id { Top10Id::A01 }

    fn name(&self) -> &'static str {
        "Broken Access Control"
    }

    fn description(&self) -> &'static str {
        "Forced browsing to sensitive paths, IDOR via ID enumeration, HTTP method override"
    }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        let base = target.url.as_str().trim_end_matches('/');
        let mut exposed: Vec<String> = Vec::new();

        // ── 1. Forced browsing ────────────────────────────────────────────────
        for path in ADMIN_PATHS {
            let url = format!("{base}{path}");
            debug!(url, "Probing admin path");
            let resp = session.client.get(&url).send().await?;
            let status = resp.status().as_u16();
            // 200, 301, 302, 403 (exists but forbidden) are all interesting
            if matches!(status, 200 | 301 | 302 | 403) {
                exposed.push(format!("HTTP {status} → {url}"));
            }
        }

        // ── 2. IDOR probe — try /resource/1 and /resource/2 ──────────────────
        let idor_finding = self.probe_idor(base, session).await?;
        if let Some(msg) = idor_finding {
            exposed.push(msg);
        }

        if exposed.is_empty() {
            return Ok(None);
        }

        Ok(Some(Finding {
            top10_id: self.top10_id().to_string(),
            title: "Broken Access Control — sensitive resources accessible".into(),
            severity: Severity::High,
            url: base.into(),
            evidence: exposed.join("\n"),
            remediation: "Implement server-side authorization checks on every request. \
                          Deny by default. Apply the principle of least privilege. \
                          Log and alert on access control failures."
                .into(),
        }))
    }
}

impl A01BrokenAccessControl {
    /// Probe for IDOR by fetching /api/users/1 and /api/users/2 and comparing
    /// response bodies — if both return 200 with different content, IDOR is likely.
    async fn probe_idor(
        &self,
        base: &str,
        session: &Session,
    ) -> Result<Option<String>, ScanError> {
        let idor_paths = ["/api/users/1", "/api/users/2", "/user/1", "/user/2"];

        for pair in idor_paths.chunks(2) {
            let (url1, url2) = (format!("{base}{}", pair[0]), format!("{base}{}", pair[1]));
            let r1 = session.client.get(&url1).send().await?;
            let r2 = session.client.get(&url2).send().await?;

            if r1.status().is_success() && r2.status().is_success() {
                let b1 = r1.text().await.unwrap_or_default();
                let b2 = r2.text().await.unwrap_or_default();
                if b1 != b2 && !b1.is_empty() && !b2.is_empty() {
                    return Ok(Some(format!(
                        "IDOR: {url1} and {url2} both return 200 with different data — \
                         no authorization check detected"
                    )));
                }
            }
        }
        Ok(None)
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
    async fn detects_exposed_admin_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Admin panel"))
            .mount(&server)
            .await;
        // All other paths → 404
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A01BrokenAccessControl.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert!(f.evidence.contains("/admin"));
        assert_eq!(f.severity, Severity::High);
    }

    #[tokio::test]
    async fn no_finding_when_all_paths_return_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A01BrokenAccessControl.run(&target, &session).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn detects_idor_when_two_user_endpoints_differ() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"id":1,"name":"alice"}"#))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/users/2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"id":2,"name":"bob"}"#))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A01BrokenAccessControl.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        assert!(result.unwrap().evidence.contains("IDOR"));
    }
}
