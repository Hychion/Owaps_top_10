//! A07:2021 — Identification and Authentication Failures
//!
//! Tests:
//!   1. Default credentials — tries common username/password pairs on /login.
//!   2. No rate limiting — sends 10 rapid login attempts and checks for lockout.
//!   3. Verbose auth errors — distinguishes "unknown user" vs "wrong password".
//!   4. Session cookie attributes — Secure, HttpOnly, SameSite.

use async_trait::async_trait;
use serde_json::json;
use tracing::debug;

use crate::{
    core::{
        error::ScanError,
        models::{Finding, Severity, Target},
        session::Session,
    },
    modules::base::{OwaspModule, Top10Id},
};

/// Common default credential pairs.
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("administrator", "administrator"),
];

/// Login endpoint candidates to probe.
const LOGIN_PATHS: &[&str] = &[
    "/login",
    "/api/login",
    "/api/v1/login",
    "/api/auth/login",
    "/auth/login",
    "/signin",
    "/api/signin",
    "/user/login",
];

pub struct A07AuthFailures;

#[async_trait]
impl OwaspModule for A07AuthFailures {
    fn top10_id(&self) -> Top10Id { Top10Id::A07 }

    fn name(&self) -> &'static str {
        "Identification and Authentication Failures"
    }

    fn description(&self) -> &'static str {
        "Default credentials, no rate limiting on login, verbose auth errors, insecure session cookies"
    }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        let base = target.url.as_str().trim_end_matches('/');
        let mut issues: Vec<(Severity, String)> = Vec::new();

        // ── 1. Find a login endpoint ──────────────────────────────────────────
        let login_url = self.find_login_endpoint(base, session).await?;

        if let Some(ref url) = login_url {
            debug!(url, "Login endpoint found");

            // ── 2. Default credentials ────────────────────────────────────────
            for (user, pass) in DEFAULT_CREDENTIALS {
                let resp = session
                    .client
                    .post(url)
                    .json(&json!({"username": user, "password": pass}))
                    .send()
                    .await?;

                if resp.status().is_success() {
                    issues.push((
                        Severity::Critical,
                        format!("Default credentials accepted: {user}:{pass} → HTTP {}", resp.status()),
                    ));
                    break;
                }
            }

            // ── 3. Rate limiting check ────────────────────────────────────────
            let mut all_same = true;
            let mut last_status = 0u16;
            for i in 0..10 {
                let resp = session
                    .client
                    .post(url)
                    .json(&json!({"username": "owasp_probe", "password": format!("probe_{i}")}))
                    .send()
                    .await?;
                let s = resp.status().as_u16();
                if i == 0 { last_status = s; }
                if s != last_status { all_same = false; break; }
            }
            if all_same && last_status != 429 {
                issues.push((
                    Severity::High,
                    format!(
                        "No rate limiting on {url}: 10 consecutive login attempts \
                         all returned HTTP {last_status} (expected 429 or lockout)"
                    ),
                ));
            }

            // ── 4. Verbose error differentiation ──────────────────────────────
            let resp_unknown = session
                .client
                .post(url)
                .json(&json!({"username": "owasp_nonexistent_user_probe", "password": "x"}))
                .send()
                .await?;
            let body_unknown = resp_unknown.text().await.unwrap_or_default().to_lowercase();

            let resp_wrong = session
                .client
                .post(url)
                .json(&json!({"username": "admin", "password": "owasp_wrong_password_probe"}))
                .send()
                .await?;
            let body_wrong = resp_wrong.text().await.unwrap_or_default().to_lowercase();

            // If the messages differ, it reveals which usernames exist
            if body_unknown != body_wrong
                && (body_unknown.contains("user") || body_unknown.contains("not found")
                    || body_unknown.contains("unknown"))
            {
                issues.push((
                    Severity::Medium,
                    "Verbose auth errors: different messages for unknown user vs wrong password \
                     — enables username enumeration"
                        .into(),
                ));
            }
        }

        // ── 5. Session cookie attributes ──────────────────────────────────────
        let resp = session.client.get(base).send().await?;
        for val in resp.headers().get_all("set-cookie").iter() {
            let raw = val.to_str().unwrap_or("");
            let lower = raw.to_lowercase();
            let mut missing: Vec<&str> = Vec::new();
            if !lower.contains("httponly") { missing.push("HttpOnly"); }
            if !lower.contains("secure")   { missing.push("Secure"); }
            if !lower.contains("samesite") { missing.push("SameSite"); }
            if !missing.is_empty() {
                issues.push((
                    Severity::Medium,
                    format!("Session cookie missing {}: {raw}", missing.join(", ")),
                ));
            }
        }

        if issues.is_empty() {
            return Ok(None);
        }

        let max_severity = issues.iter().map(|(s, _)| s.clone()).max().unwrap_or(Severity::Low);
        let evidence = issues.into_iter().map(|(_, e)| e).collect::<Vec<_>>().join("\n");

        Ok(Some(Finding {
            top10_id: self.top10_id().to_string(),
            title: "Authentication failures detected".into(),
            severity: max_severity,
            url: base.into(),
            evidence,
            remediation: "Change all default credentials. Implement rate limiting and account \
                          lockout (e.g. 5 attempts → 15 min lockout). Return generic error \
                          messages. Set Secure, HttpOnly, SameSite=Strict on session cookies. \
                          Enforce MFA for privileged accounts."
                .into(),
        }))
    }
}

impl A07AuthFailures {
    async fn find_login_endpoint(
        &self,
        base: &str,
        session: &Session,
    ) -> Result<Option<String>, ScanError> {
        for path in LOGIN_PATHS {
            let url = format!("{base}{path}");
            // Use POST with empty body to detect if the endpoint exists
            let resp = session
                .client
                .post(&url)
                .json(&json!({}))
                .send()
                .await?;
            // 400/401/422 mean the endpoint exists (it rejected the empty body)
            if matches!(resp.status().as_u16(), 200 | 400 | 401 | 403 | 422) {
                return Ok(Some(url));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{body_json_schema, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn detects_default_credentials() {
        let server = MockServer::start().await;

        // Login endpoint exists
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"token":"abc"}"#))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A07AuthFailures.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.contains("Default credentials"));
    }

    #[tokio::test]
    async fn detects_missing_cookie_attributes() {
        let server = MockServer::start().await;

        // No login endpoint
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // Homepage sets insecure cookie
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
        let result = A07AuthFailures.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert!(f.evidence.contains("HttpOnly"));
    }
}
