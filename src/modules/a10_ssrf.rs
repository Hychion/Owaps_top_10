//! A10:2021 — Server-Side Request Forgery (SSRF)
//!
//! Tests:
//!   1. URL parameter injection — injects internal/loopback addresses into common
//!      URL-accepting parameters and observes if the server fetches them.
//!   2. Cloud metadata endpoint probe — checks if the server fetches
//!      169.254.169.254 (AWS IMDSv1) when instructed.
//!   3. DNS rebinding indicator — looks for response body differences that
//!      suggest the server resolved the injected host.

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

/// Query parameters that commonly accept URLs in web applications.
const URL_PARAMS: &[&str] = &[
    "url", "uri", "href", "src", "redirect", "callback",
    "next", "return", "returnUrl", "redirect_uri", "target",
    "dest", "destination", "link", "path", "proxy", "fetch",
    "load", "request", "image", "img",
];

/// SSRF probe targets — benign internal addresses.
/// We use the OWASP-defined cloud metadata endpoint and loopback.
const SSRF_PROBES: &[(&str, &str)] = &[
    ("http://127.0.0.1/",            "loopback"),
    ("http://localhost/",            "loopback-hostname"),
    ("http://169.254.169.254/",      "aws-imds"),
    ("http://[::1]/",               "ipv6-loopback"),
    ("http://0.0.0.0/",             "zero-address"),
];

/// Patterns in response bodies that indicate the server fetched the injected URL.
const SSRF_RESPONSE_INDICATORS: &[&str] = &[
    "ami-id",               // AWS IMDS
    "instance-id",          // AWS IMDS
    "meta-data",            // Cloud metadata
    "computemetadata",      // GCP metadata
    "127.0.0.1",            // Loopback reflected back
    "localhost",
    "connection refused",   // Server tried to connect
    "no route to host",
    "network unreachable",
];

pub struct A10Ssrf;

#[async_trait]
impl OwaspModule for A10Ssrf {
    fn top10_id(&self) -> Top10Id { Top10Id::A10 }

    fn name(&self) -> &'static str {
        "Server-Side Request Forgery (SSRF)"
    }

    fn description(&self) -> &'static str {
        "URL parameter injection with internal/loopback addresses and cloud metadata endpoints"
    }

    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError> {
        let base = target.url.as_str().trim_end_matches('/');
        let mut findings: Vec<String> = Vec::new();

        for param in URL_PARAMS {
            for (probe_url, probe_name) in SSRF_PROBES {
                let url = format!("{base}?{param}={}", urlencoding::encode(probe_url));
                debug!(url, probe_name, "SSRF probe");

                let resp = match session.client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default().to_lowercase();

                // Check for indicators in the response body
                for indicator in SSRF_RESPONSE_INDICATORS {
                    if body.contains(indicator) {
                        findings.push(format!(
                            "SSRF via `?{param}={probe_url}` ({probe_name}): \
                             response body contains `{indicator}` — server likely \
                             fetched the injected URL (HTTP {status})"
                        ));
                    }
                }

                // Unexpected 200 on internal endpoints is suspicious
                if status == 200 && matches!(*probe_name, "aws-imds" | "loopback") {
                    let already_reported = findings
                        .iter()
                        .any(|f| f.contains(probe_url));
                    if !already_reported {
                        findings.push(format!(
                            "Potential SSRF via `?{param}={probe_url}` ({probe_name}): \
                             server returned HTTP 200 for internal address injection"
                        ));
                    }
                }

                if !findings.is_empty() {
                    // One confirmed finding is enough — stop probing.
                    return Ok(Some(Finding {
                        top10_id: self.top10_id().to_string(),
                        title: "SSRF — Server fetches attacker-controlled URLs".into(),
                        severity: Severity::Critical,
                        url: base.into(),
                        evidence: findings.join("\n"),
                        remediation: "Validate and allowlist all URLs before server-side fetching. \
                                      Block requests to private/loopback ranges at the network level. \
                                      Disable IMDSv1 and enforce IMDSv2 on cloud instances. \
                                      Do not return raw fetch results to the user."
                            .into(),
                    }));
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
        matchers::{method, path, query_param_contains},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn detects_ssrf_via_imds_response_indicator() {
        let server = MockServer::start().await;

        // Server reflects IMDS-like content when url param injected
        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param_contains("url", "169.254"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ami-id: ami-0abcdef1234567890\ninstance-id: i-1234567890abcdef0"),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let target = Target::new(&server.uri()).unwrap();
        let session = Session::new(target.clone(), 5, true).unwrap();
        let result = A10Ssrf.run(&target, &session).await.unwrap();

        assert!(result.is_some());
        let f = result.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.contains("ami-id"));
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
        let result = A10Ssrf.run(&target, &session).await.unwrap();

        assert!(result.is_none());
    }
}
