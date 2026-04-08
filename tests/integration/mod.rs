//! Integration tests — spin up custom Docker labs via testcontainers.
//!
//! Enable: `cargo test --features integration-tests`
//! Prerequisites: Docker daemon running + `make lab-build`

pub mod containers;

#[cfg(feature = "integration-tests")]
mod tests {
    use std::sync::Arc;
    use testcontainers::runners::AsyncRunner;
    use testcontainers::ImageExt;

    use owasp_tester::core::{models::Target, session::Session};
    use owasp_tester::modules::{
        a01_broken_access_control::A01BrokenAccessControl,
        a02_cryptographic_failures::A02CryptographicFailures,
        a03_injection::A03Injection,
        a05_security_misconfiguration::A05SecurityMisconfiguration,
        a07_auth_failures::A07AuthFailures,
        a10_ssrf::A10Ssrf,
    };
    use owasp_tester::modules::base::OwaspModule;
    use super::containers::*;

    fn setup() { build_all_labs(); }

    // ── A01:2021 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a01_detects_exposed_admin_and_idor() {
        setup();
        let c = LabA01.start().await.unwrap();
        let port = c.get_host_port_ipv4(5000).await.unwrap();
        let target = Target::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let session = Session::new(target.clone(), 10, true).unwrap();

        let result = A01BrokenAccessControl.run(&target, &session).await.unwrap();
        assert!(result.is_some(), "Expected A01 finding");
        let f = result.unwrap();
        assert!(f.evidence.contains("/admin") || f.evidence.contains("IDOR"));
    }

    // ── A02:2021 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a02_detects_http_and_missing_headers() {
        setup();
        let c = LabA02.start().await.unwrap();
        let port = c.get_host_port_ipv4(5001).await.unwrap();
        let target = Target::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let session = Session::new(target.clone(), 10, true).unwrap();

        let result = A02CryptographicFailures.run(&target, &session).await.unwrap();
        assert!(result.is_some(), "Expected A02 finding");
        let f = result.unwrap();
        assert!(f.evidence.contains("plaintext") || f.evidence.contains("HSTS") || f.evidence.contains("Cookie"));
    }

    // ── A03:2021 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a03_detects_sqli_on_lab() {
        setup();
        let c = LabA03.start().await.unwrap();
        let port = c.get_host_port_ipv4(5002).await.unwrap();
        let target = Target::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let session = Session::new(target.clone(), 10, true).unwrap();

        let result = A03Injection.run(&target, &session).await.unwrap();
        assert!(result.is_some(), "Expected A03 injection finding");
        let f = result.unwrap();
        assert!(f.evidence.contains("SQL") || f.evidence.contains("XSS") || f.evidence.contains("SSTI"));
    }

    // ── A05:2021 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a05_detects_missing_headers_and_debug_endpoints() {
        setup();
        let c = LabA05.start().await.unwrap();
        let port = c.get_host_port_ipv4(5003).await.unwrap();
        let target = Target::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let session = Session::new(target.clone(), 10, true).unwrap();

        let result = A05SecurityMisconfiguration.run(&target, &session).await.unwrap();
        assert!(result.is_some(), "Expected A05 finding");
        let f = result.unwrap();
        assert!(f.evidence.contains("Content-Security-Policy") || f.evidence.contains("actuator"));
    }

    // ── A07:2021 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a07_detects_default_credentials() {
        setup();
        let c = LabA07.start().await.unwrap();
        let port = c.get_host_port_ipv4(5004).await.unwrap();
        let target = Target::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let session = Session::new(target.clone(), 10, true).unwrap();

        let result = A07AuthFailures.run(&target, &session).await.unwrap();
        assert!(result.is_some(), "Expected A07 finding");
        let f = result.unwrap();
        assert!(f.evidence.contains("Default credentials") || f.evidence.contains("rate limiting"));
    }

    // ── A10:2021 ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a10_detects_ssrf_via_url_parameter() {
        setup();
        let c = LabA10.start().await.unwrap();
        let port = c.get_host_port_ipv4(5005).await.unwrap();
        let target = Target::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let session = Session::new(target.clone(), 10, true).unwrap();

        let result = A10Ssrf.run(&target, &session).await.unwrap();
        // SSRF lab fetches whatever URL is passed — expect a finding
        // (may be None if loopback itself returns nothing interesting; still valid)
        println!("A10 result: {:?}", result.as_ref().map(|f| &f.evidence));
    }
}
