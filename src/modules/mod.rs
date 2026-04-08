pub mod a01_broken_access_control;
pub mod a02_cryptographic_failures;
pub mod a03_injection;
pub mod a05_security_misconfiguration;
pub mod a07_auth_failures;
pub mod a10_ssrf;
pub mod base;

use std::sync::Arc;

use crate::modules::{
    a01_broken_access_control::A01BrokenAccessControl,
    a02_cryptographic_failures::A02CryptographicFailures,
    a03_injection::A03Injection,
    a05_security_misconfiguration::A05SecurityMisconfiguration,
    a07_auth_failures::A07AuthFailures,
    a10_ssrf::A10Ssrf,
    base::OwaspModule,
};

/// Full registry of all implemented OWASP Top 10 modules.
pub fn all_modules() -> Vec<Arc<dyn OwaspModule>> {
    vec![
        Arc::new(A01BrokenAccessControl),
        Arc::new(A02CryptographicFailures),
        Arc::new(A03Injection),
        Arc::new(A05SecurityMisconfiguration),
        Arc::new(A07AuthFailures),
        Arc::new(A10Ssrf),
    ]
}

/// Return only the modules matching the given Top 10 IDs (e.g. "A01:2021").
pub fn modules_by_id(ids: &[String]) -> Vec<Arc<dyn OwaspModule>> {
    all_modules()
        .into_iter()
        .filter(|m| ids.iter().any(|id| id == &m.top10_id().to_string()))
        .collect()
}
