use async_trait::async_trait;

use crate::core::{
    error::ScanError,
    models::{Finding, Target},
    session::Session,
};

/// OWASP Top 10 category identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Top10Id {
    A01, // Broken Access Control
    A02, // Cryptographic Failures
    A03, // Injection
    A05, // Security Misconfiguration
    A06, // Vulnerable & Outdated Components (partial)
    A07, // Identification & Authentication Failures
    A08, // Software & Data Integrity Failures (partial)
    A10, // Server-Side Request Forgery
}

impl std::fmt::Display for Top10Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Top10Id::A01 => "A01:2021",
            Top10Id::A02 => "A02:2021",
            Top10Id::A03 => "A03:2021",
            Top10Id::A05 => "A05:2021",
            Top10Id::A06 => "A06:2021",
            Top10Id::A07 => "A07:2021",
            Top10Id::A08 => "A08:2021",
            Top10Id::A10 => "A10:2021",
        };
        write!(f, "{s}")
    }
}

/// Every OWASP Top 10 module must implement this trait.
///
/// Modules are async, Send + Sync so they can run concurrently on the tokio thread pool.
#[async_trait]
pub trait OwaspModule: Send + Sync {
    /// OWASP Top 10 identifier, e.g. `A01:2021`.
    fn top10_id(&self) -> Top10Id;

    /// Human-readable module name.
    fn name(&self) -> &'static str;

    /// Short description of what this module tests.
    fn description(&self) -> &'static str;

    /// Execute the test against the target using the provided session.
    ///
    /// Returns `Ok(Some(finding))` if a vulnerability is detected,
    /// `Ok(None)` if the test passed cleanly, or `Err` on execution failure.
    async fn run(&self, target: &Target, session: &Session) -> Result<Option<Finding>, ScanError>;
}

/// Metadata view of a module (used by the `list` command).
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub top10_id: String,
    pub name: &'static str,
    pub description: &'static str,
}

impl<M: OwaspModule> From<&M> for ModuleInfo {
    fn from(m: &M) -> Self {
        Self {
            top10_id: m.top10_id().to_string(),
            name: m.name(),
            description: m.description(),
        }
    }
}
