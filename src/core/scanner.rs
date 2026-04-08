use std::sync::Arc;

use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::{
    core::{models::Report, session::Session},
    modules::base::OwaspModule,
};

/// Orchestrates the execution of multiple OWASP Top 10 modules against a target.
pub struct Scanner {
    session: Arc<Session>,
    modules: Vec<Arc<dyn OwaspModule>>,
    concurrency: usize,
}

impl Scanner {
    pub fn new(session: Session, modules: Vec<Arc<dyn OwaspModule>>, concurrency: usize) -> Self {
        Self {
            session: Arc::new(session),
            modules,
            concurrency,
        }
    }

    /// Run all registered modules and aggregate findings into a [`Report`].
    pub async fn run(&self) -> Report {
        let mut report = Report::new(&self.session.target);
        let mut join_set: JoinSet<Option<crate::core::models::Finding>> = JoinSet::new();
        let mut queue = self.modules.iter().peekable();

        loop {
            // Fill up to concurrency limit.
            while join_set.len() < self.concurrency {
                match queue.next() {
                    Some(module) => {
                        let module = Arc::clone(module);
                        let session = Arc::clone(&self.session);
                        info!(id = %module.top10_id(), "Starting module");
                        join_set.spawn(async move {
                            match module.run(&session.target, &session).await {
                                Ok(finding) => finding,
                                Err(e) => {
                                    error!(id = %module.top10_id(), error = %e, "Module failed");
                                    None
                                }
                            }
                        });
                    }
                    None => break,
                }
            }

            if join_set.is_empty() {
                break;
            }

            // Await the next completed module.
            if let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Some(finding)) => {
                        info!(top10_id = %finding.top10_id, severity = %finding.severity, "Finding recorded");
                        report.push(finding);
                    }
                    Ok(None) => {}
                    Err(e) => warn!(error = %e, "Module task panicked"),
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{models::Target, session::Session};
    use crate::modules::base::{OwaspModule, Top10Id};
    use async_trait::async_trait;
    use crate::core::models::{Finding, Severity};

    struct NoopModule;

    #[async_trait]
    impl OwaspModule for NoopModule {
        fn top10_id(&self) -> Top10Id { Top10Id::A05 }
        fn name(&self) -> &'static str { "Noop" }
        fn description(&self) -> &'static str { "Test noop" }

        async fn run(
            &self,
            _target: &Target,
            _session: &Session,
        ) -> Result<Option<Finding>, crate::core::error::ScanError> {
            Ok(None)
        }
    }

    struct AlwaysFindingModule;

    #[async_trait]
    impl OwaspModule for AlwaysFindingModule {
        fn top10_id(&self) -> Top10Id { Top10Id::A01 }
        fn name(&self) -> &'static str { "Always finds" }
        fn description(&self) -> &'static str { "Test module that always finds" }

        async fn run(
            &self,
            target: &Target,
            _session: &Session,
        ) -> Result<Option<Finding>, crate::core::error::ScanError> {
            Ok(Some(Finding {
                top10_id: self.top10_id().to_string(),
                title: "Test finding".into(),
                severity: Severity::Info,
                url: target.url.to_string(),
                evidence: "test evidence".into(),
                remediation: "none".into(),
            }))
        }
    }

    fn make_session() -> Session {
        let target = Target::new("https://example.com").unwrap();
        Session::new(target, 15, true).unwrap()
    }

    #[tokio::test]
    async fn scanner_no_findings_with_noop_module() {
        let session = make_session();
        let modules: Vec<Arc<dyn OwaspModule>> = vec![Arc::new(NoopModule)];
        let scanner = Scanner::new(session, modules, 1);
        let report = scanner.run().await;
        assert_eq!(report.finding_count(), 0);
    }

    #[tokio::test]
    async fn scanner_records_finding() {
        let session = make_session();
        let modules: Vec<Arc<dyn OwaspModule>> = vec![Arc::new(AlwaysFindingModule)];
        let scanner = Scanner::new(session, modules, 1);
        let report = scanner.run().await;
        assert_eq!(report.finding_count(), 1);
    }

    #[tokio::test]
    async fn scanner_runs_multiple_modules_concurrently() {
        let session = make_session();
        let modules: Vec<Arc<dyn OwaspModule>> = vec![
            Arc::new(AlwaysFindingModule),
            Arc::new(NoopModule),
            Arc::new(AlwaysFindingModule),
        ];
        let scanner = Scanner::new(session, modules, 3);
        let report = scanner.run().await;
        assert_eq!(report.finding_count(), 2);
    }
}
