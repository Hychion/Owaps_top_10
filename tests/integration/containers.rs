//! testcontainers image definitions for each OWASP Top 10 lab.

use testcontainers::{core::WaitFor, Image};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

macro_rules! lab_image {
    ($name:ident, $image:literal, $port:expr) => {
        #[derive(Debug, Clone)]
        pub struct $name;

        impl Image for $name {
            fn name(&self) -> &str { $image }
            fn tag(&self) -> &str { "test" }
            fn ready_conditions(&self) -> Vec<WaitFor> {
                vec![WaitFor::http(
                    testcontainers::core::HttpWaitStrategy::new("/health")
                        .with_expected_status_code(200_u16),
                )]
            }
        }
    };
}

lab_image!(LabA01, "owasp-lab-a01", 5000);
lab_image!(LabA02, "owasp-lab-a02", 5001);
lab_image!(LabA03, "owasp-lab-a03", 5002);
lab_image!(LabA05, "owasp-lab-a05", 5003);
lab_image!(LabA07, "owasp-lab-a07", 5004);
lab_image!(LabA10, "owasp-lab-a10", 5005);

/// Build all lab images before running integration tests.
/// Uses a `Once` guard so it only runs once per test binary invocation.
pub fn build_all_labs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let labs = [
            ("owasp-lab-a01:test", "docker/lab-a01"),
            ("owasp-lab-a02:test", "docker/lab-a02"),
            ("owasp-lab-a03:test", "docker/lab-a03"),
            ("owasp-lab-a05:test", "docker/lab-a05"),
            ("owasp-lab-a07:test", "docker/lab-a07"),
            ("owasp-lab-a10:test", "docker/lab-a10"),
        ];
        for (tag, context) in labs {
            let status = std::process::Command::new("docker")
                .args(["build", "-t", tag, context])
                .current_dir(MANIFEST_DIR)
                .status()
                .unwrap_or_else(|_| panic!("docker build failed for {tag}"));
            assert!(status.success(), "Failed to build {tag}");
        }
    });
}
