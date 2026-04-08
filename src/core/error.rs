use thiserror::Error;

/// Top-level error type for scan module execution.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Module error: {0}")]
    Module(String),
}
