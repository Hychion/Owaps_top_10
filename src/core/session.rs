use reqwest::{
    header::{HeaderMap, HeaderValue, USER_AGENT},
    Client, ClientBuilder,
};
use thiserror::Error;

use crate::core::models::Target;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Failed to build HTTP client: {0}")]
    Build(#[from] reqwest::Error),
    #[error("Invalid header value: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
}

/// Wraps an HTTP client configured for a specific scan target.
#[derive(Debug, Clone)]
pub struct Session {
    pub(crate) client: Client,
    pub target: Target,
}

impl Session {
    /// Build a new session for the given target.
    ///
    /// # Errors
    /// Returns [`SessionError`] if the HTTP client cannot be constructed.
    pub fn new(target: Target, timeout_secs: u64, verify_tls: bool) -> Result<Self, SessionError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("owasp-tester/0.1.0 (authorized security assessment)"),
        );

        // Inject auth header if provided.
        if let Some(token) = &target.auth_token {
            let value = HeaderValue::from_str(&format!("Bearer {token}"))?;
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }

        let client = ClientBuilder::new()
            .default_headers(headers)
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(!verify_tls)
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()?;

        Ok(Self { client, target })
    }

    /// Perform a GET request and return the response.
    pub async fn get(&self, url: &str) -> Result<reqwest::Response, reqwest::Error> {
        self.client.get(url).send().await
    }

    /// Perform a POST request with a form body.
    pub async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.client.post(url).form(form).send().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target() -> Target {
        Target::new("https://example.com").unwrap()
    }

    #[test]
    fn session_builds_successfully() {
        let session = Session::new(make_target(), 15, true);
        assert!(session.is_ok());
    }

    #[test]
    fn session_with_invalid_tls_builds() {
        let session = Session::new(make_target(), 15, false);
        assert!(session.is_ok());
    }
}
