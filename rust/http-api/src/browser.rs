//! Browser transport policy, configured once when the HTTP listener is installed.

use axum::http::{HeaderName, HeaderValue, Method};
use std::str::FromStr;
use std::time::Duration;
use tower_http::cors::{AllowHeaders, CorsLayer};

const SETTING: &str = "NEXUS_HTTP_ALLOWED_ORIGINS";
const INVALID: &str = "NEXUS_HTTP_ALLOWED_ORIGINS must contain comma-separated http(s) origins without wildcards, credentials, paths, query or fragment";

/// Exact browser origins. Empty configuration leaves cross-origin access disabled.
#[derive(Clone, Debug, Default)]
pub struct BrowserOrigins(Vec<HeaderValue>);

impl FromStr for BrowserOrigins {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.trim().is_empty() {
            return Ok(Self::default());
        }
        let mut origins = Vec::new();
        for entry in value.split(',') {
            let url = url::Url::parse(entry.trim()).map_err(|_| INVALID.to_string())?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none_or(|host| host.contains('*'))
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(INVALID.to_string());
            }
            let origin = HeaderValue::from_str(&url.origin().ascii_serialization())
                .map_err(|_| INVALID.to_string())?;
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        Ok(Self(origins))
    }
}

impl BrowserOrigins {
    pub(crate) fn from_env() -> Result<Self, String> {
        match std::env::var(SETTING) {
            Ok(value) => value.parse(),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => Err(INVALID.to_string()),
        }
    }

    pub(crate) fn layer(&self) -> Option<CorsLayer> {
        if self.0.is_empty() {
            return None;
        }
        Some(
            CorsLayer::new()
                .allow_origin(self.0.clone())
                .allow_credentials(true)
                .allow_methods([
                    Method::GET,
                    Method::HEAD,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers(AllowHeaders::mirror_request())
                .expose_headers([HeaderName::from_bytes(
                    crate::revision::REVISION_HEADER.as_bytes(),
                )
                .expect("revision response header is valid")])
                .max_age(Duration::from_secs(600)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_normalized_and_deduplicated() {
        let config: BrowserOrigins =
            "https://EXAMPLE.test:443/, https://example.test, http://[::1]:5173"
                .parse()
                .unwrap();
        assert_eq!(config.0.len(), 2);
        assert_eq!(config.0[0], "https://example.test");
        assert_eq!(config.0[1], "http://[::1]:5173");
        assert!(config.layer().is_some());
        assert!("  ".parse::<BrowserOrigins>().unwrap().layer().is_none());
    }

    #[test]
    fn invalid_configuration_is_rejected_as_a_whole() {
        for entry in [
            "*",
            "null",
            "https://*.example.test",
            "https://user:secret@example.test",
            "https://example.test/path",
            "https://example.test/?query=yes",
            "https://example.test/#fragment",
            "file:///tmp/console",
            "https://example.test,",
            "https://example.test,invalid",
        ] {
            let error = entry.parse::<BrowserOrigins>().unwrap_err();
            assert_eq!(error, INVALID);
            assert!(!error.contains("secret"));
        }
    }
}
