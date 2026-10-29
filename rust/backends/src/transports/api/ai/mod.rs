//! LLM connector backends — SSE → DT_STREAM → CAS pipeline.

mod http_exchange;

/// Model connections bound DNS, TCP and TLS setup; callers own request retries.
fn http_client() -> std::io::Result<reqwest::Client> {
    crate::http::http_client_builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|error| std::io::Error::other(format!("reqwest build: {error}")))
}

#[cfg(feature = "driver-anthropic")]
pub mod anthropic;
#[cfg(feature = "driver-openai")]
pub mod openai;
