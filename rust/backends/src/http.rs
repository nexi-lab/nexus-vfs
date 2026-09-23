//! The one place a `reqwest::Client` is built.
//!
//! Every connector that speaks HTTP comes through here, for one reason that is
//! easy to get wrong in 21 separate places: rustls needs a process-level
//! `CryptoProvider` installed before a TLS client is constructed, and building
//! one without it fails at runtime — in whichever connector happened to make
//! the first call, which is a miserable way to find out.
//!
//! The daemon installs the provider during TLS setup
//! ([`lib::transport_primitives::ensure_crypto_provider`], ring). That
//! is enough when a connector is used after the daemon has served mTLS, and not
//! enough in general: a mount can be built before anything has done TLS, and a
//! non-daemon host (tests, tools) may never call it at all. Installing it here,
//! idempotently, makes a connector's HTTP client self-sufficient rather than
//! dependent on boot ordering it cannot see.
//!
//! This is also what lets `reqwest` be compiled with `rustls-no-provider`: it
//! then uses the process default — the same `ring` the rest of the binary
//! already links — instead of bundling a second crypto library of its own.

/// A `reqwest::ClientBuilder` with the crypto provider guaranteed installed.
///
/// For a call site that needs to set timeouts or pool options; a site with no
/// options wants [`http_client`].
pub(crate) fn http_client_builder() -> reqwest::ClientBuilder {
    lib::transport_primitives::ensure_crypto_provider();
    reqwest::Client::builder()
}

/// A default `reqwest::Client`, with the crypto provider guaranteed installed.
///
/// Replaces `reqwest::Client::new()` and keeps its contract, panic included:
/// `Client::new()` is itself `builder().build().unwrap()`, and a client that
/// cannot be constructed is a broken build rather than a runtime condition a
/// connector could do anything about.
pub(crate) fn http_client() -> reqwest::Client {
    http_client_builder()
        .build()
        .expect("reqwest client: TLS backend unavailable")
}
