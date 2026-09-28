//! Channel creation utility — centralized tonic Endpoint configuration.

use super::config::{ClientConfig, TlsConfig};
use super::error::TransportError;

/// Create a tonic Channel to the given endpoint with optional TLS.
///
/// Centralizes Endpoint configuration (timeouts, keepalive, TLS) so
/// each domain crate doesn't reinvent channel setup.
///
/// # The whole connect is bounded, not each layer of it
///
/// `connect_timeout` bounds the TCP connect and `timeout` bounds a request, and
/// between them sits the TLS handshake, which neither covers. A peer that ACCEPTS
/// the connection and then says nothing therefore parks this await forever — and
/// "accepts and says nothing" is not exotic: a wedged daemon, a port-forward with
/// nothing behind it, a socket bound by a process that never reads it. Found the
/// hard way: `auth mint` on an enrolled node dials its own daemon first, and with a
/// silent listener on that port the command hung indefinitely instead of failing
/// over to the founder after its stated 15 seconds.
///
/// So the caller's `connect_timeout` bounds the entire establishment. A caller that
/// asks for 15 seconds gets an answer in 15 seconds, whichever layer stalls, which
/// is the only version of a timeout a caller can reason about.
#[allow(clippy::result_large_err)]
pub async fn create_channel(
    endpoint: &str,
    config: &ClientConfig,
) -> Result<tonic::transport::Channel, TransportError> {
    let mut ep = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| TransportError::InvalidAddress(format!("{e}")))?
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout);

    if let Some(keepalive) = config.tcp_keepalive {
        ep = ep.tcp_keepalive(Some(keepalive));
    }
    if let Some(interval) = config.http2_keepalive_interval {
        ep = ep.http2_keep_alive_interval(interval);
    }
    if let Some(timeout) = config.http2_keepalive_timeout {
        ep = ep.keep_alive_timeout(timeout);
    }

    if let Some(ref tls) = config.tls {
        ep = apply_tls(ep, tls)?;
    }

    match tokio::time::timeout(config.connect_timeout, ep.connect()).await {
        Ok(result) => result.map_err(TransportError::Tonic),
        Err(_) => Err(TransportError::Connection(format!(
            "connect to {endpoint} did not complete within {:?} — the peer may be accepting \
             connections without completing a handshake",
            config.connect_timeout
        ))),
    }
}

/// Install the process-level rustls `CryptoProvider` (ring) exactly once.
///
/// rustls 0.23's auto-selecting config builder — which tonic's
/// `ClientTlsConfig`/`ServerTlsConfig` drive — panics when **zero or
/// multiple** provider features are compiled in. On Linux the dependency
/// graph pulls both `ring` (tonic's `tls-ring`) and `aws-lc-rs` (rustls'
/// default feature), so the process default must be pinned before the first
/// TLS config is built or the handshake thread panics ("could not
/// automatically determine the process-level CryptoProvider"). All mTLS
/// paths were `--no-tls` until now, so nothing exercised this — the server
/// and client TLS setup both call this first. Idempotent via `Once`;
/// `install_default` returning `Err` (already set) is intentionally ignored.
pub fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Apply TLS configuration to a tonic Endpoint.
#[allow(clippy::result_large_err)]
fn apply_tls(
    ep: tonic::transport::Endpoint,
    tls: &TlsConfig,
) -> Result<tonic::transport::Endpoint, TransportError> {
    ensure_crypto_provider();
    let ca_cert = tonic::transport::Certificate::from_pem(&tls.ca_pem);
    let identity = tonic::transport::Identity::from_pem(&tls.cert_pem, &tls.key_pem);

    // Verify the peer against the fixed cluster server name (present in every
    // node cert as a SAN) + the cluster CA chain — NOT the dialed IP/hostname.
    // A node's identity is CA membership + its URI SAN; the network address is
    // routing. Pinning the dialed IP here would force every cert to enumerate
    // its addresses and re-enroll on any overlay-IP change. See
    // `CLUSTER_TLS_SERVER_NAME`.
    let tls_config = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
        .domain_name(TlsConfig::CLUSTER_SERVER_NAME);

    ep.tls_config(tls_config).map_err(TransportError::Tonic)
}
