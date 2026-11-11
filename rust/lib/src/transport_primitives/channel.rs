//! Channel creation utility — centralized tonic Endpoint configuration.

use super::config::{ClientConfig, TlsConfig};
use super::error::TransportError;
use super::peer_verifier::ExpectedPeer;
use std::{future::Future, pin::Pin};

type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<tonic::transport::Channel, TransportError>> + Send + 'a>>;

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
// Share the connection state machine across transport consumers. The allocation
// is paid when opening a channel; pooled RPCs keep using the existing channel.
#[inline(never)]
pub fn create_channel<'a>(endpoint: &'a str, config: &'a ClientConfig) -> ConnectFuture<'a> {
    Box::pin(connect_channel(endpoint, config, None))
}

/// Connect to an exact signed Node or owner replica using the same transport
/// configuration as other channels. The route carries no identity authority.
#[inline(never)]
pub fn create_peer_channel<'a>(
    endpoint: &'a str,
    config: &'a ClientConfig,
    expected: std::num::NonZeroU64,
) -> ConnectFuture<'a> {
    Box::pin(connect_channel(
        endpoint,
        config,
        Some(ExpectedPeer::Replication(expected)),
    ))
}

/// Connect to an exact cluster Node. An owner replica with the same numeric ID
/// is a different authority and cannot serve this channel, including reconnects.
#[inline(never)]
pub fn create_node_channel<'a>(
    endpoint: &'a str,
    config: &'a ClientConfig,
    expected: std::num::NonZeroU64,
) -> ConnectFuture<'a> {
    Box::pin(connect_channel(
        endpoint,
        config,
        Some(ExpectedPeer::Node(expected)),
    ))
}

#[allow(clippy::result_large_err)]
async fn connect_channel(
    endpoint: &str,
    config: &ClientConfig,
    expected: Option<ExpectedPeer>,
) -> Result<tonic::transport::Channel, TransportError> {
    if expected.is_some() && config.tls.is_none() {
        return Err(TransportError::Connection(
            "authenticated peer channels require TLS".into(),
        ));
    }
    let ep = configured_endpoint(endpoint, config, expected)?;
    match tokio::time::timeout(config.connect_timeout, ep.connect()).await {
        Ok(result) => result.map_err(TransportError::Tonic),
        Err(_) => Err(TransportError::Connection(format!(
            "connect to {endpoint} did not complete within {:?} — the peer may be accepting \
             connections without completing a handshake",
            config.connect_timeout
        ))),
    }
}

// URI and certificate preparation completes before the asynchronous dial. Keep
// its parsing and error paths in one synchronous body across transport callers.
#[inline(never)]
#[allow(clippy::result_large_err)]
fn configured_endpoint(
    endpoint: &str,
    config: &ClientConfig,
    expected: Option<ExpectedPeer>,
) -> Result<tonic::transport::Endpoint, TransportError> {
    let mut uri: tonic::codegen::http::Uri = endpoint
        .parse()
        .map_err(|e| TransportError::InvalidAddress(format!("{e}")))?;
    // TLS material selects the transport. A routing URI cannot disable it.
    if config.tls.is_some() {
        match uri.scheme_str() {
            Some("http") => {
                let mut parts = uri.into_parts();
                parts.scheme = Some(tonic::codegen::http::uri::Scheme::HTTPS);
                uri = tonic::codegen::http::Uri::from_parts(parts)
                    .map_err(|e| TransportError::InvalidAddress(format!("{e}")))?;
            }
            Some("https") => {}
            _ => {
                return Err(TransportError::InvalidAddress(
                    "TLS peer endpoints require an http or https routing URI".into(),
                ))
            }
        }
    }
    let mut ep = tonic::transport::Endpoint::from_shared(uri.to_string())
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
        ep = apply_tls(ep, tls, expected)?;
    }

    Ok(ep)
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
    expected: Option<ExpectedPeer>,
) -> Result<tonic::transport::Endpoint, TransportError> {
    ensure_crypto_provider();
    let identity = tonic::transport::Identity::from_pem(&tls.cert_pem, &tls.key_pem);

    // Verify the peer against the fixed cluster server name (present in every
    // node cert as a SAN) + the cluster CA chain — NOT the dialed IP/hostname.
    // A node's identity is CA membership + its URI SAN; the network address is
    // routing. Pinning the dialed IP here would force every cert to enumerate
    // its addresses and re-enroll on any overlay-IP change. See
    // `CLUSTER_TLS_SERVER_NAME`.
    let tls_config = tonic::transport::ClientTlsConfig::new()
        .identity(identity)
        .domain_name(TlsConfig::CLUSTER_SERVER_NAME);
    match expected {
        Some(expected) => {
            let verifier = super::peer_verifier::PeerVerifier::new(&tls.ca_pem, expected)
                .map_err(TransportError::Connection)?;
            ep.tls_config_with_verifier(tls_config, verifier)
                .map_err(TransportError::Tonic)
        }
        None => ep
            .tls_config(
                tls_config.ca_certificate(tonic::transport::Certificate::from_pem(&tls.ca_pem)),
            )
            .map_err(TransportError::Tonic),
    }
}
