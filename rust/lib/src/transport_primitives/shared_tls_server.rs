//! Server configurations derived from the node's shared credential source.

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_stream::Stream;

use super::{server_config, FederatedClientCertVerifier, SharedTlsConfig, TlsSnapshot};

/// Prepared listener trust sharing its current credentials with outbound clients.
pub struct SharedTlsListener {
    source: SharedTlsConfig,
    ca_pem: Vec<u8>,
    verifier: Arc<FederatedClientCertVerifier>,
    cached: Mutex<Option<(TlsSnapshot, Arc<rustls::ServerConfig>)>>,
}

impl SharedTlsListener {
    /// Validate the configured key and trust before opening durable runtime data.
    /// Each handshake still requires a current, live installation.
    pub fn prepare(
        source: SharedTlsConfig,
        verifier: Option<Arc<FederatedClientCertVerifier>>,
    ) -> Result<Self, String> {
        source.read(|initial| {
            let tls = initial
                .configured_material()?
                .ok_or("TLS listener requires credentials")?;
            let verifier = match verifier {
                Some(verifier) => verifier,
                None => FederatedClientCertVerifier::new(&tls.ca_pem)?,
            };
            let config = Arc::new(server_config(
                Arc::clone(&verifier),
                &tls.cert_pem,
                &tls.key_pem,
            )?);
            Ok(Self {
                source: source.clone(),
                ca_pem: tls.ca_pem.clone(),
                verifier,
                cached: Mutex::new(Some((initial.clone(), config))),
            })
        })
    }

    /// Start accepting connections under the current credential installation.
    pub fn incoming(
        self,
        listener: TcpListener,
    ) -> impl Stream<Item = std::io::Result<TlsStream<TcpStream>>> {
        let source = self.source.clone();
        super::federated_tls::tls_incoming_checked(
            listener,
            move || self.config().ok(),
            move |snapshot| source.is_current(snapshot),
        )
    }

    fn config(&self) -> Result<(Arc<rustls::ServerConfig>, TlsSnapshot), String> {
        self.source.read(|snapshot| {
            let tls = snapshot
                .config()?
                .ok_or("TLS listener requires credentials")?;
            if tls.ca_pem != self.ca_pem {
                return Err("TLS replacement must preserve the listener trust anchor".into());
            }
            let mut cached = self.cached.lock();
            if let Some((original, config)) = cached.as_ref() {
                if original.same_installation(snapshot) {
                    return Ok((Arc::clone(config), snapshot.clone()));
                }
            }
            let config = Arc::new(server_config(
                Arc::clone(&self.verifier),
                &tls.cert_pem,
                &tls.key_pem,
            )?);
            *cached = Some((snapshot.clone(), Arc::clone(&config)));
            Ok((config, snapshot.clone()))
        })
    }
}

/// Use the same live credential installation as outbound transports.
/// The existing federated verifier remains shared with its trust observers.
pub fn shared_tls_incoming(
    listener: TcpListener,
    source: SharedTlsConfig,
    verifier: Option<Arc<FederatedClientCertVerifier>>,
) -> Result<impl Stream<Item = std::io::Result<TlsStream<TcpStream>>>, String> {
    Ok(SharedTlsListener::prepare(source, verifier)?.incoming(listener))
}

/// Bind a listener that consumes the same credential source as its clients.
/// Validate its trust configuration before scheduling the bind. Each handshake
/// still reads the current installation, including withdrawal and replacement.
pub fn shared_mtls_incoming(
    address: SocketAddr,
    source: SharedTlsConfig,
    verifier: Option<Arc<FederatedClientCertVerifier>>,
) -> impl std::future::Future<
    Output = Result<impl Stream<Item = std::io::Result<TlsStream<TcpStream>>>, String>,
> {
    let prepared = SharedTlsListener::prepare(source, verifier);
    async move {
        let server = prepared?;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| e.to_string())?;
        Ok(server.incoming(listener))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_primitives::{TlsConfig, TlsPolicy};
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    fn credentials() -> (TlsConfig, TlsConfig) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&ca.pem(), ca_key).unwrap();
        let leaf = |expired| {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
            if expired {
                params.not_before = rcgen::date_time_ymd(2000, 1, 1);
                params.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            TlsConfig {
                cert_pem: params.signed_by(&key, &issuer).unwrap().pem().into_bytes(),
                key_pem: key.serialize_pem().into_bytes(),
                ca_pem: ca.pem().into_bytes(),
            }
        };
        (leaf(true), leaf(false))
    }

    #[test]
    fn expired_listener_prepares_but_waits_for_a_live_replacement() {
        let (expired, current) = credentials();
        let source = SharedTlsConfig::new(Some(expired));
        let listener = SharedTlsListener::prepare(source.clone(), None).unwrap();
        assert!(
            listener.config().is_err(),
            "expired material cannot authorize TLS"
        );
        source.replace(TlsPolicy::Configured(current.clone()));
        let (_, original) = listener.config().unwrap();
        assert!(source.is_current(&original));
        source.replace(TlsPolicy::Rejected("withdrawn"));
        assert!(
            listener.config().is_err(),
            "withdrawal must reach the listener"
        );
        source.replace(TlsPolicy::Configured(current));
        assert!(listener.config().is_ok());
        assert!(
            !source.is_current(&original),
            "replacement cannot revive an old handshake"
        );
    }

    #[test]
    fn expired_listener_still_validates_its_private_key_before_boot() {
        let (mut expired, current) = credentials();
        expired.key_pem = current.key_pem;
        assert!(SharedTlsListener::prepare(SharedTlsConfig::new(Some(expired)), None).is_err());
        assert!(SharedTlsListener::prepare(SharedTlsConfig::default(), None).is_err());
        let rejected = SharedTlsConfig::default();
        rejected.replace(TlsPolicy::Rejected("withdrawn"));
        assert!(SharedTlsListener::prepare(rejected, None).is_err());
    }
}
