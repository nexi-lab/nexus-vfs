//! Server configurations derived from the node's shared credential source.

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_stream::Stream;

use super::{server_config, FederatedClientCertVerifier, SharedTlsConfig, TlsSnapshot};

struct SharedServerConfig {
    source: SharedTlsConfig,
    ca_pem: Vec<u8>,
    verifier: Arc<FederatedClientCertVerifier>,
    cached: Mutex<Option<(TlsSnapshot, Arc<rustls::ServerConfig>)>>,
}

impl SharedServerConfig {
    fn new(
        source: SharedTlsConfig,
        verifier: Option<Arc<FederatedClientCertVerifier>>,
    ) -> Result<Self, String> {
        source.read(|initial| {
            let tls = initial
                .config()?
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

    fn incoming(
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
    Ok(SharedServerConfig::new(source, verifier)?.incoming(listener))
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
    let prepared = SharedServerConfig::new(source, verifier);
    async move {
        let server = prepared?;
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| e.to_string())?;
        Ok(server.incoming(listener))
    }
}
