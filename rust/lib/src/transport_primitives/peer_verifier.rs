//! Bind a peer channel to its expected signed replication identity.

use std::{num::NonZeroU64, sync::Arc};

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
pub(super) struct PeerVerifier {
    expected: ExpectedPeer,
    chain: Arc<WebPkiServerVerifier>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ExpectedPeer {
    Replication(NonZeroU64),
    Node(NonZeroU64),
}

impl ExpectedPeer {
    fn id(self) -> NonZeroU64 {
        match self {
            Self::Replication(id) | Self::Node(id) => id,
        }
    }
}

impl PeerVerifier {
    pub(super) fn new(ca: &[u8], expected: ExpectedPeer) -> Result<Arc<Self>, String> {
        let mut roots = RootCertStore::empty();
        let certificates = pem::parse_many(ca).map_err(|error| error.to_string())?;
        if certificates.is_empty() {
            return Err("missing peer trust anchor".into());
        }
        for certificate in certificates {
            if certificate.tag() != "CERTIFICATE" {
                return Err("peer trust anchor must contain certificates".into());
            }
            roots
                .add(CertificateDer::from(certificate.into_contents()))
                .map_err(|error| error.to_string())?;
        }
        let chain = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Arc::new(Self { expected, chain }))
    }

    fn peer_name(&self, der: &[u8]) -> Result<ServerName<'static>, String> {
        let (rest, leaf) = X509Certificate::from_der(der).map_err(|error| error.to_string())?;
        if !rest.is_empty() {
            return Err("trailing bytes in peer certificate".into());
        }
        let (node, name) = match super::replica_node_id_from_x509(&leaf)? {
            Some(node) => {
                if matches!(self.expected, ExpectedPeer::Node(_)) {
                    return Err("server certificate must name a cluster Node".into());
                }
                (
                    node,
                    super::user_runtime_name_from_x509(&leaf)?
                        .ok_or("replica requires owner runtime server capability")?,
                )
            }
            None => (
                super::node_identity_from_x509(&leaf)?.1,
                super::TlsConfig::CLUSTER_SERVER_NAME.to_owned(),
            ),
        };
        if node != self.expected.id().get() {
            return Err("server certificate does not name the expected replication peer".into());
        }
        ServerName::try_from(name).map_err(|error| error.to_string())
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let name = self
            .peer_name(end_entity.as_ref())
            .map_err(Error::General)?;
        // The expected ID is additional to WebPKI's chain, lifetime, EKU and
        // DNS verification. Both TLS handshake signature paths delegate too.
        self.chain
            .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.chain.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.chain.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}
