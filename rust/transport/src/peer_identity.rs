//! Recover the mTLS peer's identity from the client certificate tonic
//! already validated.
//!
//! The cluster's gRPC servers set `client_ca_root(..)` (see
//! `raft::transport::server` and `grpc::spawn`), so rustls rejects any
//! client whose certificate does not chain to the cluster CA *before*
//! a handler runs. That verified identity was previously discarded:
//! handlers called `into_inner()` and never looked at the connection.
//! This module is the (small) bridge that keeps it.
//!
//! Identity is carried in the certificate two ways:
//!
//! * **CN** — `nexus-zone-{zone}-node-{hostname}`, always present, but
//!   it names the *host*, not the node.
//! * **URI SAN** — `nexus://zone/{zone_id}/node/{node_id}`, pinned by
//!   `certgen::generate_node_cert`. This is the machine-readable one.
//!
//! Certs minted before the URI SAN existed still authenticate (the chain
//! is what proves membership); they simply resolve to a `PeerIdentity`
//! with `node_id: None`.

use crate::auth::PeerIdentity;
use nexus_raft::transport::parse_node_identity_uri;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::Request;

/// Extract the peer identity from a request's TLS connection info.
///
/// `None` for plaintext connections and for TLS connections with no
/// client certificate — both of which mean "this caller has not proven
/// cluster membership", so a strict provider must fall back to the token
/// plane.
///
/// Must be called *before* `Request::into_inner()`, which drops the
/// extensions along with the rest of the envelope.
pub fn from_request<T>(req: &Request<T>) -> Option<PeerIdentity> {
    let tls = req.extensions().get::<TlsConnectInfo<TcpConnectInfo>>()?;
    let certs = tls.peer_certs()?;
    from_der(certs.first()?.as_ref())
}

/// Parse a DER-encoded leaf certificate into a [`PeerIdentity`].
///
/// Split out from [`from_request`] so it is testable without a live TLS
/// handshake. Returns `None` only when the DER does not parse — a cert
/// that parses but carries no recognizable SAN still yields an identity
/// (CN only), because the chain has already been verified by then.
pub fn from_der(der: &[u8]) -> Option<PeerIdentity> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();

    let (zone_id, node_id) = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|gn| match gn {
                GeneralName::URI(uri) => parse_node_identity_uri(uri),
                _ => None,
            })
        })
        .map_or((None, None), |(z, n)| (Some(z), Some(n)));

    Some(PeerIdentity {
        common_name,
        node_id,
        zone_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{generate_node_cert, generate_zone_ca};

    /// A real cert minted by certgen must round-trip through `from_der`
    /// with both its CN and its pinned node id — this is the contract
    /// the peer identity plane rests on.
    #[test]
    fn from_der_recovers_cn_and_node_id_from_a_certgen_cert() {
        let (ca_pem, ca_key_pem) = generate_zone_ca("sharedzone").unwrap();
        let (cert_pem, _key) =
            generate_node_cert(7, "sharedzone", &ca_pem, &ca_key_pem, &[], Some("win-box"))
                .unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let id = from_der(pem.contents()).expect("certgen cert must parse");

        assert_eq!(id.common_name, "nexus-zone-sharedzone-node-win-box");
        assert_eq!(id.node_id, Some(7), "node id must be pinned in the URI SAN");
        assert_eq!(id.zone_id, Some("sharedzone".to_string()));
        assert_eq!(id.display_id(), "node/7");
    }

    /// A cert with no identity SAN (minted before it existed) still
    /// authenticates — the verified chain is what proves membership —
    /// it just cannot name itself.
    #[test]
    fn from_der_accepts_a_cert_without_the_identity_san() {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
        };

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "nexus-zone-root-node-legacy");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();

        let pem = pem::parse(cert.pem()).unwrap();
        let id = from_der(pem.contents()).expect("legacy cert must still parse");

        assert_eq!(id.common_name, "nexus-zone-root-node-legacy");
        assert_eq!(id.node_id, None);
        assert_eq!(id.display_id(), "nexus-zone-root-node-legacy");
    }

    #[test]
    fn from_der_rejects_garbage() {
        assert!(from_der(b"not a certificate").is_none());
    }
}
