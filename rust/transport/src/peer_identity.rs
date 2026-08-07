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
use lib::transport_primitives::authorship::{agent_name_from_x509, cert_signed_by};
use lib::transport_primitives::ForeignCaAnchor;
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
    Some(from_x509(&cert))
}

/// Extract the identity fields from an already-parsed cert. Split from
/// [`from_der`] so [`classify_peer_cert`] — which must parse the cert anyway to
/// verify its issuer — reuses the exact same extraction without parsing twice.
///
/// `trust_domain` is always `None` here: a bare cert states who it is, not which
/// CA vouched for it. Only [`classify_peer_cert`] sets a foreign domain, because
/// that needs the CA the cert chained to, which the cert alone cannot show.
fn from_x509(cert: &x509_parser::certificate::X509Certificate) -> PeerIdentity {
    use x509_parser::prelude::*;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or_default()
        .to_string();

    // A cert carries at most one identity URI SAN, and the node / agent
    // namespaces are disjoint (nexus://zone/ vs nexus://agent/), so at most
    // one of node vs agent ends up set.
    let mut zone_id = None;
    let mut node_id = None;
    if let Some(san) = cert.subject_alternative_name().ok().flatten() {
        for gn in san.value.general_names.iter() {
            if let GeneralName::URI(uri) = gn {
                if let Some((z, n)) = parse_node_identity_uri(uri) {
                    zone_id = Some(z);
                    node_id = Some(n);
                }
            }
        }
    }
    // The agent-identity SAN is read one way, via the shared library helper
    // (the same one `authorship::verify` uses), so a node cert and an agent
    // cert are told apart identically here and at message-verify time. The
    // cert is a pure identity — there is no authorization extension to read.
    let agent_name = agent_name_from_x509(cert);

    // The serial is what a CRL revokes; carry it so the provider can reject a
    // revoked agent cert (the raw bytes match `certgen::serial_from_cert_pem`).
    let serial = cert.raw_serial().to_vec();

    PeerIdentity {
        common_name,
        node_id,
        zone_id,
        agent_name,
        trust_domain: None,
        serial,
    }
}

/// Why a TLS-verified peer cert could not be classified into an identity.
#[derive(Debug, PartialEq, Eq)]
pub enum ClassifyError {
    /// The leaf DER did not parse.
    Unparseable,
    /// The cert chains to neither the cluster CA nor any registered foreign CA.
    /// rustls should have rejected it before a handler ran, so this is
    /// defense in depth — a mis-wired trust root fails closed here too.
    UntrustedIssuer,
    /// A registered foreign CA presented a cert that is NOT an agent identity.
    /// A foreign trust domain may vouch only for its agents, never for a cluster
    /// member — this is the invariant that stops a customer's CA from minting a
    /// node (a voter) in our raft.
    ForeignNotAnAgent,
}

/// Classify a TLS-verified peer certificate into a [`PeerIdentity`], deciding
/// **local** (cluster CA) vs **foreign** (a registered foreign CA) by which
/// anchor the cert actually chains to.
///
/// The discriminator is the **signature**, not the issuer name: a foreign CA
/// controls its own issuer DN and could spell it identically to the cluster CA,
/// so only verifying the cert's signature under each candidate CA's public key
/// is sound. (Same primitive `authorship::verify` trusts.)
///
/// * Chains to the cluster CA → the identity as-is (node or agent), `trust_domain` `None`.
/// * Chains to a registered foreign CA and is an agent → a foreign agent:
///   `trust_domain` set to that anchor's domain, node/zone forced `None`.
/// * Chains to a foreign CA but is not an agent → [`ClassifyError::ForeignNotAnAgent`].
/// * Chains to nothing registered → [`ClassifyError::UntrustedIssuer`].
///
/// Runs once per handshake (not per message): the cluster CA is tried first —
/// the common case, one signature verify — and the foreign anchors only if that
/// misses. `foreign_anchors` is the caller's cached set (rebuilt on an
/// apply-observer invalidation), so classification does no store I/O.
pub fn classify_peer_cert(
    der: &[u8],
    cluster_ca_der: &[u8],
    foreign_anchors: &[ForeignCaAnchor],
) -> Result<PeerIdentity, ClassifyError> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| ClassifyError::Unparseable)?;

    // Local first — the common case, and a hit is a single signature verify.
    if chains_to(&cert, cluster_ca_der) {
        return Ok(from_x509(&cert));
    }

    // Foreign — whichever registered CA actually signed it names its domain.
    for anchor in foreign_anchors {
        if chains_to(&cert, &anchor.ca_cert_der) {
            let mut id = from_x509(&cert);
            if id.agent_name.is_none() {
                // A foreign CA vouching for a node (or a SAN-less) cert is the
                // exact thing the two-anchor split forbids.
                return Err(ClassifyError::ForeignNotAnAgent);
            }
            // A foreign identity is agent-only, always. Force the member fields
            // off even though an agent cert already lacks them, so the invariant
            // holds regardless of what the SAN parser produced.
            id.node_id = None;
            id.zone_id = None;
            id.trust_domain = Some(anchor.trust_domain_id.clone());
            return Ok(id);
        }
    }

    Err(ClassifyError::UntrustedIssuer)
}

/// Does `cert`'s signature verify under the public key in `ca_der`? nexus certs
/// are signed directly by the zone CA (one hop, no intermediates), so this
/// single check is the whole chain. Delegates to [`authorship::cert_signed_by`]
/// — the one definition `authorship::verify` also uses — so message-verify and
/// TLS-classify agree on "chains to CA". `false` if the CA DER does not parse.
fn chains_to(cert: &x509_parser::certificate::X509Certificate, ca_der: &[u8]) -> bool {
    use x509_parser::prelude::*;
    match X509Certificate::from_der(ca_der) {
        Ok((_, ca)) => cert_signed_by(cert, &ca),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{generate_agent_cert, generate_node_cert, generate_zone_ca};

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
        assert_eq!(id.agent_name, None, "a node cert is not an agent");
    }

    /// An agent-identity cert resolves to a peer whose `agent_name` is set and
    /// whose node fields are `None` — the disjoint half of the round-trip
    /// above. This is what lets a client-cert handshake on the agent bind
    /// produce an `agent_id`.
    #[test]
    fn from_der_recovers_agent_name_from_an_agent_cert() {
        let (ca_pem, ca_key_pem) = generate_zone_ca("sharedzone").unwrap();
        let (cert_pem, _key) = generate_agent_cert("win-ai", &ca_pem, &ca_key_pem).unwrap();

        let pem = pem::parse(&cert_pem).unwrap();
        let id = from_der(pem.contents()).expect("agent cert must parse");

        // The cert is a pure identity: it names the agent and nothing else.
        assert_eq!(id.agent_name, Some("win-ai".to_string()));
        assert_eq!(id.node_id, None, "an agent cert has no node id");
        assert_eq!(id.zone_id, None);
        assert_eq!(id.display_id(), "agent/win-ai");
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

    // --- cross-org classification (`classify_peer_cert`) -------------------

    /// PEM bytes → DER (the shape `classify_peer_cert` takes), via the same
    /// `pem::parse` the other tests use.
    fn der(pem_bytes: &[u8]) -> Vec<u8> {
        pem::parse(pem_bytes).unwrap().contents().to_vec()
    }

    fn anchor(domain: &str, ca_pem: &[u8]) -> ForeignCaAnchor {
        ForeignCaAnchor::new(domain, der(ca_pem))
    }

    /// A cluster-CA cert (node or agent) classifies LOCAL — `trust_domain` stays
    /// `None` and the node/agent fields are exactly what `from_der` recovers.
    #[test]
    fn a_cluster_ca_cert_is_local() {
        let (ca_pem, ca_key) = generate_zone_ca("root").unwrap();
        let (node_pem, _) =
            generate_node_cert(7, "root", &ca_pem, &ca_key, &[], Some("win")).unwrap();
        let (agent_pem, _) = generate_agent_cert("win-ai", &ca_pem, &ca_key).unwrap();
        let cluster_ca = der(&ca_pem);

        let node = classify_peer_cert(&der(&node_pem), &cluster_ca, &[]).expect("node is local");
        assert_eq!(node.node_id, Some(7));
        assert_eq!(node.trust_domain, None, "a cluster cert is not foreign");

        let agent = classify_peer_cert(&der(&agent_pem), &cluster_ca, &[]).expect("agent is local");
        assert_eq!(agent.agent_name.as_deref(), Some("win-ai"));
        assert_eq!(agent.trust_domain, None);
        assert_eq!(agent.display_id(), "agent/win-ai");
    }

    /// A registered foreign CA's AGENT classifies FOREIGN: `trust_domain` set,
    /// member fields `None`, and the id renders qualified.
    #[test]
    fn a_registered_foreign_agent_is_foreign_and_qualified() {
        let (cluster_pem, _cluster_key) = generate_zone_ca("root").unwrap();
        let (foreign_pem, foreign_key) = generate_zone_ca("hospital").unwrap();
        let (agent_pem, _) = generate_agent_cert("cardio", &foreign_pem, &foreign_key).unwrap();
        let anchors = [anchor("hospital-a", &foreign_pem)];

        let id = classify_peer_cert(&der(&agent_pem), &der(&cluster_pem), &anchors)
            .expect("a registered foreign agent classifies");
        assert_eq!(id.agent_name.as_deref(), Some("cardio"));
        assert_eq!(id.trust_domain.as_deref(), Some("hospital-a"));
        assert_eq!(id.node_id, None, "a foreign identity is never a member");
        assert_eq!(id.zone_id, None);
        assert_eq!(id.display_id(), "hospital-a/agent/cardio");
    }

    /// The wiring data path: a foreign agent registered on the VERIFIER (via
    /// `set_foreign_cas`, as the apply observer does) is classified foreign using
    /// the verifier's own accessors — exactly the call the request path makes:
    /// `classify_peer_cert(der, verifier.cluster_ca_der(), &verifier.foreign_anchors())`.
    /// Proves the admission verifier and the authoritative classifier read the
    /// SAME live foreign set, so an admitted foreign agent is never mis-identified.
    #[test]
    fn verifier_accessors_drive_classification() {
        use lib::transport_primitives::FederatedClientCertVerifier;

        let (cluster_pem, _ck) = generate_zone_ca("root").unwrap();
        let (foreign_pem, foreign_key) = generate_zone_ca("hospital").unwrap();
        let (agent_pem, _) = generate_agent_cert("cardio", &foreign_pem, &foreign_key).unwrap();
        let agent_der = der(&agent_pem);
        let verifier = FederatedClientCertVerifier::new(&cluster_pem).unwrap();

        // Before register: the classifier fed by the verifier sees no anchors, so
        // the foreign agent is untrusted — matching what the verifier would reject.
        let anchors = verifier.foreign_anchors();
        assert_eq!(
            classify_peer_cert(&agent_der, verifier.cluster_ca_der(), &anchors),
            Err(ClassifyError::UntrustedIssuer)
        );

        // Register → the same accessors now classify it foreign, org-qualified.
        verifier
            .set_foreign_cas(&[anchor("hospital-a", &foreign_pem)])
            .unwrap();
        let anchors = verifier.foreign_anchors();
        let id = classify_peer_cert(&agent_der, verifier.cluster_ca_der(), &anchors)
            .expect("registered → classified foreign");
        assert_eq!(id.trust_domain.as_deref(), Some("hospital-a"));
        assert_eq!(id.display_id(), "hospital-a/agent/cardio");
    }

    /// THE load-bearing invariant: a foreign CA's NODE cert is REJECTED. A
    /// customer's CA must never be able to mint a cluster member (a raft voter),
    /// even though the CA is registered for its agents.
    #[test]
    fn a_foreign_node_cert_is_rejected() {
        let (cluster_pem, _) = generate_zone_ca("root").unwrap();
        let (foreign_pem, foreign_key) = generate_zone_ca("hospital").unwrap();
        // A node cert signed by the foreign CA — a foreign box trying to look
        // like a member of the (its own) cluster.
        let (foreign_node_pem, _) =
            generate_node_cert(1, "hospital", &foreign_pem, &foreign_key, &[], Some("dgx"))
                .unwrap();
        let anchors = [anchor("hospital-a", &foreign_pem)];

        assert_eq!(
            classify_peer_cert(&der(&foreign_node_pem), &der(&cluster_pem), &anchors),
            Err(ClassifyError::ForeignNotAnAgent),
            "a foreign CA may vouch for agents only, never a cluster member"
        );
    }

    /// A cert from an UNregistered CA is rejected (defense in depth — rustls
    /// should have already, but the classifier fails closed regardless).
    #[test]
    fn an_unregistered_ca_is_untrusted() {
        let (cluster_pem, _) = generate_zone_ca("root").unwrap();
        let (stranger_pem, stranger_key) = generate_zone_ca("stranger").unwrap();
        let (agent_pem, _) = generate_agent_cert("x", &stranger_pem, &stranger_key).unwrap();

        assert_eq!(
            classify_peer_cert(&der(&agent_pem), &der(&cluster_pem), &[]),
            Err(ClassifyError::UntrustedIssuer),
            "a cert from no registered CA classifies as untrusted"
        );
    }

    /// The issuer-name-spoof attack: a foreign CA minted with the SAME subject
    /// DN as the cluster CA (`nexus-zone-root-ca`). Its agent must STILL classify
    /// foreign — proving the discriminator is the signature, not the issuer name.
    /// If classification matched on name, this would be a full cluster-member
    /// impersonation.
    #[test]
    fn an_issuer_name_collision_does_not_impersonate_the_cluster() {
        let (cluster_pem, _cluster_key) = generate_zone_ca("root").unwrap();
        // Same zone id → same CA subject DN `nexus-zone-root-ca`, different key.
        let (evil_pem, evil_key) = generate_zone_ca("root").unwrap();
        let (agent_pem, _) = generate_agent_cert("mole", &evil_pem, &evil_key).unwrap();
        let anchors = [anchor("evil-org", &evil_pem)];

        let id = classify_peer_cert(&der(&agent_pem), &der(&cluster_pem), &anchors)
            .expect("the evil agent chains to its own (registered) CA");
        assert_eq!(
            id.trust_domain.as_deref(),
            Some("evil-org"),
            "a name collision must not classify a foreign agent as local"
        );
        assert_eq!(id.node_id, None);
    }

    #[test]
    fn classify_rejects_garbage() {
        let (cluster_pem, _) = generate_zone_ca("root").unwrap();
        assert_eq!(
            classify_peer_cert(b"not a cert", &der(&cluster_pem), &[]),
            Err(ClassifyError::Unparseable)
        );
    }
}
