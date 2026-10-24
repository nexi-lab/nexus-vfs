//! Request-bound identity for the experimental collaboration protocol.
//!
//! A decoded public address, an ephemeral owner/session credential and a durable
//! Agent are different things. Only this module's TLS request entry constructs
//! an authenticated Agent. The caller must supply native current-authority
//! policy on every admission; signature/time checks alone do not prove current
//! CRL, issuer continuity or space permission. Nothing installs this feature in
//! the daemon or changes legacy peer classification.

use a2a::domain_address::AgentAddress;
use lib::transport_primitives::{
    authorship::cert_signed_by, FederatedClientCertVerifier, ForeignCaAnchor,
};
use sha2::{Digest, Sha256};
use tonic::{
    transport::server::{TcpConnectInfo, TlsConnectInfo},
    Request,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::peer_identity::from_der;

/// A certificate identity to inspect in native current-authority policy. Its
/// fields are derived from the actual TLS leaf and the currently installed
/// registered anchor, never from the RPC body, issuer DN or a display label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateAgent {
    address: AgentAddress,
    trust_domain: Option<String>,
    serial: Vec<u8>,
    leaf_sha256: [u8; 32],
}

impl CertificateAgent {
    pub fn address(&self) -> &AgentAddress {
        &self.address
    }
    pub fn trust_domain(&self) -> Option<&str> {
        self.trust_domain.as_deref()
    }
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
    pub fn leaf_sha256(&self) -> &[u8; 32] {
        &self.leaf_sha256
    }
}

/// Trusted composition-root policy, not a caller-provided predicate or grant.
/// Implementations must check the applicable current issuer/CRL state and fail
/// closed when that state cannot be established, including for foreign issuers.
/// The legacy cluster-only serial set is not a foreign-CRL implementation.
/// Space/participant authorization remains an additional required decision.
pub trait CurrentAgentAuthority: Send + Sync {
    fn check_current(&self, agent: &CertificateAgent) -> Result<(), String>;
}

/// No public constructor or deserializer: only an admitted TLS request produces
/// this proof. It is request-scoped evidence, never a cached grant or a promise
/// of atomic revocation through a later append.
#[derive(Debug)]
pub struct AuthenticatedAgent {
    certificate: CertificateAgent,
}

impl AuthenticatedAgent {
    pub fn certificate(&self) -> &CertificateAgent {
        &self.certificate
    }
    pub fn address(&self) -> &AgentAddress {
        self.certificate.address()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    UnsupportedCredentialPlane,
    MissingTlsLeaf,
    InvalidCertificate,
    ExpiredCertificate,
    UntrustedAuthority,
    AmbiguousAuthority,
    NotDurableAgent,
    InvalidAddress,
    CurrentAuthorityDenied,
}

/// Authenticate the actual mTLS caller for one admission. An absent TLS leaf
/// fails explicitly: bearer tokens, Node credentials, runtime delegation and
/// session credentials are not silently converted into durable Agent leaves.
pub fn authenticate_request<T: crate::grpc::AuthedRequest>(
    request: &Request<T>,
    verifier: &FederatedClientCertVerifier,
    current: &dyn CurrentAgentAuthority,
) -> Result<AuthenticatedAgent, IdentityError> {
    if !request.get_ref().auth_token().is_empty()
        || request
            .metadata()
            .get_bin(crate::runtime_scope::RUNTIME_DELEGATION_METADATA_KEY)
            .is_some()
    {
        return Err(IdentityError::UnsupportedCredentialPlane);
    }
    let tls = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .ok_or(IdentityError::MissingTlsLeaf)?;
    let certs = tls.peer_certs().ok_or(IdentityError::MissingTlsLeaf)?;
    let leaf = certs.first().ok_or(IdentityError::MissingTlsLeaf)?;
    let anchors = verifier.foreign_anchors();
    admit_leaf(leaf.as_ref(), verifier.cluster_ca_der(), &anchors, current)
}

// Private: parsing a publicly readable certificate does not establish key
// possession. Production calls reach this only through the TLS request above.
fn admit_leaf(
    der: &[u8],
    local_anchor: &[u8],
    foreign: &[ForeignCaAnchor],
    current: &dyn CurrentAgentAuthority,
) -> Result<AuthenticatedAgent, IdentityError> {
    let (rest, leaf) =
        X509Certificate::from_der(der).map_err(|_| IdentityError::InvalidCertificate)?;
    if !rest.is_empty() {
        return Err(IdentityError::InvalidCertificate);
    }
    if !leaf.validity().is_valid() {
        return Err(IdentityError::ExpiredCertificate);
    }

    let mut matched: Option<([u8; 32], Option<&str>)> = None;
    for (anchor_der, domain) in std::iter::once((local_anchor, None)).chain(
        foreign
            .iter()
            .map(|a| (a.ca_cert_der.as_slice(), Some(a.trust_domain_id.as_str()))),
    ) {
        let (rest, anchor) =
            X509Certificate::from_der(anchor_der).map_err(|_| IdentityError::InvalidCertificate)?;
        if !rest.is_empty() {
            return Err(IdentityError::InvalidCertificate);
        }
        if !cert_signed_by(&leaf, &anchor) {
            continue;
        }
        let authority: [u8; 32] = Sha256::digest(anchor.public_key().raw).into();
        if let Some(previous) = matched {
            if previous != (authority, domain) {
                return Err(IdentityError::AmbiguousAuthority);
            }
        } else {
            matched = Some((authority, domain));
        }
    }
    let (authority, domain) = matched.ok_or(IdentityError::UntrustedAuthority)?;
    let peer = from_der(der).ok_or(IdentityError::InvalidCertificate)?;
    if peer.node_id.is_some()
        || peer.zone_id.is_some()
        || peer.owner.is_some()
        || peer.runtime_server_name.is_some()
    {
        return Err(IdentityError::NotDurableAgent);
    }
    let subject = peer.agent_name.ok_or(IdentityError::NotDurableAgent)?;
    // Legacy readers find the first matching SAN. A collaboration credential
    // must name exactly one Nexus identity, with no second actor/owner role.
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| IdentityError::InvalidCertificate)?
        .ok_or(IdentityError::NotDurableAgent)?;
    let identities: Vec<_> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::URI(uri) if uri.starts_with("nexus://") => {
                Some(*uri)
            }
            _ => None,
        })
        .collect();
    if identities != [format!("nexus://agent/{subject}").as_str()] {
        return Err(IdentityError::NotDurableAgent);
    }
    let certificate = CertificateAgent {
        address: AgentAddress::new(authority, subject)
            .map_err(|_| IdentityError::InvalidAddress)?,
        trust_domain: domain.map(str::to_owned),
        serial: leaf.raw_serial().to_vec(),
        leaf_sha256: Sha256::digest(der).into(),
    };
    current
        .check_current(&certificate)
        .map_err(|_| IdentityError::CurrentAuthorityDenied)?;
    Ok(AuthenticatedAgent { certificate })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{
        generate_agent_cert, generate_node_cert, generate_session_agent_cert, generate_zone_ca,
    };
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Current {
        deny: AtomicBool,
        calls: AtomicUsize,
    }
    impl Current {
        fn new() -> Self {
            Self {
                deny: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
            }
        }
    }
    impl CurrentAgentAuthority for Current {
        fn check_current(&self, _: &CertificateAgent) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.deny.load(Ordering::SeqCst) {
                Err("revoked or unavailable".into())
            } else {
                Ok(())
            }
        }
    }
    fn der(pem: &[u8]) -> Vec<u8> {
        pem::parse(pem).unwrap().into_contents()
    }
    fn renewed_anchors() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let first = p.self_signed(&key).unwrap();
        p.not_after = rcgen::date_time_ymd(2045, 1, 1);
        let second = p.self_signed(&key).unwrap();
        (
            first.pem().into_bytes(),
            second.pem().into_bytes(),
            key.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn same_key_ca_renewal_keeps_address_but_conflicting_domains_refuse_in_any_order() {
        let (local, _) = generate_zone_ca("local").unwrap();
        let (first, second, key) = renewed_anchors();
        assert_ne!(der(&first), der(&second));
        let (leaf, _) = generate_agent_cert("same-name", &first, &key).unwrap();
        let current = Current::new();
        let a = ForeignCaAnchor::new("edge", der(&first));
        let b = ForeignCaAnchor::new("edge", der(&second));
        let read =
            |anchors: &[ForeignCaAnchor]| admit_leaf(&der(&leaf), &der(&local), anchors, &current);
        let one = read(std::slice::from_ref(&a)).unwrap();
        assert_eq!(
            one.address(),
            read(std::slice::from_ref(&b)).unwrap().address()
        );
        assert_eq!(
            one.address(),
            read(&[a.clone(), b.clone()]).unwrap().address()
        );
        let conflict = ForeignCaAnchor::new("other-domain", b.ca_cert_der.clone());
        for anchors in [vec![a.clone(), conflict.clone()], vec![conflict, a]] {
            assert_eq!(
                read(&anchors).unwrap_err(),
                IdentityError::AmbiguousAuthority
            );
        }
    }

    #[test]
    fn local_and_foreign_same_key_is_ambiguous_and_same_name_distinct_keys_stay_distinct() {
        let (local, key) = generate_zone_ca("local").unwrap();
        let (other, other_key) = generate_zone_ca("other").unwrap();
        let (a, _) = generate_agent_cert("agent", &local, &key).unwrap();
        let (b, _) = generate_agent_cert("agent", &other, &other_key).unwrap();
        let current = Current::new();
        let foreign = [ForeignCaAnchor::new("edge", der(&other))];
        let local_id = admit_leaf(&der(&a), &der(&local), &foreign, &current).unwrap();
        let foreign_id = admit_leaf(&der(&b), &der(&local), &foreign, &current).unwrap();
        assert_ne!(local_id.address(), foreign_id.address());
        assert_eq!(foreign_id.certificate().trust_domain(), Some("edge"));
        assert_eq!(
            admit_leaf(
                &der(&a),
                &der(&local),
                &[ForeignCaAnchor::new("alias", der(&local))],
                &current
            )
            .unwrap_err(),
            IdentityError::AmbiguousAuthority
        );
    }

    #[test]
    fn current_policy_is_rechecked_and_removed_anchor_does_not_reach_it() {
        let (local, _) = generate_zone_ca("local").unwrap();
        let (ca, key) = generate_zone_ca("edge").unwrap();
        let (leaf, _) = generate_agent_cert("agent", &ca, &key).unwrap();
        let anchors = [ForeignCaAnchor::new("edge", der(&ca))];
        let current = Current::new();
        admit_leaf(&der(&leaf), &der(&local), &anchors, &current).unwrap();
        current.deny.store(true, Ordering::SeqCst);
        assert_eq!(
            admit_leaf(&der(&leaf), &der(&local), &anchors, &current).unwrap_err(),
            IdentityError::CurrentAuthorityDenied
        );
        assert_eq!(current.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            admit_leaf(&der(&leaf), &der(&local), &[], &current).unwrap_err(),
            IdentityError::UntrustedAuthority
        );
        assert_eq!(current.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn node_and_owner_session_are_not_durable_agents() {
        let (ca, key) = generate_zone_ca("root").unwrap();
        let (node, _) = generate_node_cert(7, "root", &ca, &key, &[], None).unwrap();
        let (session, _) =
            generate_session_agent_cert("session-test", "owner", 3600, &ca, &key).unwrap();
        let current = Current::new();
        for leaf in [node, session] {
            assert_eq!(
                admit_leaf(&der(&leaf), &der(&ca), &[], &current).unwrap_err(),
                IdentityError::NotDurableAgent
            );
        }
        assert_eq!(current.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_tls_or_malformed_certificate_never_becomes_an_authenticated_agent() {
        let (ca, _) = generate_zone_ca("root").unwrap();
        let verifier = FederatedClientCertVerifier::new(&ca).unwrap();
        let current = Current::new();
        assert_eq!(
            authenticate_request(
                &Request::new(kernel::kernel::vfs_proto::PingRequest::default()),
                &verifier,
                &current
            )
            .unwrap_err(),
            IdentityError::MissingTlsLeaf
        );
        assert_eq!(
            admit_leaf(b"not a certificate", &der(&ca), &[], &current).unwrap_err(),
            IdentityError::InvalidCertificate
        );
        assert_eq!(current.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn duplicate_identity_sans_and_expired_leaves_refuse_before_current_policy() {
        use rcgen::{Issuer, SanType};
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let issuer = Issuer::from_ca_cert_pem(
            std::str::from_utf8(&ca).unwrap(),
            KeyPair::from_pem(std::str::from_utf8(&ca_key).unwrap()).unwrap(),
        )
        .unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let identity =
            |name: &str| SanType::URI(format!("nexus://agent/{name}").try_into().unwrap());
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![identity("one"), identity("two")];
        let duplicate = p.signed_by(&key, &issuer).unwrap();
        let current = Current::new();
        assert_eq!(
            admit_leaf(duplicate.der(), &der(&ca), &[], &current).unwrap_err(),
            IdentityError::NotDurableAgent
        );
        p.subject_alt_names = vec![identity("one")];
        p.not_before = rcgen::date_time_ymd(2000, 1, 1);
        p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let expired = p.signed_by(&key, &issuer).unwrap();
        assert_eq!(
            admit_leaf(expired.der(), &der(&ca), &[], &current).unwrap_err(),
            IdentityError::ExpiredCertificate
        );
        assert_eq!(current.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bearer_and_gateway_carriers_cannot_upgrade_into_certificate_authority() {
        let (ca, _) = generate_zone_ca("root").unwrap();
        let verifier = FederatedClientCertVerifier::new(&ca).unwrap();
        let current = Current::new();
        let mut message = kernel::kernel::vfs_proto::PingRequest::default();
        message.auth_token = "bogus-token".into();
        assert_eq!(
            authenticate_request(&Request::new(message), &verifier, &current).unwrap_err(),
            IdentityError::UnsupportedCredentialPlane
        );
        let mut request = Request::new(kernel::kernel::vfs_proto::PingRequest::default());
        request.metadata_mut().insert_bin(
            crate::runtime_scope::RUNTIME_DELEGATION_METADATA_KEY,
            tonic::metadata::MetadataValue::from_bytes(b"untrusted"),
        );
        assert_eq!(
            authenticate_request(&request, &verifier, &current).unwrap_err(),
            IdentityError::UnsupportedCredentialPlane
        );
        assert_eq!(current.calls.load(Ordering::SeqCst), 0);
    }

    /// A real tonic/rustls connection, reusing native VFS Ping as its wire
    /// fixture. The interceptor checks request TLS evidence; the atomic policy
    /// is deliberately a test stand-in, not a foreign-CRL implementation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn established_mtls_connection_rechecks_policy_and_removed_anchor() {
        use crate::collaboration_access::SpaceAuthorizer;
        use a2a::{
            collaboration_policy::{CollaborationOperation, SpacePolicy, SpacePolicyStore},
            domain_address::ConversationAddress,
        };
        use futures::StreamExt;
        use kernel::kernel::{
            vfs_proto::{
                nexus_vfs_service_client::NexusVfsServiceClient,
                nexus_vfs_service_server::NexusVfsServiceServer, PingRequest,
            },
            Kernel,
        };
        use lib::transport_primitives::{federated_tls_incoming, server_config};
        use nexus_raft::{collaboration_store::RaftSpacePolicyStore, raft::ZoneRaftRegistry};
        use std::sync::{Arc, Mutex, OnceLock};
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server};

        let (local, local_key) = generate_zone_ca("root").unwrap();
        let (foreign, foreign_key) = generate_zone_ca("edge").unwrap();
        let (server_cert, server_key) =
            generate_node_cert(1, "root", &local, &local_key, &[], None).unwrap();
        let (client_cert, client_key) =
            generate_agent_cert("existing-agent", &foreign, &foreign_key).unwrap();
        let verifier = FederatedClientCertVerifier::new(&local).unwrap();
        verifier
            .set_foreign_cas(&[ForeignCaAnchor::new("edge", der(&foreign))])
            .unwrap();
        let local_der = der(&local);
        let (_, local_anchor) = X509Certificate::from_der(&local_der).unwrap();
        let host: [u8; 32] = Sha256::digest(local_anchor.public_key().raw).into();
        let client_identity = admit_leaf(
            &der(&client_cert),
            &local_der,
            &verifier.foreign_anchors(),
            &Current::new(),
        )
        .unwrap();
        let other = AgentAddress::new(host, "other-agent".into()).unwrap();
        let space = "0123456789abcdef0123456789abcdef";
        let pair = ConversationAddress::new(
            space.into(),
            client_identity.address().clone(),
            other.clone(),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let registry = ZoneRaftRegistry::new(directory.path().to_path_buf(), 1);
        let runtime = tokio::runtime::Handle::current();
        let node = registry
            .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
            .unwrap();
        node.campaign().await.unwrap();
        let store = Arc::new(RaftSpacePolicyStore::new(node, runtime));
        let expires: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();
        store
            .create(
                &SpacePolicy::new(
                    space.into(),
                    host,
                    "collab-one".into(),
                    vec![client_identity.address().clone(), other],
                    0,
                    expires + 60_000,
                )
                .unwrap(),
            )
            .unwrap();
        let current = Arc::new(Current::new());
        let admitted = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::new(OnceLock::new());
        slot.set(verifier.clone()).unwrap();
        // The auth crate depends on transport; importing its provider into a
        // transport unit test creates two trait identities. This Ping-only
        // fixture needs no authorization state and never returns system/admin.
        struct PingPeer;
        impl crate::auth::AuthProvider for PingPeer {
            fn resolve(
                &self,
                credentials: &crate::auth::AuthCredentials<'_>,
            ) -> Result<contracts::OperationContext, tonic::Status> {
                if !credentials.token.is_empty() {
                    return Err(tonic::Status::unauthenticated("no bearer in this fixture"));
                }
                let agent = credentials
                    .peer
                    .and_then(|peer| peer.resolved_agent_id())
                    .ok_or_else(|| tonic::Status::unauthenticated("Agent peer required"))?;
                Ok(contracts::OperationContext::new(
                    &agent,
                    "root",
                    false,
                    Some(&agent),
                    false,
                ))
            }
        }
        let service = crate::grpc::build_vfs_service(
            Arc::new(Kernel::new()),
            Arc::new(PingPeer),
            slot,
            crate::grpc::DataPlaneReady::open(),
            "collaboration-tls-fixture",
            None,
        );
        let gate_verifier = verifier.clone();
        let gate_current = current.clone();
        let gate_admitted = admitted.clone();
        let gate_store = store.clone();
        let service =
            NexusVfsServiceServer::with_interceptor(service, move |request: Request<()>| {
                let (metadata, extensions, ()) = request.into_parts();
                let request = Request::from_parts(metadata, extensions, PingRequest::default());
                // This is an admission fixture over Ping, not a transcript
                // operation or proof of an installed collaboration mount.
                let principal = SpaceAuthorizer::new(
                    &gate_verifier,
                    gate_current.as_ref(),
                    gate_store.as_ref(),
                    &host,
                    "collab-one",
                )
                .authorize(
                    &request,
                    &pair.transcript(),
                    CollaborationOperation::ReadTranscript,
                )
                .map_err(|_| tonic::Status::permission_denied("collaboration admission refused"))?;
                gate_admitted
                    .lock()
                    .unwrap()
                    .push(principal.actor().clone());
                let (metadata, extensions, _) = request.into_parts();
                Ok(Request::from_parts(metadata, extensions, ()))
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let count = handshakes.clone();
        let incoming = federated_tls_incoming(
            listener,
            Arc::new(server_config(verifier.clone(), &server_cert, &server_key).unwrap()),
        )
        .map(move |result| {
            if result.is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
            result
        });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .timeout(std::time::Duration::from_secs(5))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(Certificate::from_pem(local))
                    .identity(Identity::from_pem(client_cert, client_key)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = NexusVfsServiceClient::new(channel);
        client.ping(PingRequest::default()).await.unwrap();
        store.revoke(space).unwrap();
        assert_eq!(
            client
                .ping(PingRequest::default())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        current.deny.store(true, Ordering::SeqCst);
        assert_eq!(
            client
                .ping(PingRequest::default())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        verifier.set_foreign_cas(&[]).unwrap();
        assert_eq!(
            client
                .ping(PingRequest::default())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            handshakes.load(Ordering::SeqCst),
            1,
            "same TLS channel, no reconnect or retry"
        );
        assert_eq!(
            current.calls.load(Ordering::SeqCst),
            3,
            "removed anchor refuses before policy"
        );
        assert_eq!(admitted.lock().unwrap().len(), 1);
        stop.send(()).unwrap();
        drop(client);
        server.await.unwrap();
        drop(store);
        registry.shutdown_all();
        drop(registry);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
