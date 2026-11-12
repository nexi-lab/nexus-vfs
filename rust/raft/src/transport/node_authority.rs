//! Authenticate cluster Nodes and owner replicas at the replication boundary.
//! Replicas access admitted data zones; control operations retain Node authority.

use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tonic::{
    body::Body,
    codegen::{http, BoxFuture, Service},
    server::NamedService,
    transport::server::{TcpConnectInfo, TlsConnectInfo},
    Status,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/// Signed identity/time/role information, not proof of key possession. Network
/// callers must supply the actual TLS leaf; a public certificate is not auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNodeCertificate {
    pub node_id: u64,
    pub zone_id: String,
    pub serial: Vec<u8>,
}

impl LocalNodeCertificate {
    /// The canonical identity URI the certificate's SAN carries. It names the
    /// Node, not one credential: renewal keeps it while serial and key change.
    pub fn identity_uri(&self) -> String {
        lib::transport_primitives::node_identity_uri(&self.zone_id, self.node_id)
    }
}

/// Identity taken from the authenticated TLS connection.
#[derive(Clone, Copy)]
enum AuthenticatedPeer {
    Node(u64),
    Replica(u64),
}

impl AuthenticatedPeer {
    fn node_id(self) -> u64 {
        match self {
            Self::Node(id) | Self::Replica(id) => id,
        }
    }
}

fn authenticated_peer(extensions: &http::Extensions) -> Result<Option<AuthenticatedPeer>, Status> {
    if let Some(peer) = extensions.get::<AuthenticatedPeer>() {
        return Ok(Some(*peer));
    }
    if extensions.get::<TlsConnectInfo<TcpConnectInfo>>().is_some() {
        return Err(Status::permission_denied(
            "message requires an authenticated replication peer",
        ));
    }
    Ok(None)
}

/// The Node or replica id the TLS connection authenticated, `None` on a
/// plaintext listener.
pub(super) fn authenticated_node_id(extensions: &http::Extensions) -> Result<Option<u64>, Status> {
    Ok(authenticated_peer(extensions)?.map(AuthenticatedPeer::node_id))
}

/// Storage format preparation requires Node authority even on a development
/// listener. Numeric replica identity alone carries no control authority.
pub(super) fn require_authenticated_control_node(
    extensions: &http::Extensions,
) -> Result<(), Status> {
    match authenticated_peer(extensions)? {
        Some(AuthenticatedPeer::Node(_)) => Ok(()),
        _ => Err(Status::permission_denied(
            "storage reader preparation requires a cluster Node mTLS connection",
        )),
    }
}

/// Authorize before parsing payloads, learning routes or reading zone data.
#[inline(never)] // Share admission code across all typed RPC handlers.
pub(super) fn authorize_data_zone(
    extensions: &http::Extensions,
    registry: &crate::raft::ZoneRaftRegistry,
    zone_id: &str,
) -> Result<(), Status> {
    let Some(AuthenticatedPeer::Replica(peer)) = authenticated_peer(extensions)? else {
        return Ok(());
    };
    let denied = || Status::permission_denied("replica is not admitted to the requested data zone");
    contracts::validate_zone_id_for(contracts::ZoneIdUse::TenantCreate, zone_id)
        .map_err(|_| denied())?;
    let node = registry.get_node(zone_id).ok_or_else(denied)?;
    if !node.is_replication_member(peer) {
        return Err(denied());
    }
    Ok(())
}

/// Bind an EC sender to its connection before applying or acknowledging data.
pub(super) fn authorize_ec_sender(
    extensions: &http::Extensions,
    sender: u64,
) -> Result<(), Status> {
    if authenticated_node_id(extensions)?.is_some_and(|peer| peer != sender) {
        return Err(Status::permission_denied(
            "message sender does not match the authenticated Node",
        ));
    }
    Ok(())
}

/// Preserve raft-rs request relaying and return the actual transport peer.
pub(super) fn authorize_raft_sender(
    extensions: &http::Extensions,
    message: &raft::eraftpb::Message,
) -> Result<u64, Status> {
    let Some(peer) = authenticated_node_id(extensions)? else {
        return Ok(message.from);
    };
    if matches!(
        authenticated_peer(extensions)?,
        Some(AuthenticatedPeer::Replica(_))
    ) && message.get_msg_type() == raft::eraftpb::MessageType::MsgPropose
        && message.entries.iter().any(|entry| {
            matches!(
                entry.get_entry_type(),
                raft::eraftpb::EntryType::EntryConfChange
                    | raft::eraftpb::EntryType::EntryConfChangeV2
            )
        })
    {
        return Err(Status::permission_denied(
            "membership proposals require a cluster Node",
        ));
    }
    let is_relayed_request = matches!(
        message.get_msg_type(),
        raft::eraftpb::MessageType::MsgPropose
            | raft::eraftpb::MessageType::MsgReadIndex
            | raft::eraftpb::MessageType::MsgTransferLeader
    );
    if message.from != peer && (!is_relayed_request || message.from == 0) {
        return Err(Status::permission_denied(
            "Raft sender does not match the authenticated Node",
        ));
    }
    Ok(peer)
}

/// Verify against the configured LOCAL cluster anchor, never the union of
/// client-auth anchors or an issuer DN. Foreign-CA registration cannot confer
/// Node authority. This primitive does not add CRL distribution/consensus.
pub fn current_local_node_certificate(
    der: &[u8],
    local_ca_der: &[u8],
) -> Result<LocalNodeCertificate, String> {
    let leaf = current_local_leaf(der, local_ca_der)?;
    node_certificate_identity(&leaf)
}

/// Validate a local-root replica's signed bootstrap identity. An expired leaf
/// can wait for renewal; request and handshake admission still require validity.
pub(crate) fn prepared_local_replication_id(
    der: &[u8],
    local_ca_der: &[u8],
) -> Result<u64, String> {
    let leaf = locally_signed_leaf(der, local_ca_der)?;
    if let Some(id) = lib::transport_primitives::replica_node_id_from_x509(&leaf)? {
        if leaf.validity().not_before > x509_parser::time::ASN1Time::now()
            || leaf.validity().not_after <= leaf.validity().not_before
        {
            return Err("replica certificate has an invalid bootstrap validity window".into());
        }
        return Ok(id);
    }
    current_local_node_certificate(der, local_ca_der).map(|node| node.node_id)
}

fn current_local_peer_certificate(
    der: &[u8],
    local_ca_der: &[u8],
) -> Result<AuthenticatedPeer, String> {
    let certificate = current_local_leaf(der, local_ca_der)?;
    if let Some(id) = lib::transport_primitives::replica_node_id_from_x509(&certificate)? {
        return Ok(AuthenticatedPeer::Replica(id));
    }
    node_certificate_identity(&certificate).map(|node| AuthenticatedPeer::Node(node.node_id))
}

/// The Node a data directory's PEM TLS bundle names, under exactly the checks
/// above: its first certificate is current, signed by the bundle's own CA and
/// carries one canonical Node identity. Boot, operator grants and `doctor`
/// all read a local Node identity through this one function.
pub fn local_node_identity(cert_pem: &[u8], ca_pem: &[u8]) -> Result<LocalNodeCertificate, String> {
    let leaf = lib::transport_primitives::first_certificate_der(cert_pem, "Node")?;
    let ca = lib::transport_primitives::first_certificate_der(ca_pem, "cluster CA")?;
    current_local_node_certificate(&leaf, &ca)
}

fn current_local_leaf<'a>(
    der: &'a [u8],
    local_ca_der: &[u8],
) -> Result<X509Certificate<'a>, String> {
    let leaf = locally_signed_leaf(der, local_ca_der)?;
    if !leaf.validity().is_valid() {
        return Err("Node certificate is malformed or outside its validity window".into());
    }
    Ok(leaf)
}

fn locally_signed_leaf<'a>(
    der: &'a [u8],
    local_ca_der: &[u8],
) -> Result<X509Certificate<'a>, String> {
    let (rest, leaf) = X509Certificate::from_der(der).map_err(|_| "invalid Node certificate")?;
    if !rest.is_empty() {
        return Err("Node certificate is malformed or outside its validity window".into());
    }
    let (rest, ca) =
        X509Certificate::from_der(local_ca_der).map_err(|_| "invalid local cluster CA")?;
    if !rest.is_empty()
        || !ca.validity().is_valid()
        || !lib::transport_primitives::authorship::cert_signed_by(&leaf, &ca)
    {
        return Err("Node certificate is not signed by the local cluster CA".into());
    }
    Ok(leaf)
}

fn node_certificate_identity(leaf: &X509Certificate<'_>) -> Result<LocalNodeCertificate, String> {
    let (zone_id, node_id) = lib::transport_primitives::node_identity_from_x509(leaf)?;
    Ok(LocalNodeCertificate {
        node_id,
        zone_id,
        serial: leaf.raw_serial().to_vec(),
    })
}

#[derive(Clone)]
pub(super) struct NodeControlPolicy {
    local_ca: Option<Arc<[u8]>>,
    local_credentials: Option<(lib::transport_primitives::SharedTlsConfig, Option<Vec<u8>>)>,
}
impl NodeControlPolicy {
    pub(super) fn from_tls(tls: Option<&super::TlsConfig>) -> Result<Self, String> {
        Ok(Self {
            local_credentials: None,
            local_ca: tls
                .map(|t| {
                    lib::transport_primitives::first_certificate_der(&t.ca_pem, "local cluster CA")
                        .map(Arc::from)
                })
                .transpose()?,
        })
    }

    pub(super) fn from_shared_tls(
        source: lib::transport_primitives::SharedTlsConfig,
    ) -> Result<Self, String> {
        let initial = source.snapshot();
        let tls = initial.configured_material()?;
        let mut policy = Self::from_tls(tls)?;
        policy.local_credentials = Some((source, tls.map(|tls| tls.ca_pem.clone())));
        Ok(policy)
    }

    fn check_local_credentials(&self) -> Result<(), Status> {
        if let Some((source, ca)) = &self.local_credentials {
            source.read(|snapshot| -> Result<(), Status> {
                let tls = snapshot.config().map_err(Status::unavailable)?;
                if tls.map(|tls| tls.ca_pem.as_slice()) != ca.as_deref() {
                    return Err(Status::unavailable("local listener trust anchor changed"));
                }
                Ok(())
            })?;
        }
        Ok(())
    }
    fn check(&self, extensions: &http::Extensions) -> Result<Option<AuthenticatedPeer>, Status> {
        // Explicit plaintext/development listeners retain their old contract.
        // They must not host the protected collaboration namespace.
        let Some(ca) = &self.local_ca else {
            return Ok(None);
        };
        let certs = extensions
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|t| t.peer_certs())
            .ok_or_else(|| {
                Status::permission_denied("Raft control requires a local Node mTLS certificate")
            })?;
        let leaf = certs
            .first()
            .ok_or_else(|| Status::permission_denied("missing Node mTLS leaf"))?;
        current_local_peer_certificate(leaf.as_ref(), ca)
            .map(Some)
            .map_err(|_| {
                Status::permission_denied(
                    "Raft control requires a current local Node or owner replica certificate",
                )
            })
    }
}

/// Wrap only the Raft/control services, leaving the cohosted authenticated VFS
/// routes on their own existing policy. New control methods default to Node-only.
#[derive(Clone)]
pub(super) struct NodeControlService<S> {
    inner: S,
    admission: RequestAdmission,
}

#[derive(Clone)]
struct RequestAdmission {
    policy: NodeControlPolicy,
    delegated: Arc<[String]>,
    replica_data: Arc<[String]>,
}
impl<S: NamedService> NodeControlService<S> {
    pub(super) fn new(inner: S, policy: NodeControlPolicy, delegated: &[&str]) -> Self {
        Self {
            inner,
            admission: RequestAdmission {
                policy,
                delegated: method_paths(S::NAME, delegated),
                replica_data: Arc::from([]),
            },
        }
    }

    pub(super) fn with_owner_replica_data(mut self) -> Self {
        self.admission.replica_data = method_paths(S::NAME, REPLICA_DATA_METHODS);
        self
    }
}
impl<S: NamedService> NamedService for NodeControlService<S> {
    const NAME: &'static str = S::NAME;
}
impl<S, E> Service<http::Request<Body>> for NodeControlService<S>
where
    S: Service<
            http::Request<Body>,
            Response = http::Response<Body>,
            Error = E,
            Future = BoxFuture<http::Response<Body>, E>,
        > + Send
        + 'static,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut request: http::Request<Body>) -> Self::Future {
        if let Err(status) = self.admission.check(&mut request) {
            return Box::pin(async move { Ok(status.into_http()) });
        }
        self.inner.call(request)
    }
}

impl RequestAdmission {
    // The payload/service type has no role in authenticating the connection.
    // Keep one implementation across all generated tonic service wrappers.
    #[inline(never)]
    fn check(&self, request: &mut http::Request<Body>) -> Result<(), Status> {
        self.policy.check_local_credentials()?;
        if !self.delegated.iter().any(|p| p == request.uri().path()) {
            match self.policy.check(request.extensions()) {
                Ok(Some(AuthenticatedPeer::Replica(_)))
                    if !self
                        .replica_data
                        .iter()
                        .any(|path| path == request.uri().path()) =>
                {
                    return Err(Status::permission_denied(
                        "operation requires a cluster Node",
                    ));
                }
                Ok(Some(peer)) => {
                    request.extensions_mut().insert(peer);
                }
                Ok(None) => {}
                Err(status) => return Err(status),
            }
        }
        Ok(())
    }
}

fn method_paths(service: &str, methods: &[&str]) -> Arc<[String]> {
    methods
        .iter()
        .map(|method| format!("/{service}/{method}"))
        .collect::<Vec<_>>()
        .into()
}

/// Each typed handler below this gate also checks the same zone membership.
const REPLICA_DATA_METHODS: &[&str] = &[
    "StepMessage",
    "StepStorageV1",
    "ReplicateEntries",
    "SnapshotEcState",
    "Propose",
    "Query",
    "GetClusterInfo",
    "GetSearchCapabilities",
    "ReadZoneBlob",
];

/// These doors have their own current caller/allow-list/ownership policy in the
/// native issuer. They never inherit Node authority from this exclusion.
pub(super) const AGENT_CREDENTIAL_METHODS: &[&str] = &[
    "MintSessionAgent",
    "MintUserRuntime",
    "RenewSessionAgent",
    "RevokeAgentCert",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{generate_agent_cert, generate_node_cert, generate_zone_ca};
    fn der(p: &[u8]) -> Vec<u8> {
        ::pem::parse(p).unwrap().into_contents()
    }
    #[test]
    fn local_node_role_requires_current_signature_and_a_single_canonical_identity() {
        let (local, key) = generate_zone_ca("root").unwrap();
        let (foreign, foreign_key) = generate_zone_ca("root").unwrap();
        let (node, _) = generate_node_cert(7, "root", &local, &key, &[], None).unwrap();
        let (outsider, _) =
            generate_node_cert(7, "root", &foreign, &foreign_key, &[], None).unwrap();
        let (agent, _) = generate_agent_cert("node-lookalike", &local, &key).unwrap();
        let identity = current_local_node_certificate(&der(&node), &der(&local)).unwrap();
        assert_eq!(identity.node_id, 7);
        assert_eq!(identity.zone_id, "root");
        assert!(current_local_node_certificate(&der(&outsider), &der(&local)).is_err());
        assert!(current_local_node_certificate(&der(&agent), &der(&local)).is_err());
        assert!(current_local_node_certificate(b"not DER", &der(&local)).is_err());
    }

    #[test]
    fn renewal_keeps_the_node_identity_while_the_credential_changes() {
        let (ca, key) = generate_zone_ca("root").unwrap();
        let (foreign, _) = generate_zone_ca("root").unwrap();
        // A founder's bootstrap leaf names its host in the CN; `enroll` renews
        // it with the Node ID there. Both name the Node by the same URI SAN.
        let host = Some("DESKTOP-K2PHFNR");
        let (issued, _) = generate_node_cert(7, "root", &ca, &key, &[], host).unwrap();
        let (renewed, _) = generate_node_cert(7, "root", &ca, &key, &[], None).unwrap();
        let (other, _) = generate_node_cert(8, "root", &ca, &key, &[], None).unwrap();
        let identity = local_node_identity(&issued, &ca).unwrap();
        let renewal = local_node_identity(&renewed, &ca).unwrap();
        assert_eq!(identity.identity_uri(), "nexus://zone/root/node/7");
        assert_eq!(renewal.identity_uri(), identity.identity_uri());
        assert_ne!(renewal.serial, identity.serial);
        assert_ne!(
            local_node_identity(&other, &ca).unwrap().identity_uri(),
            identity.identity_uri()
        );
        assert!(local_node_identity(&issued, &foreign).is_err());
    }

    #[test]
    fn expired_future_and_ambiguous_node_leaves_are_refused() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let issuer = super::super::certgen::ca_issuer_from_pem(&ca, &ca_key).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let key = rcgen::KeyPair::generate().unwrap();
        for (start, end, identities) in [
            (-120, -60, vec!["nexus://zone/root/node/7"]),
            (60, 120, vec!["nexus://zone/root/node/7"]),
            (
                -60,
                120,
                vec!["nexus://zone/root/node/7", "nexus://agent/also-agent"],
            ),
            (-60, 120, vec!["nexus://zone/root/node/007"]),
        ] {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.not_before = now + time::Duration::seconds(start);
            params.not_after = now + time::Duration::seconds(end);
            params.subject_alt_names = identities
                .into_iter()
                .map(|s| rcgen::SanType::URI(s.try_into().unwrap()))
                .collect();
            let leaf = params.signed_by(&key, &issuer).unwrap();
            assert!(current_local_node_certificate(leaf.der(), &der(&ca)).is_err());
        }
    }
}
