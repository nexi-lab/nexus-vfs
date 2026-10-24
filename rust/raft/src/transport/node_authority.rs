//! Keep the cluster control plane Node-only even when the listener also admits
//! domestic/foreign Agent certificates for cohosted VFS services. TLS admission
//! is not Node authorization. No policy cache or second issuer is introduced.

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
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer};

/// Signed identity/time/role information, not proof of key possession. Network
/// callers must supply the actual TLS leaf; a public certificate is not auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNodeCertificate {
    pub node_id: u64,
    pub zone_id: String,
    pub serial: Vec<u8>,
}

/// Verify against the configured LOCAL cluster anchor, never the union of
/// client-auth anchors or an issuer DN. Foreign-CA registration cannot confer
/// Node authority. This primitive does not add CRL distribution/consensus.
pub fn current_local_node_certificate(
    der: &[u8],
    local_ca_der: &[u8],
) -> Result<LocalNodeCertificate, String> {
    let (rest, leaf) = X509Certificate::from_der(der).map_err(|_| "invalid Node certificate")?;
    if !rest.is_empty() || !leaf.validity().is_valid() {
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
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| "invalid Node SAN")?
        .ok_or("missing Node SAN")?;
    let identities: Vec<_> = san
        .value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::URI(uri) if uri.starts_with("nexus://") => Some(*uri),
            _ => None,
        })
        .collect();
    let [identity] = identities.as_slice() else {
        return Err("Node certificate must carry exactly one Nexus identity".into());
    };
    let (zone_id, node_id) =
        super::parse_node_identity_uri(identity).ok_or("certificate does not name a Node")?;
    contracts::validate_zone_id_for(contracts::ZoneIdUse::ExistingRef, &zone_id)
        .map_err(|e| e.to_string())?;
    if super::node_identity_uri(&zone_id, node_id) != *identity {
        return Err("Node identity is not canonical".into());
    }
    Ok(LocalNodeCertificate {
        node_id,
        zone_id,
        serial: leaf.raw_serial().to_vec(),
    })
}

#[derive(Clone)]
pub(super) struct NodeControlPolicy {
    local_ca: Option<Arc<[u8]>>,
}
impl NodeControlPolicy {
    pub(super) fn from_tls(tls: Option<&super::TlsConfig>) -> Result<Self, String> {
        Ok(Self {
            local_ca: tls
                .map(|t| {
                    lib::transport_primitives::first_certificate_der(&t.ca_pem, "local cluster CA")
                        .map(Arc::from)
                })
                .transpose()?,
        })
    }
    fn check(&self, extensions: &http::Extensions) -> Result<(), Status> {
        // Explicit plaintext/development listeners retain their old contract.
        // They must not host the protected collaboration namespace.
        let Some(ca) = &self.local_ca else {
            return Ok(());
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
        current_local_node_certificate(leaf.as_ref(), ca)
            .map(|_| ())
            .map_err(|_| {
                Status::permission_denied("Raft control requires a current local Node certificate")
            })
    }
}

/// Wrap only the Raft/control services, leaving the cohosted authenticated VFS
/// routes on their own existing policy. New control methods default to Node-only.
#[derive(Clone)]
pub(super) struct NodeControlService<S> {
    inner: S,
    policy: NodeControlPolicy,
    delegated: Arc<[String]>,
}
impl<S: NamedService> NodeControlService<S> {
    pub(super) fn new(inner: S, policy: NodeControlPolicy, delegated: &[&str]) -> Self {
        Self {
            inner,
            policy,
            delegated: delegated
                .iter()
                .map(|m| format!("/{}/{m}", S::NAME))
                .collect::<Vec<_>>()
                .into(),
        }
    }
}
impl<S: NamedService> NamedService for NodeControlService<S> {
    const NAME: &'static str = S::NAME;
}
impl<S> Service<http::Request<Body>> for NodeControlService<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        if !self.delegated.iter().any(|p| p == request.uri().path()) {
            if let Err(status) = self.policy.check(request.extensions()) {
                return Box::pin(async move { Ok(status.into_http()) });
            }
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

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
            let params = rcgen::CertificateParams {
                not_before: now + time::Duration::seconds(start),
                not_after: now + time::Duration::seconds(end),
                subject_alt_names: identities
                    .into_iter()
                    .map(|s| rcgen::SanType::URI(s.try_into().unwrap()))
                    .collect(),
                ..Default::default()
            };
            let leaf = params.signed_by(&key, &issuer).unwrap();
            assert!(current_local_node_certificate(leaf.der(), &der(&ca)).is_err());
        }
    }
}
