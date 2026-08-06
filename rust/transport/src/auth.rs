//! `transport::auth` — the `AuthProvider` trait, the credentials it
//! resolves, and the kernel-default `NoAuth` impl.
//!
//! ## Why this lives in `transport`, not `services`
//!
//! The `AuthProvider` trait is consumed by
//! `transport::grpc::VfsServiceImpl` to gate requests before they reach
//! the kernel. By the Rust convention of "trait owner = primary
//! consumer", the trait belongs to `transport`. `NoAuth` ships alongside
//! the trait because it is the single-node-dev all-pass policy.
//!
//! ## Two identity planes
//!
//! A request authenticates on exactly one of two planes, and the
//! [`AuthCredentials`] passed to [`AuthProvider::resolve`] carries both
//! so a provider can decide:
//!
//! * **Peer / system** — [`AuthCredentials::peer`] is `Some`. The
//!   connection completed an mTLS handshake against the cluster CA, so
//!   rustls has *already* verified the chain: the mere existence of a
//!   [`PeerIdentity`] is a cryptographic proof that the caller holds a
//!   CA-signed node key. This is the plane raft, federation fan-out and
//!   remote mounts ride on — all of which send an empty `auth_token`.
//!
//! * **Agent / user** — [`AuthCredentials::token`] carries an `sk-` API
//!   key. Resolved against the replicated key store.
//!
//! Keeping both on one struct is what lets a strict provider reject an
//! empty token *without* killing federation: no token but a valid peer
//! cert is still a fully authenticated caller.

use kernel::kernel::OperationContext;

/// Cryptographically verified identity of the TLS peer.
///
/// Constructed only from a client certificate that rustls has already
/// validated against the cluster CA (the server sets `client_ca_root`,
/// so an unsigned or wrong-CA cert never reaches a handler). Treat the
/// presence of this value as proof of cluster membership.
///
/// `node_id` / `zone_id` are populated from the `nexus://zone/{zone}/node/{id}`
/// URI SAN that `raft::transport::certgen` pins into every node cert.
/// They are `None` for certs issued before that SAN existed — such a
/// cert is still a valid cluster peer (the chain verified), it just
/// cannot name itself, so it is usable for authentication but not for
/// per-node authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Subject CommonName, always present.
    pub common_name: String,
    /// Node id pinned in a `nexus://zone/{zone}/node/{id}` URI SAN.
    pub node_id: Option<u64>,
    /// Zone id pinned in the node URI SAN.
    pub zone_id: Option<String>,
    /// Agent name pinned in a `nexus://agent/{name}` URI SAN. `Some` for an
    /// agent-identity cert, `None` for a node cert — the two SAN namespaces
    /// are disjoint. When present the peer is an agent, not a cluster node.
    /// The cert is a pure identity (a DID): it carries no authorization, so
    /// there is nothing else to read from it — a valid agent is a mailbox
    /// principal, full stop.
    pub agent_name: Option<String>,
    /// The foreign trust domain this agent belongs to, when its cert chains to a
    /// registered foreign CA rather than the cluster CA. `None` = a local
    /// (cluster-CA) identity; `Some(td)` = a cross-org agent of trust domain
    /// `td`. A foreign identity is ALWAYS agent-only — `peer_identity`'s
    /// classifier never populates `node_id` from a foreign-CA cert, so a
    /// customer's CA can mint no cluster member — and it renders the qualified
    /// `td/agent/{name}` id.
    pub trust_domain: Option<String>,
    /// The certificate's raw serial-number bytes. For an agent cert this is
    /// what revocation names: `resolve` rejects a peer whose serial is in the
    /// cluster CA's signed CRL. Every X.509 cert carries a serial.
    pub serial: Vec<u8>,
}

impl PeerIdentity {
    /// Stable string used as the `user_id` of a peer-plane context.
    ///
    /// Prefers the self-named `node/{id}` form, falling back to the CN
    /// for certs minted before the URI SAN existed.
    pub fn display_id(&self) -> String {
        if let Some(name) = &self.agent_name {
            // A foreign agent ALWAYS renders qualified — never a bare `agent/x`
            // that could be mistaken for a local agent of the same name (the
            // id-leak guard: accountability must name the org).
            return match &self.trust_domain {
                Some(td) => format!("{td}/agent/{name}"),
                None => format!("agent/{name}"),
            };
        }
        match self.node_id {
            Some(id) => format!("node/{id}"),
            None => self.common_name.clone(),
        }
    }
}

/// Everything a provider may use to decide who the caller is.
///
/// One param, two orthogonal planes — see the module docs.
pub struct AuthCredentials<'a> {
    /// Bearer token from the request message (`auth_token`). Empty
    /// string when the caller supplied none.
    pub token: &'a str,
    /// mTLS peer, when the connection was authenticated by client cert.
    pub peer: Option<&'a PeerIdentity>,
}

impl<'a> AuthCredentials<'a> {
    /// Token-only credentials — the shape a plaintext (non-mTLS) caller
    /// presents.
    pub fn from_token(token: &'a str) -> Self {
        Self { token, peer: None }
    }
}

/// Resolve a request's credentials into an `OperationContext`.
pub trait AuthProvider: Send + Sync + 'static {
    fn resolve(&self, creds: &AuthCredentials<'_>) -> Result<OperationContext, tonic::Status>;
}

/// Single-node-dev all-pass policy. Every request becomes a
/// system-level admin context regardless of what it presents.
///
/// This is the default only because a fresh single-node daemon has no
/// key store to check against yet. Any deployment that federates or
/// serves agents selects a real provider at the composition root.
pub struct NoAuth;

impl AuthProvider for NoAuth {
    fn resolve(&self, _creds: &AuthCredentials<'_>) -> Result<OperationContext, tonic::Status> {
        Ok(OperationContext::new(
            "cluster-internal",
            "root",
            true,
            None,
            true,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reject helper used in tests to exercise the rejection branch
    /// of consumer code without dragging a real auth backend into the
    /// transport crate.
    struct RejectAll;
    impl AuthProvider for RejectAll {
        fn resolve(&self, _creds: &AuthCredentials<'_>) -> Result<OperationContext, tonic::Status> {
            Err(tonic::Status::unauthenticated("rejected"))
        }
    }

    #[test]
    fn no_auth_returns_admin_context_for_any_token() {
        let auth = NoAuth;
        for token in ["", "any-token-here", "x"] {
            let ctx = auth.resolve(&AuthCredentials::from_token(token)).unwrap();
            assert_eq!(ctx.user_id, "cluster-internal");
            assert!(ctx.is_admin);
            assert!(ctx.is_system);
        }
    }

    #[test]
    fn reject_all_helper_rejects() {
        assert!(RejectAll
            .resolve(&AuthCredentials::from_token("anything"))
            .is_err());
    }

    #[test]
    fn peer_display_id_prefers_node_id_over_cn() {
        let named = PeerIdentity {
            common_name: "nexus-zone-root-node-win".into(),
            node_id: Some(7),
            zone_id: Some("root".into()),
            agent_name: None,
            trust_domain: None,
            serial: vec![],
        };
        assert_eq!(named.display_id(), "node/7");

        let legacy = PeerIdentity {
            common_name: "nexus-zone-root-node-win".into(),
            node_id: None,
            zone_id: None,
            agent_name: None,
            trust_domain: None,
            serial: vec![],
        };
        assert_eq!(legacy.display_id(), "nexus-zone-root-node-win");

        let agent = PeerIdentity {
            common_name: "nexus-agent-win-ai".into(),
            node_id: None,
            zone_id: None,
            agent_name: Some("win-ai".into()),
            trust_domain: None,
            serial: vec![],
        };
        assert_eq!(agent.display_id(), "agent/win-ai");

        // A foreign agent renders QUALIFIED by its trust domain — never the bare
        // `agent/win-ai` above, which a local agent of the same name would use.
        let foreign = PeerIdentity {
            trust_domain: Some("hospital-a".into()),
            ..agent.clone()
        };
        assert_eq!(foreign.display_id(), "hospital-a/agent/win-ai");
    }
}
