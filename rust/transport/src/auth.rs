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
    /// Node id pinned in the URI SAN.
    pub node_id: Option<u64>,
    /// Zone id pinned in the URI SAN.
    pub zone_id: Option<String>,
}

impl PeerIdentity {
    /// Stable string used as the `user_id` of a peer-plane context.
    ///
    /// Prefers the self-named `node/{id}` form, falling back to the CN
    /// for certs minted before the URI SAN existed.
    pub fn display_id(&self) -> String {
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
        };
        assert_eq!(named.display_id(), "node/7");

        let legacy = PeerIdentity {
            common_name: "nexus-zone-root-node-win".into(),
            node_id: None,
            zone_id: None,
        };
        assert_eq!(legacy.display_id(), "nexus-zone-root-node-win");
    }
}
