//! [`LocalSearchBackend`] — the trait the dispatcher calls once per
//! zone to run the actual search RPC.  Owning the trait here (rather
//! than importing a concrete gRPC client) lets tests wire a fake
//! without the plugin gRPC stack, and lets a future cross-zone gRPC
//! impl slot in behind the same shape.
//!
use async_trait::async_trait;
use nexus_search_common::{Hit, QueryParameters, SearchDelegation};
use std::sync::Arc;

/// The dispatcher's per-zone search request.  Owned (not a borrow of
/// an axum body) so each leg's spawn owns its clone.
// Contains a live credential; do not derive Debug or serialization.
#[derive(Clone)]
pub struct SearchRequest {
    /// Original caller credential for local RPC legs. Remote legs use a
    /// delegated subject over the node's authenticated connection instead.
    pub auth_token: String,
    /// Shared immutable query parameters. Queued legs clone the Arc rather than
    /// prefix maps and filters; the transport copies them into its wire request.
    pub parameters: Arc<QueryParameters>,
    /// The original caller a per-zone leg runs the search AS.  A
    /// remote-zone backend stamps this onto the [`SearchDelegation`]
    /// it mints so the servicer records the correct subject on its
    /// audit trail (the request runs as the original caller, NOT as
    /// the delegation minter).  Owned `(subject_type, subject_id)`
    /// so each leg's spawn owns its clone.
    ///
    /// The dispatcher stamps this from the `Subject<'_>` passed to
    /// [`crate::FederatedSearchDispatcher::search`] before spawning
    /// legs — a backend never sees an unset subject.
    pub subject: (String, String),
}

/// A backend that can run a search inside ONE zone and return a list
/// of hits ranked by the backend's own score.  Async because every
/// production impl talks a network transport (tonic gRPC to the
/// search-plugin).
///
/// # Local vs remote
///
/// This trait is the dispatcher's per-zone entry point regardless of
/// where the zone lives.  Two concrete shapes:
///
/// * The daemon's OWN zones — a thin in-process wrapper around
///   `nexus.search.v1.SearchService.Query` on the local plugin.
/// * A CROSS-daemon zone — served by [`crate::routing::RoutingBackend`], which uses
///   a [`ZoneSearchRegistry`](nexus_search_common::ZoneSearchRegistry)
///   to pick the right daemon and a [`RemoteSearchBackend`] to dial it.
///
/// The dispatcher does not know the difference — routing is a
/// composition concern owned by [`crate::routing::RoutingBackend`].
#[async_trait]
pub trait LocalSearchBackend: Send + Sync {
    async fn search_zone(
        &self,
        zone_id: &str,
        req: &SearchRequest,
    ) -> Result<Vec<Hit>, BackendError>;
}

/// Run a search on the owning remote daemon. The transport authenticates the
/// issuing node and carries the already-minted delegation with the RPC.
///
/// # Why the trait sees the delegation, not the raw subject
///
/// Delegation minting is a routing concern (source zone id, TTL,
/// delegation id generation) that must not leak into the transport.
/// [`crate::routing::RoutingBackend`] mints one delegation per zone and hands the
/// impl an ALREADY-MINTED credential — the transport only serialises
/// it and puts it on the wire.  Split responsibilities cleanly: a
/// future transport that speaks JSON-over-HTTP (or an in-process
/// stub) drops in behind the same trait unchanged.
#[async_trait]
pub trait RemoteSearchBackend: Send + Sync {
    /// Run the search on the remote daemon at `target`, presenting
    /// `delegation` as the auth credential.
    ///
    /// `target` — the string [`ZoneSearchRegistry::resolve`](nexus_search_common::ZoneSearchRegistry::resolve)
    /// returned.  Uninterpreted here; the impl's job is to decode it
    /// into a transport endpoint (gRPC URI, socket path, in-process
    /// registry key).
    async fn search_remote_zone(
        &self,
        target: &str,
        delegation: &SearchDelegation,
        zone_id: &str,
        req: &SearchRequest,
    ) -> Result<Vec<Hit>, BackendError>;
}

/// Errors a backend may surface.  Kept small — the dispatcher just
/// bubbles the message onto [`nexus_search_common::ZoneFailure`],
/// so the wire shape is a plain string on the response envelope.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum BackendError {
    /// Transport / RPC-level failure (dial refused, TLS mismatch,
    /// timeout inside the transport).
    #[error("transport: {0}")]
    Transport(String),
    /// Backend-side refusal (bad request, ResourceExhausted,
    /// FailedPrecondition, …).
    #[error("backend: {0}")]
    Backend(String),
    /// Config bug (unrecognised backend target, misconfigured
    /// registry).  Surfaced as a 500 upstream — matches how the
    /// Python dispatcher treats a mis-wired registry.
    #[error("config: {0}")]
    Config(String),
}

/// [`RemoteSearchBackend`] that refuses every dial.  Used by the
/// composition root of a single-daemon deployment (no cross-zone
/// peers wired yet) so [`crate::routing::RoutingBackend`] can still be
/// constructed — a caller who leaves the registry empty never hits
/// this arm; a mis-wired caller who registers a remote target and
/// forgot to wire a real transport gets a loud
/// [`BackendError::Config`] instead of a silent-drop.
pub struct NoOpRemoteSearchBackend;

#[async_trait]
impl RemoteSearchBackend for NoOpRemoteSearchBackend {
    async fn search_remote_zone(
        &self,
        target: &str,
        _delegation: &SearchDelegation,
        zone_id: &str,
        _req: &SearchRequest,
    ) -> Result<Vec<Hit>, BackendError> {
        Err(BackendError::Config(format!(
            "no remote search backend wired — zone {zone_id:?} resolved to \
             remote target {target:?}, but this daemon was built with \
             NoOpRemoteSearchBackend (single-daemon deployment)",
        )))
    }
}
