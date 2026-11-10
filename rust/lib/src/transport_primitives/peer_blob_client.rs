//! `PeerBlobClient` — transport-layer abstraction for peer-blob fetch.
//!
//! Lowest shared layer: kernel holds an `Arc<dyn PeerBlobClient>`
//! through the peer_client slot, raft holds it through the blob
//! fetcher path, rpc impls it on the client side. Living in
//! `shared/transport-primitives` lets every consumer name the trait
//! without closing a Cargo cycle through any peer crate.
//!
//! Callers with an owning data zone use `fetch_in_zone`. Object identifiers
//! stay opaque; the peer resolves them within the selected content namespace.
//! `fetch` is the separate cluster-wide administrator surface.

/// Result type used by the peer-blob fetch method.
///
/// String errors carry gRPC status messages and timeout descriptions
/// verbatim from the underlying tonic client.
pub type PeerBlobResult<T> = Result<T, String>;

/// Abstract peer-blob fetch surface.
///
/// Reference impl: `rpc::peer_blob::PeerBlobClient` — speaks gRPC to
/// remote nodes and returns the bytes for an opaque ``content_id``.
///
/// `Send + Sync` so the `Arc<dyn PeerBlobClient>` can travel between
/// the kernel's tokio worker pool and the raft replication apply
/// task.
///
/// Methods stay narrowly typed (`Vec<u8>` for blob payloads; not
/// `Bytes` or `&[u8]`) so impls can either own the buffer (most
/// common) or arrange ownership through a copy.
pub trait PeerBlobClient: Send + Sync {
    /// Fetch a blob from a remote peer (`addr` is `host:port`, the
    /// same string stored in `FileMetadata.last_writer_address`).
    ///
    /// `content_id` is opaque — VFS path for federation reads, CAS
    /// hash for chunk-dedup pulls, or a backend-specific handle. The
    /// peer's own data-plane resolves it.
    ///
    /// Returns the blob bytes or an error string.
    fn fetch(&self, addr: &str, content_id: &str) -> PeerBlobResult<Vec<u8>>;

    /// Fetch within the named data zone using the peer's admitted namespace.
    /// Implementations without scoped reads return an error.
    fn fetch_in_zone(
        &self,
        _addr: &str,
        _zone_id: &str,
        _content_id: &str,
    ) -> PeerBlobResult<Vec<u8>> {
        Err("zone-scoped peer content is unavailable".into())
    }

    /// Install TLS config (PEM bundle). Default impl no-ops so
    /// non-TLS callers (tests, Noop fallback) skip the burden.
    /// Production rpc-tier client impl overrides.
    fn install_tls(&self, _ca_pem: &[u8], _cert_pem: Option<&[u8]>, _key_pem: Option<&[u8]>) {}
}

/// No-op fallback used at `Kernel::new` so the `peer_client` field
/// always carries an `Arc<dyn PeerBlobClient>` — Rust unit tests and
/// WASM builds keep the same call shape. Each method errors out with
/// "PeerBlobClient not installed"; the transport-tier install hook
/// replaces this with the real rpc-side impl on the production boot
/// path.
pub struct NoopPeerBlobClient;

impl PeerBlobClient for NoopPeerBlobClient {
    fn fetch(&self, _addr: &str, _content_id: &str) -> PeerBlobResult<Vec<u8>> {
        Err("PeerBlobClient not installed".into())
    }
}

impl NoopPeerBlobClient {
    pub fn arc() -> Arc<dyn PeerBlobClient> {
        Arc::new(NoopPeerBlobClient)
    }
}

use std::sync::Arc;
