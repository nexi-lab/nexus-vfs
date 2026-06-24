//! `FederationPeerClient` — kernel HAL trait for typed cross-node VFS RPCs.
//!
//! Sister to [`crate::hal::peer::PeerBlobClient`].  Where the blob client
//! exposes one opaque `(addr, content_id) -> Vec<u8>` fetch, this trait
//! carries every typed `NexusVFSService` method we need on the
//! syscall hot path: `read`, `write`, `stat`, `list_dir`, `delete_file`,
//! `rmdir`, `mkdir`.  Used by
//! [`crate::abc::object_store::ObjectStore`] impls that proxy to a
//! remote peer (`backends::storage::federation_peer::FederationPeerBackend`).
//!
//! ## Why not extend `PeerBlobClient`?
//!
//! `PeerBlobClient` is the store-and-forward CAS-blob shape: a single
//! opaque content id, no shape on the wire beyond `Vec<u8>`.  Federation
//! peer fetch needs typed metadata responses (size + is_dir for stat,
//! `Vec<(name, entry_type)>` for readdir, …) — putting those on the
//! `PeerBlobClient` trait would either bloat its surface for the
//! ReadBlob caller or force the federation backend to serialise
//! responses to bytes and re-parse, which is what the typed
//! `NexusVFSService` proto was designed to avoid.
//!
//! ## Layering
//!
//! Trait declared here in the kernel crate.  Concrete impl lives in the
//! `transport` crate (`transport::federation::FederationClient`) which
//! holds the per-peer tonic Channel pool + mTLS material.  Kernel
//! consumers reach the trait via an `Arc<dyn FederationPeerClient>`
//! installed at boot.

use std::sync::Arc;

use crate::abc::object_store::{BackendStat, WriteResult};

/// Result type for federation peer RPCs.  String errors carry the
/// underlying tonic status / timeout message verbatim so callers can
/// surface them in tracing without losing context.
pub type FederationPeerResult<T> = Result<T, String>;

/// Cross-node typed VFS RPC surface.
///
/// Every method takes the peer's `host:port` address as the first arg
/// so a single client can multiplex calls across many peers (the
/// implementation pools `Channel`s by address internally).
///
/// `Send + Sync` so the `Arc<dyn FederationPeerClient>` can travel
/// between the kernel's tokio worker pool and any async apply task
/// that needs to reach a peer.
pub trait FederationPeerClient: Send + Sync {
    /// Fetch file bytes via `NexusVFSService.Read`.
    ///
    /// `path` is the absolute zone-canonical path on the peer.  `offset`
    /// is byte-offset into the file (0 for full read; non-zero only for
    /// range / stream reads — most federation reads pass 0).
    fn read(&self, addr: &str, path: &str, offset: u64) -> FederationPeerResult<Vec<u8>>;

    /// Write file bytes via `NexusVFSService.Write`.
    ///
    /// Partial writes are not modelled at this layer — the federation
    /// peer either accepts a full-file write or rejects it.  Callers
    /// that need pwrite semantics handle the read-modify-write locally
    /// before calling this.
    fn write(&self, addr: &str, path: &str, content: &[u8])
        -> FederationPeerResult<WriteResult>;

    /// Stat one path via `NexusVFSService.Stat`.
    ///
    /// Returns `Ok(None)` when the peer reports the path is not found
    /// (in-band `found = false`).  Transport errors surface as `Err`.
    fn stat(&self, addr: &str, path: &str) -> FederationPeerResult<Option<BackendStat>>;

    /// List immediate children via `NexusVFSService.Readdir`.
    ///
    /// Each child is `(name, entry_type)`, mirroring
    /// `MetaStore::list_dir`'s shape.  Names are bare filenames (not
    /// full paths) so callers append to `path` themselves.
    fn list_dir(&self, addr: &str, path: &str)
        -> FederationPeerResult<Vec<(String, u8)>>;

    /// Delete a file via `NexusVFSService.Delete`.
    fn delete_file(&self, addr: &str, path: &str) -> FederationPeerResult<()>;

    /// Remove a directory via `NexusVFSService.Delete` with `recursive`.
    fn rmdir(&self, addr: &str, path: &str, recursive: bool) -> FederationPeerResult<()>;

    /// Create a directory via `NexusVFSService.Mkdir`.
    fn mkdir(
        &self,
        addr: &str,
        path: &str,
        parents: bool,
        exist_ok: bool,
    ) -> FederationPeerResult<()>;
}

/// No-op fallback installed at `Kernel::new` so the slot always carries
/// an `Arc<dyn FederationPeerClient>` — Rust unit tests and WASM builds
/// keep the same call shape.  Every method errors out with "federation
/// peer client not installed"; the transport-tier install hook replaces
/// this with the real client on the production boot path.
pub struct NoopFederationPeerClient;

impl FederationPeerClient for NoopFederationPeerClient {
    fn read(&self, _addr: &str, _path: &str, _offset: u64) -> FederationPeerResult<Vec<u8>> {
        Err("federation peer client not installed".into())
    }
    fn write(
        &self,
        _addr: &str,
        _path: &str,
        _content: &[u8],
    ) -> FederationPeerResult<WriteResult> {
        Err("federation peer client not installed".into())
    }
    fn stat(&self, _addr: &str, _path: &str) -> FederationPeerResult<Option<BackendStat>> {
        Err("federation peer client not installed".into())
    }
    fn list_dir(
        &self,
        _addr: &str,
        _path: &str,
    ) -> FederationPeerResult<Vec<(String, u8)>> {
        Err("federation peer client not installed".into())
    }
    fn delete_file(&self, _addr: &str, _path: &str) -> FederationPeerResult<()> {
        Err("federation peer client not installed".into())
    }
    fn rmdir(&self, _addr: &str, _path: &str, _recursive: bool) -> FederationPeerResult<()> {
        Err("federation peer client not installed".into())
    }
    fn mkdir(
        &self,
        _addr: &str,
        _path: &str,
        _parents: bool,
        _exist_ok: bool,
    ) -> FederationPeerResult<()> {
        Err("federation peer client not installed".into())
    }
}

impl NoopFederationPeerClient {
    pub fn arc() -> Arc<dyn FederationPeerClient> {
        Arc::new(NoopFederationPeerClient)
    }
}
