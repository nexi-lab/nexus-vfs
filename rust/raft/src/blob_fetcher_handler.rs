//! KernelBlobFetcher — server-side handler for the driver-to-driver
//! `ReadBlob` RPC, co-located with `ZoneApiService` on the raft port.
//!
//! Lives in the raft crate alongside the `BlobFetcher` trait + the
//! gRPC server: raft owns the wire-format and dispatch fabric, kernel
//! owns the data plane (mount backends). This handler bridges the two
//! by reaching kernel-side state (`VFSRouter`) through the kernel's
//! syscall surface — no ``MetaStore`` Arc leaks across the crate
//! boundary.
//!
//! Absolute ``content_id`` values name global VFS paths. The fetcher resolves
//! those via the local ``VFSRouter``; the router picks the matching mount, and the
//! mount's backend interprets the locally-stored
//! ``FileMetadata.content_id`` (hash for CAS, backend_path for PAS).
//! Other values address stored objects directly. CAS serves the raw object
//! whose hash was requested, including a manifest before chunk assembly.
//!
//! Installation: [`install`] is called from
//! `RaftDistributedCoordinator::install_with_kernel` once the
//! ZoneManager is up — it drains the slot stashed via
//! `Kernel::stash_blob_fetcher_slot` and writes `Arc<KernelBlobFetcher>`
//! into the `BlobFetcherSlot` handed back by
//! `ZoneManager::blob_fetcher_slot()`.  From then on, peer `ReadBlob`
//! requests resolve against the local data plane.

use std::sync::Arc;

use crate::blob_fetcher::BlobFetcher;

use kernel::abc::object_store::{ObjectStore, StorageError};
use kernel::kernel::{Kernel, OperationContext};
use kernel::vfs_router::VFSRouter;

/// Closure type for "look up locally-stored content_id at this path" —
/// federation builds this from `Kernel::content_id_lookup_fn` so the
/// fetcher consults the metastore through the kernel's syscall layer
/// (no ``MetaStore`` symbol crossing the crate boundary).
type LocalContentIdLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Read an addressed object. CAS manifests are objects in their own right;
/// assembling their chunks belongs to a logical file read.
fn read_backend_object(
    backend: &dyn ObjectStore,
    content_id: &str,
    ctx: &OperationContext,
) -> Result<Vec<u8>, StorageError> {
    match backend.as_cas() {
        Some(cas) => cas
            .transport()
            .read_blob(content_id)
            .map_err(|error| StorageError::from(kernel::cas_engine::CASError::from(error))),
        None => backend.read_content(content_id, ctx),
    }
}

/// Kernel-side `BlobFetcher` — backed by the kernel's `VFSRouter` plus
/// a narrow content-id-lookup closure.
pub struct KernelBlobFetcher {
    kernel: Arc<Kernel>,
    vfs_router: Arc<VFSRouter>,
    lookup_local_content_id: LocalContentIdLookup,
}

impl KernelBlobFetcher {
    pub fn new(
        kernel: Arc<Kernel>,
        vfs_router: Arc<VFSRouter>,
        lookup_local_content_id: LocalContentIdLookup,
    ) -> Self {
        Self {
            kernel,
            vfs_router,
            lookup_local_content_id,
        }
    }
}

#[tonic::async_trait]
impl BlobFetcher for KernelBlobFetcher {
    /// Resolve ``content_id`` against the local data plane.
    ///
    /// Absolute paths request logical files; other addresses request objects.
    ///
    /// 1. **Path-style local read** — if ``vfs_router.route()`` resolves
    ///    ``content_id`` to a mount, try reading from that mount with
    ///    the local ``FileMetadata.content_id`` (or the route's
    ///    ``backend_path`` as a cold-cache fallback). This handles
    ///    federation reads where the peer asked for a VFS path.
    ///
    /// 2. **Addressed-object fan-out** — try each backend for its
    ///    locally stored object. CAS serves the exact immutable blob,
    ///    including manifests; other backends use their content reader.
    ///    This serves:
    ///      * CAS chunk fetches whose ``content_id`` is a raw hash
    ///        with no mount path
    ///      * Federation reads where the peer's local routing of the
    ///        path doesn't reach the same mount as the writer (e.g.
    ///        the writer published into a federation_share zone whose
    ///        mount only exists on the joining node, or a crosslink
    ///        alias whose target zone's storage lives elsewhere on
    ///        the peer)
    ///
    /// Either path the file ends at the same shared storage Arc, so
    /// fall-through is a thin extra try, not a heavy fan-out.
    async fn read(&self, content_id: &str) -> Result<Vec<u8>, String> {
        if content_id.is_empty() {
            return Err("empty content_id".to_string());
        }
        // Peer-served call: the consumer of this read is a remote node
        // demanding bytes via the ReadBlob RPC.  Setting
        // `propagates_cross_node = true` does TWO things in lockstep
        // via the duality contract on OperationContext:
        //   1. Any backend hit triggers `observe_backend_content` to
        //      materialize metadata with `last_writer_address = self`,
        //      so the demanding peer's next read uses
        //      `try_remote_fetch` directly (no second round-trip).
        //   2. Fan-out is disabled — we already are the one being
        //      asked, no looping back to peers.
        let mut ctx = OperationContext::new("system", contracts::ROOT_ZONE_ID, true, None, true);
        ctx.propagates_cross_node = true;

        // Step 1: try path-style routing → local mount read.
        if let Some(route) = content_id
            .starts_with('/')
            .then(|| self.vfs_router.route(content_id, contracts::ROOT_ZONE_ID))
            .flatten()
        {
            let local_content_id = (self.lookup_local_content_id)(content_id)
                .unwrap_or_else(|| route.backend_path.clone());
            if let Some(bytes) = route
                .backend
                .as_ref()
                .and_then(|backend| backend.read_content(&local_content_id, &ctx).ok())
            {
                // `content_id` here is the global VFS path the peer
                // asked for — that's the key the metadata is keyed on.
                self.kernel.observe_backend_content(
                    content_id,
                    bytes.len() as u64,
                    None,
                    &route.zone_id,
                    &ctx,
                );
                return Ok(bytes);
            }

            // Step 1.5 (PR #98 / #99): federation-peer-mount placeholder
            // SSOT-symmetric read.  Under the uniform local-first
            // sys_write contract, writes through a placeholder mount
            // (route.backend = None + target_zone_id = Some) land on
            // this voter's kernel-global federation cache addressed by
            // canonical VFS path — NOT on any ObjectStore backend
            // routed by `route.backend` or visible to the fan-out in
            // Step 2.  `Kernel::sys_read` substitutes the federation
            // cache in the same shape for the writer's own readback;
            // this peer-served ReadBlob path is the symmetric SSOT for
            // remote readers fetching back via
            // `try_remote_fetch(last_writer = this voter)`.  Without
            // this, founder's `cat` of a joiner-written file 404s
            // because Step 1 misses on the placeholder + Step 2
            // doesn't know to look in the federation cache.
            //
            // Predicate: federation-peer mount only (backend.is_none()
            // && target_zone_id.is_some()).  Non-federation routes
            // (regular mounts, CAS hashes) fall through to Step 2
            // unchanged.
            if route.backend.is_none() && route.target_zone_id.is_some() {
                if let Some(bytes) = self
                    .kernel
                    .federation_cache_arc()
                    .and_then(|b| b.read_content(content_id, &ctx).ok())
                {
                    self.kernel.observe_backend_content(
                        content_id,
                        bytes.len() as u64,
                        None,
                        &route.zone_id,
                        &ctx,
                    );
                    return Ok(bytes);
                }
            }
        }

        // Step 2: hash-style fan-out across every local backend. CAS
        // backends will recognise a hash; PAS / connector backends will
        // reject and we keep walking. This is also the recovery path
        // for federation-share / crosslink reads where the writer's
        // local routing doesn't carry over verbatim to the peer's
        // mount table.
        let backends = self.vfs_router.backends();
        if backends.is_empty() {
            return Err(format!("read_content({content_id}): no local backends"));
        }
        let mut last_err: Option<String> = None;
        for backend in backends {
            match read_backend_object(backend.as_ref(), content_id, &ctx) {
                Ok(bytes) => return Ok(bytes),
                Err(e) => last_err = Some(format!("{:?}", e)),
            }
        }
        Err(last_err.unwrap_or_else(|| format!("read_content({content_id}): not found")))
    }
}

/// Install hook called during kernel process boot after
/// `kernel::python::register` so the raft server's `BlobFetcherSlot`
/// carries a kernel-backed fetcher before the first federation read.
///
/// No-op when `Kernel::pending_blob_fetcher_slot` is empty (federation
/// disabled — `NEXUS_HOSTNAME` was unset).
///
/// Kernel hands back the slot as `Box<dyn Any + Send + Sync>`; this
/// handler downcasts to the concrete `BlobFetcherSlot` here, which
/// is fine because the handler lives in raft alongside the type.
pub fn install(kernel: &Arc<kernel::kernel::Kernel>) {
    let Some(any_slot) = kernel.take_pending_blob_fetcher_slot() else {
        return;
    };
    let slot = match any_slot.downcast::<crate::blob_fetcher::BlobFetcherSlot>() {
        Ok(boxed) => *boxed,
        Err(_) => {
            tracing::error!(
                "blob_fetcher_handler::install: pending slot type mismatch \
                 (expected nexus_raft::blob_fetcher::BlobFetcherSlot)"
            );
            return;
        }
    };
    let lookup = kernel.content_id_lookup_fn(contracts::ROOT_ZONE_ID);
    let fetcher = Arc::new(KernelBlobFetcher::new(
        Arc::clone(kernel),
        kernel.vfs_router_arc(),
        lookup,
    ));
    *slot.write() = Some(fetcher as Arc<dyn BlobFetcher>);
}
