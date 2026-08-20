//! Cold-tier segment store for WAL DT_STREAMs — the content half of tiered
//! storage, wired into `WalStreamCore` at federation boot.
//!
//! `WalStreamCore` is a `core::stream` primitive and must never reach up into
//! the VFS router / object-store backends / peer client. So it takes a
//! [`ColdSegmentStore`] trait object; this federation-domain file is the kernel
//! impl. It composes the SAME path a DT_REG file's content takes — the reason
//! cold segments replicate + resolve cross-node exactly like file bytes already
//! do:
//!
//! * **write** — resolve the stream path's content backend (a per-mount backend,
//!   else the kernel-global federation cache for placeholder mounts) and
//!   `write_content` the segment blob, returning the id the backend assigned
//!   (a CAS hash, or — in the cluster profile's path-addressed backend — the
//!   storage path). Mirrors `sys_write`.
//! * **read** — the same backend locally, else a whole-blob `ReadBlob` peer
//!   fetch from the seal `origin`. Mirrors `sys_read` + `try_remote_fetch`.
//!
//! The field declaration (`Kernel::cold_segment_store`) lives on `Kernel`
//! proper; only the accessors + impl live here, matching the federation-cache
//! split in `coordinator_wiring.rs`.

use std::sync::{Arc, Weak};

use crate::abc::object_store::ObjectStore;
use crate::core::stream::wal::{ColdSegmentStore, SealPolicy};
use crate::kernel::{Kernel, OperationContext};

impl Kernel {
    /// Arm the cold-tier segment store — called at federation boot alongside
    /// [`Kernel::arm_stream_materializer`], so "coordinator wired ⇔ streams
    /// materialize cross-node ⇔ streams seal+spill" holds by construction.
    /// Idempotent (`OnceLock`). Until armed, `wal_backend_for` builds hot-only
    /// WAL cores (unbounded-in-raft) — the pre-P1 behaviour for a non-federated
    /// kernel.
    pub(crate) fn arm_stream_cold_tier(self: &Arc<Self>) {
        let store: Arc<dyn ColdSegmentStore> = Arc::new(KernelColdSegmentStore {
            kernel: Arc::downgrade(self),
        });
        let _ = self.cold_segment_store.set(store);
    }

    /// The armed cold-tier store, if any. `None` ⇒ hot-only WAL streams.
    pub(crate) fn cold_segment_store_arc(&self) -> Option<Arc<dyn ColdSegmentStore>> {
        self.cold_segment_store.get().cloned()
    }

    /// Roll thresholds for WAL DT_STREAM sealing. `NEXUS_STREAM_HOT_WINDOW` /
    /// `NEXUS_STREAM_SEAL_BATCH` override the keep-forever default; a
    /// `seal_batch` of `0` disables sealing (opt back into unbounded-in-raft).
    pub(crate) fn seal_policy(&self) -> SealPolicy {
        let parse = |name: &str, default: u64| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(default)
        };
        SealPolicy {
            hot_window: parse(
                "NEXUS_STREAM_HOT_WINDOW",
                SealPolicy::KEEP_FOREVER.hot_window,
            ),
            seal_batch: parse(
                "NEXUS_STREAM_SEAL_BATCH",
                SealPolicy::KEEP_FOREVER.seal_batch,
            ),
        }
    }

    /// Content backend for a stream's zone: the per-mount backend, else the
    /// kernel-global federation cache for a placeholder mount — the SAME
    /// resolution `sys_write`/`sys_read` use for DT_REG content, so a stream
    /// segment lands in and reads from exactly the store file bytes do.
    fn stream_content_backend(&self, stream_path: &str) -> Option<Arc<dyn ObjectStore>> {
        self.vfs_router
            .route(stream_path, contracts::ROOT_ZONE_ID)
            .and_then(|r| r.backend.clone())
            .or_else(|| self.federation_cache_arc())
    }

    /// Write a sealed segment blob to the content pillar, returning the id to
    /// record in the segment index (a CAS hash, or the storage path for the
    /// path-addressed federation cache). Mirrors `sys_write`'s content write.
    pub(crate) fn write_cold_segment(
        &self,
        stream_path: &str,
        base: u64,
        bytes: &[u8],
    ) -> Result<String, String> {
        let zone_id = self.routed_zone_id(stream_path);
        let backend = self
            .stream_content_backend(stream_path)
            .ok_or_else(|| format!("no content backend for stream {stream_path}"))?;
        let ctx = OperationContext::new(
            "system", &zone_id, /* is_admin */ true, None, /* is_system */ true,
        );
        // A unique per-segment key: ignored by a content-addressed backend
        // (id = hash of the bytes), the storage/fetch path for a path-addressed
        // one. Under the stream so a placeholder-mount route lands it in the
        // stream's zone, resolvable by a peer's `BlobFetcher::read` the same way
        // a DT_REG file is.
        let seg_key = format!("{stream_path}/__seg__/{base}");
        let wr = backend
            .write_content(bytes, &seg_key, &ctx, 0)
            .map_err(|e| format!("write cold segment ({stream_path} base {base}): {e:?}"))?;
        Ok(wr.content_id)
    }

    /// Read a sealed segment blob by `content_id`: the local content backend,
    /// else a whole-blob `ReadBlob` peer fetch from the seal `origin`. Mirrors
    /// `sys_read` + `try_remote_fetch`.
    pub(crate) fn read_cold_segment(
        &self,
        stream_path: &str,
        content_id: &str,
        origin: &str,
    ) -> Result<Vec<u8>, String> {
        let zone_id = self.routed_zone_id(stream_path);
        let ctx = OperationContext::new(
            "system", &zone_id, /* is_admin */ true, None, /* is_system */ true,
        );

        // Local content store first (the writer node, or any node that has
        // fetched it before under a shared/replicated backend).
        if let Some(backend) = self.stream_content_backend(stream_path) {
            if let Ok(data) = backend.read_content(content_id, &ctx) {
                return Ok(data);
            }
        }

        // Local miss: pull the whole blob from the node that sealed it — the
        // exact federated content read a DT_REG file uses. Never loop back to
        // self (we'd already have hit locally).
        if !origin.is_empty() {
            let is_self = self
                .self_address
                .read()
                .as_deref()
                .is_some_and(|me| me == origin);
            if !is_self {
                return self
                    .peer_client_arc()
                    .fetch(origin, content_id)
                    .map_err(|e| {
                        format!("peer fetch cold segment {content_id} from {origin}: {e}")
                    });
            }
        }
        Err(format!(
            "cold segment {content_id} unavailable (local miss; origin {origin:?})"
        ))
    }

    /// Delete the LOCAL blob for a trimmed segment (retention GC). A path-
    /// addressed backend (federation cache) deletes by the path `content_id`; a
    /// content-addressed one by hash — the other call returns NotSupported and is
    /// ignored. Returns `true` if a backend accepted the delete; `false` when
    /// neither did (no local backend, or the blob was already gone — the caller
    /// logs that, so a genuine reclaim failure is not silent).
    pub(crate) fn delete_cold_segment(&self, stream_path: &str, content_id: &str) -> bool {
        let Some(backend) = self.stream_content_backend(stream_path) else {
            return false;
        };
        // Either arm succeeding is a reclaim; NotSupported from the wrong arm for
        // this backend kind is expected and not a failure.
        backend.delete_content(content_id).is_ok() | backend.delete_file(content_id).is_ok()
    }

    /// Retention GC for a trimmed range: delete the LOCAL cold-segment blobs
    /// this node sealed (`origin == self`). The trim-GC apply-observer calls
    /// this on EVERY node for the same `TrimStreamSegment` command; each
    /// reclaims only its own-origin blobs, so a multi-origin stream is cleaned
    /// exactly once per blob with no cross-node delete race. A seal records
    /// `origin = self_origin().unwrap_or_default()` (the seal path above), so an
    /// un-federated single node (empty `self_address`) matches the empty origin
    /// it stamped and still reclaims its own blobs.
    ///
    /// Logs the reclaim outcome: without it a no-op GC (or a backend that
    /// silently refuses deletes) would leave the retention budget unbounded on
    /// disk with no signal — the log is the operator-visible proof the cold tier
    /// is actually reclaimed, and the hook the live e2e gates on.
    pub fn gc_trimmed_cold_segments(&self, stream_path: &str, trimmed: &[(String, String)]) {
        let me = self.self_address.read().clone().unwrap_or_default();
        let mut owned = 0usize;
        let mut reclaimed = 0usize;
        for (origin, content_id) in trimmed {
            if origin.as_str() == me.as_str() {
                owned += 1;
                if self.delete_cold_segment(stream_path, content_id) {
                    reclaimed += 1;
                }
            }
        }
        if owned == 0 {
            return; // none of the trimmed blobs are this node's to reclaim
        }
        if reclaimed == owned {
            tracing::info!(
                stream_id = %stream_path,
                reclaimed,
                "wal DT_STREAM trim-GC reclaimed cold segment blobs"
            );
        } else {
            tracing::warn!(
                stream_id = %stream_path,
                reclaimed,
                owned,
                "wal DT_STREAM trim-GC: some own-origin cold blobs not reclaimed (already gone / delete refused)"
            );
        }
    }
}

/// `ColdSegmentStore` bridge: a `Weak<Kernel>` so an in-flight seal thread that
/// outlives the kernel degrades to a clean error instead of keeping it alive.
struct KernelColdSegmentStore {
    kernel: Weak<Kernel>,
}

impl ColdSegmentStore for KernelColdSegmentStore {
    fn self_origin(&self) -> Option<String> {
        self.kernel
            .upgrade()
            .and_then(|k| k.self_address.read().clone())
    }

    fn write_segment(&self, stream_id: &str, base: u64, bytes: &[u8]) -> Result<String, String> {
        let k = self.kernel.upgrade().ok_or("kernel dropped")?;
        k.write_cold_segment(stream_id, base, bytes)
    }

    fn read_segment(
        &self,
        stream_id: &str,
        content_id: &str,
        origin: &str,
    ) -> Result<Vec<u8>, String> {
        let k = self.kernel.upgrade().ok_or("kernel dropped")?;
        k.read_cold_segment(stream_id, content_id, origin)
    }
}
