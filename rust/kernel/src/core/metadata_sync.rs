//! `metadata_sync` — kernel-side reconcile that keeps the metastore
//! authoritative for a mount whose backend receives content out-of-band.
//!
//! Design contract: `docs/observer-backend-contract.md`.
//!
//! ## Why kernel-side, not a backend trait
//!
//! Some backends own storage the kernel cannot mediate — a
//! LocalConnector over a host directory that `cc` (or `rsync`, or any
//! process) writes to directly, bypassing `sys_write`. The metastore
//! must still learn about that content so peers see it via
//! raft-replicated `metastore.list`.
//!
//! The mechanism that achieves this — walk the backend's listing, propose
//! a metadata row per entry, repeat on an interval — is **entirely
//! generic**: it needs only `ObjectStore::list_dir` + `stat`, which every
//! backend provides. The backend contributes nothing type-specific.
//!
//! An earlier design modelled it as a per-backend trait (an
//! `ObserverBackend` reached via an `ObjectStore::as_observer` downcast).
//! That was wrong: concrete-type downcasts cannot cross the dylib C-ABI
//! boundary, so a dylib-loaded connector (the production `local-connector`)
//! is seen by the kernel as an opaque `DylibObjectStore` and the downcast
//! returned `None` — the sync never armed. `list_dir` / `stat` DO cross
//! that boundary (they're C-ABI methods), so running the walk kernel-side
//! over `&dyn ObjectStore` works uniformly for dylib and built-in backends.
//!
//! ## Triggers
//!
//! Three triggers feed the one idempotent atom
//! [`crate::kernel::Kernel::observe_backend_entry`]; each enumerates the
//! backend in whatever way is cheapest for it, then proposes the rows the
//! metastore is missing:
//!
//! 1. **Initial walk** (this module, [`arm`]) — a synchronous recursive
//!    walk at mount time, so every pre-existing entry is authoritative
//!    before the mount serves peers.
//! 2. **Periodic reconcile** (this module, the background thread) — the
//!    self-verifying backstop that re-walks every [`RECONCILE_INTERVAL`],
//!    catching content no one has listed yet.
//! 3. **On-access seed** (`Kernel::sys_readdir`) — when a `readdir` on an
//!    armed mount surfaces a backend child the metastore does not yet
//!    carry, that child is seeded synchronously in the same call, so the
//!    row (and its `last_writer`) exists at once instead of waiting up to a
//!    full reconcile interval. This is the low-latency path; triggers 1–2
//!    are the completeness floor.
//!
//! The three are the classic network-FS coherence split applied to the
//! metastore↔backend layer: eager seed + on-access revalidation, with a
//! periodic re-walk as the correctness backstop. They never conflict — the
//! atom is idempotent (it never clobbers an existing row, which is SSOT for
//! `last_writer_address` routing), so whichever trigger reaches a new entry
//! first wins and the rest are no-ops.
//!
//! ## Opt-in
//!
//! Whether a mount's backend receives out-of-band content is not knowable
//! generically, so arming is a deliberate per-mount opt-in: the boot path
//! calls [`crate::kernel::Kernel::arm_metadata_sync`] after mounting a
//! passthrough connector (e.g. the cluster profile arms it for
//! `--mount-driver local-connector:…`). Every other mount runs none of
//! this code — no reconcile thread, no walk, and `sys_readdir` skips the
//! on-access seed too (gated on `DriverLifecycleCoordinator::is_sync_armed`)
//! — no cost.

use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::abc::object_store::ObjectStore;
use crate::meta_store::{DT_DIR, DT_REG};

/// Reconcile cadence — the self-verifying backstop re-walks the backend
/// this often and re-proposes any entries the metastore is missing.
/// Additive-only (see `docs/observer-backend-contract.md` §3.3); a
/// watcher latency-optimization layer can be added later without
/// changing this correctness floor.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// Shutdown responsiveness — the reconcile loop sleeps in slices this
/// long so `MetadataSyncHandle::drop` joins promptly instead of waiting
/// out a full `RECONCILE_INTERVAL`.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Kernel-side channel a reconcile pass proposes metadata rows through.
///
/// Cheap to clone. All calls are best-effort:
///
/// * Idempotent — kernel skips the propose if a row already covers the
///   path (the existing row is SSOT for `last_writer_address` routing).
/// * Silent on transient raft failure — logs a warning and moves on; the
///   next reconcile tick retries.
/// * No-op if the kernel has been dropped (weak reference upgrade fail).
#[derive(Clone)]
pub struct MetadataSink {
    kernel: Weak<crate::kernel::Kernel>,
    zone_id: Arc<str>,
    /// Global VFS path the mount is installed at (e.g. `/shared/tasks`).
    /// The backend enumerates in its own backend-relative namespace; the
    /// sink prefixes with this to form the global path the metastore is
    /// keyed on. Empty / `"/"` for a root-mounted backend.
    mount_prefix: Arc<str>,
}

impl MetadataSink {
    /// Constructed by `DriverLifecycleCoordinator` at mount install.
    ///
    /// * `zone_id` — the mount's zone, stamped on every proposed row.
    /// * `mount_prefix` — the mount's global VFS path; backend-relative
    ///   paths are joined onto it.
    pub(crate) fn new(
        kernel: Weak<crate::kernel::Kernel>,
        zone_id: String,
        mount_prefix: String,
    ) -> Self {
        Self {
            kernel,
            zone_id: zone_id.into(),
            mount_prefix: mount_prefix.into(),
        }
    }

    /// Join the mount prefix with a backend-relative path to form the
    /// global VFS path the metastore is keyed on.
    pub(crate) fn global_path(&self, backend_rel: &str) -> String {
        let rel = backend_rel.trim_start_matches('/');
        let prefix = self.mount_prefix.trim_end_matches('/');
        if prefix.is_empty() {
            format!("/{rel}")
        } else if rel.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}/{rel}")
        }
    }

    /// Propose a metadata row for a backend-owned entry.
    ///
    /// * `backend_rel_path` — path relative to the backend root (what the
    ///   walk enumerates and what `content_id` addresses). Joined onto the
    ///   mount prefix.
    /// * `entry_type` — `DT_REG` or `DT_DIR`.
    /// * `size` — real byte size for DT_REG (POSIX `read()` short-circuits
    ///   on `st_size == 0`); `0` for DT_DIR.
    /// * `content_id` — `Some(backend_rel_path)` for DT_REG, `None` for
    ///   DT_DIR.
    ///
    /// Returns `true` iff a NEW row was proposed (not an idempotent skip
    /// or a failed put) — the reconcile aggregates this to report how
    /// much fresh content each pass materialized.
    fn propose(
        &self,
        backend_rel_path: &str,
        entry_type: u8,
        size: u64,
        content_id: Option<String>,
    ) -> bool {
        let Some(kernel) = self.kernel.upgrade() else {
            return false;
        };
        let global = self.global_path(backend_rel_path);
        kernel.observe_backend_entry(&global, entry_type, &self.zone_id, size, content_id)
    }
}

/// RAII shutdown guard for a mount's reconcile thread. Dropping it (on
/// unmount) signals the thread to stop.
pub(crate) struct MetadataSyncHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl MetadataSyncHandle {
    fn new() -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (Self { shutdown: tx }, rx)
    }
}

impl Drop for MetadataSyncHandle {
    fn drop(&mut self) {
        // Failure means the receiver already dropped — thread already
        // unwound, no broadcast needed.
        let _ = self.shutdown.send(true);
    }
}

/// Enumerate every entry under a backend, returning
/// `(backend_relative_path, entry_type, size)` tuples. Generic over any
/// `ObjectStore` — the same code drives a built-in backend and a
/// C-ABI-forwarded `DylibObjectStore`. Best-effort: an unreadable
/// subdirectory is skipped rather than aborting the walk (the next
/// reconcile tick re-attempts it).
fn collect_backend_listing(backend: &dyn ObjectStore) -> Vec<(String, u8, u64)> {
    let mut out = Vec::new();
    walk_dir(backend, "", &mut out);
    out
}

fn walk_dir(backend: &dyn ObjectStore, rel: &str, out: &mut Vec<(String, u8, u64)>) {
    let names = match backend.list_dir(rel) {
        Ok(n) => n,
        Err(_) => return,
    };
    for name in names {
        let is_dir = name.ends_with('/');
        let clean = name.trim_end_matches('/');
        if clean.is_empty() {
            continue;
        }
        let child_rel = if rel.is_empty() {
            clean.to_string()
        } else {
            format!("{rel}/{clean}")
        };
        if is_dir {
            out.push((child_rel.clone(), DT_DIR, 0));
            walk_dir(backend, &child_rel, out);
        } else {
            // DT_REG size from `stat` — POSIX read()/cat consult
            // st_size, so a size-0 stamp on a non-empty file reads empty.
            let size = backend.stat(&child_rel).map(|s| s.size).unwrap_or(0);
            out.push((child_rel, DT_REG, size));
        }
    }
}

/// Push one full backend listing through the sink. Idempotent at the
/// kernel layer, so the initial walk and every reconcile tick share it.
/// Returns the number of NEW rows proposed (existing rows are skipped).
fn sync_once(entries: &[(String, u8, u64)], sink: &MetadataSink) -> usize {
    let mut proposed = 0;
    for (rel, etype, size) in entries {
        let content_id = if *etype == DT_REG {
            Some(rel.clone())
        } else {
            None
        };
        if sink.propose(rel, *etype, *size, content_id) {
            proposed += 1;
        }
    }
    proposed
}

/// Arm the reconcile for a mount: run the initial walk synchronously
/// (seeds every pre-existing entry before the mount serves peers), then
/// spawn a background thread that re-walks every [`RECONCILE_INTERVAL`].
/// The returned handle's Drop stops the thread — the DLC stores it for
/// the mount's lifetime and drops it on unmount.
///
/// `backend` is held by the reconcile thread (an `Arc` clone keeps the
/// backend — and, for a dylib, its loaded library — alive as long as the
/// sync runs).
pub(crate) fn arm(backend: Arc<dyn ObjectStore>, sink: MetadataSink) -> MetadataSyncHandle {
    // Layer 1: initial walk, synchronous.
    let initial = collect_backend_listing(backend.as_ref());
    let proposed = sync_once(&initial, &sink);
    tracing::info!(
        target: "kernel::metadata_sync",
        enumerated = initial.len(),
        proposed,
        "metadata sync initial walk",
    );

    // Layer 3: periodic reconciler (the self-verifying backstop; a
    // sub-second watcher is a deferred latency optimization). Logs at
    // INFO only when a tick materialises NEW content (never per-tick
    // spam), so operators see out-of-band writes land in the metastore.
    let (handle, shutdown) = MetadataSyncHandle::new();
    let spawned = std::thread::Builder::new()
        .name("metadata-sync-reconcile".to_string())
        .spawn(move || {
            let slices = (RECONCILE_INTERVAL.as_millis() / SHUTDOWN_POLL.as_millis()).max(1) as u64;
            loop {
                for _ in 0..slices {
                    std::thread::sleep(SHUTDOWN_POLL);
                    if *shutdown.borrow() {
                        return;
                    }
                }
                let n = sync_once(&collect_backend_listing(backend.as_ref()), &sink);
                if n > 0 {
                    tracing::info!(
                        target: "kernel::metadata_sync",
                        proposed = n,
                        "metadata sync reconcile materialised new backend content to metastore",
                    );
                }
            }
        });
    if let Err(e) = spawned {
        // Initial walk already ran; only the ongoing reconcile is lost.
        tracing::error!(
            target: "kernel::metadata_sync",
            "failed to spawn metadata-sync-reconcile thread: {e}",
        );
    }
    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abc::object_store::{BackendStat, StorageError, WriteResult};
    use crate::kernel::OperationContext;

    /// In-memory backend exposing a fixed tree via `list_dir` / `stat`
    /// — stands in for any ObjectStore (built-in or dylib) the walk runs
    /// over.
    struct TreeBackend {
        dirs: std::collections::HashMap<String, Vec<String>>,
        sizes: std::collections::HashMap<String, u64>,
    }

    impl ObjectStore for TreeBackend {
        fn name(&self) -> &str {
            "tree-mock"
        }
        fn list_dir(&self, path: &str) -> Result<Vec<String>, StorageError> {
            self.dirs
                .get(path)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(path.to_string()))
        }
        fn stat(&self, path: &str) -> Result<BackendStat, StorageError> {
            if let Some(&size) = self.sizes.get(path) {
                Ok(BackendStat {
                    size,
                    is_dir: false,
                })
            } else if self.dirs.contains_key(path) {
                Ok(BackendStat {
                    size: 0,
                    is_dir: true,
                })
            } else {
                Err(StorageError::NotFound(path.to_string()))
            }
        }
        fn write_content(
            &self,
            _c: &[u8],
            _id: &str,
            _ctx: &OperationContext,
            _o: u64,
        ) -> Result<WriteResult, StorageError> {
            Err(StorageError::NotSupported("write_content"))
        }
        fn read_content(
            &self,
            _id: &str,
            _ctx: &OperationContext,
        ) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::NotSupported("read_content"))
        }
    }

    fn tree() -> TreeBackend {
        // Root: a.json (5) + sub/ ; sub: b.json (11)
        let mut dirs = std::collections::HashMap::new();
        dirs.insert(
            "".to_string(),
            vec!["a.json".to_string(), "sub/".to_string()],
        );
        dirs.insert("sub".to_string(), vec!["b.json".to_string()]);
        let mut sizes = std::collections::HashMap::new();
        sizes.insert("a.json".to_string(), 5);
        sizes.insert("sub/b.json".to_string(), 11);
        TreeBackend { dirs, sizes }
    }

    /// The generic walk recurses the whole tree over `&dyn ObjectStore`,
    /// tagging DT_DIR (size 0) vs DT_REG (real size) with backend-relative
    /// paths — the core of what makes the sync work for any backend,
    /// dylib or built-in.
    #[test]
    fn collect_backend_listing_recurses_and_tags() {
        let backend = tree();
        let listing = collect_backend_listing(&backend);
        let by: std::collections::HashMap<&str, (u8, u64)> = listing
            .iter()
            .map(|(p, t, s)| (p.as_str(), (*t, *s)))
            .collect();
        assert_eq!(by.get("a.json"), Some(&(DT_REG, 5)));
        assert_eq!(by.get("sub"), Some(&(DT_DIR, 0)));
        assert_eq!(by.get("sub/b.json"), Some(&(DT_REG, 11)));
        assert_eq!(by.len(), 3, "exactly the three entries");
    }

    #[test]
    fn sink_global_path_join_rules() {
        let s = |prefix: &str| MetadataSink::new(Weak::new(), "root".into(), prefix.into());
        assert_eq!(
            s("/shared/tasks").global_path("a.json"),
            "/shared/tasks/a.json"
        );
        assert_eq!(
            s("/shared/tasks").global_path("/a.json"),
            "/shared/tasks/a.json"
        );
        assert_eq!(
            s("/shared/tasks/").global_path("a.json"),
            "/shared/tasks/a.json"
        );
        assert_eq!(s("/shared").global_path("d/1.json"), "/shared/d/1.json");
        assert_eq!(s("").global_path("a.json"), "/a.json");
        assert_eq!(s("/shared/tasks").global_path(""), "/shared/tasks");
    }

    /// `propose` no-ops when the kernel weak-ref can't upgrade (teardown).
    #[test]
    fn sink_propose_noops_when_kernel_dropped() {
        let sink = MetadataSink::new(Weak::new(), "root".into(), "/mnt".into());
        sink.propose("x", DT_REG, 1, Some("x".into()));
    }

    /// `arm` on a kernel-less sink runs the initial walk (no-op proposes)
    /// and returns a handle whose Drop stops the reconcile thread without
    /// hanging.
    #[test]
    fn arm_returns_handle_and_shuts_down() {
        let backend: Arc<dyn ObjectStore> = Arc::new(tree());
        let sink = MetadataSink::new(Weak::new(), "root".into(), "/mnt".into());
        let handle = arm(backend, sink);
        drop(handle);
    }
}
