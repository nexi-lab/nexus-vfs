//! `ObserverBackend` — extension trait for `ObjectStore` backends that
//! actively sync their authoritative file listing into the metastore.
//!
//! Design contract: `docs/observer-backend-contract.md`.
//!
//! ## Motivation
//!
//! Some backends own storage the kernel cannot mediate — the
//! `LocalConnectorBackend`, for example, mounts a host filesystem
//! directory where content can arrive by any path (raw fs write from a
//! peer process, `cc` writing task JSON directly, `rsync`, etc.).
//! Without this trait, the kernel relied on lazy observation — proposing
//! metadata rows at readdir time (`observe_backend_readdir_entry`) and
//! falling back to a fan-out probe on read miss (`fan_out`).  Both were
//! symptomatic patches; both are removed alongside this trait's arrival.
//!
//! ## Contract
//!
//! An `ObserverBackend` implementor owns the responsibility to keep the
//! metastore populated with a row for every path its backend can serve.
//! The kernel router, in turn, trusts the metastore as SSOT for
//! existence — no lazy readdir observation, no fan-out safety net.
//!
//! Implementors satisfy the contract via three layers (see the design
//! doc §3.2):
//!
//! 1. **Initial walk** at `install_observer` — synchronous, blocks the
//!    mount ready signal until every existing path has proposed a row.
//! 2. **OS-native watcher** — sub-second real-time updates for content
//!    that arrives after mount.
//! 3. **Periodic reconciler** — a self-verifying safety net against
//!    watcher event drops.  Additive-only in the MVP (see §3.3).

use std::sync::Weak;

use crate::abc::object_store::ObjectStore;

// Placement rationale: this module is an ObjectStore extension hook,
// not a §3.A storage pillar.  Per `crate::abc::mod`'s doc invariant,
// `abc/` holds only the three co-equal storage pillars
// (ObjectStore / MetaStore / CacheStore); extensions like this one
// live at the crate root alongside `crate::llm_streaming`.

/// Extension trait for backends that keep the metastore in sync with
/// their authoritative storage.  Consumed by
/// `DriverLifecycleCoordinator` at mount install time.
///
/// Backends that do NOT implement this trait must publish metadata
/// through the normal `sys_write` path (i.e. content-owning backends
/// like `PathLocalBackend`, `CasLocalBackend`, cloud object stores) —
/// the kernel router still trusts metastore in either case.
pub trait ObserverBackend: ObjectStore {
    /// Called once at mount install.  Runs the initial walk to
    /// completion, then spawns watcher and reconciler threads that
    /// share the returned `ObservationHandle`'s shutdown token.
    ///
    /// The sink is the sole channel through which the backend proposes
    /// metadata rows — the kernel deduplicates against existing
    /// metastore rows and best-effort-logs raft-put failures.  Calling
    /// `sink.propose` for the same path multiple times is idempotent.
    ///
    /// Returns an [`ObservationHandle`] whose Drop shuts down every
    /// task/thread the impl spawned.  `DriverLifecycleCoordinator`
    /// stores the handle for the mount's lifetime; unmount drops it.
    fn install_observer(
        &self,
        sink: ObservationSink,
    ) -> Result<ObservationHandle, ObservationError>;
}

/// Kernel-side channel for backends to propose metadata rows.
///
/// Cheap to clone — backends distribute clones to their walker,
/// watcher, and reconciler threads.  All calls are best-effort:
///
/// * Idempotent — kernel skips the propose if a row already covers the
///   path.
/// * Silent on transient raft failure — a `metastore_put` error logs a
///   warning and moves on; the reconciler will retry on the next tick.
/// * No-op if the kernel has been dropped (weak reference upgrade fail).
#[derive(Clone)]
pub struct ObservationSink {
    kernel: Weak<crate::kernel::Kernel>,
    zone_id: std::sync::Arc<str>,
}

impl ObservationSink {
    /// Constructed by `DriverLifecycleCoordinator` right before it
    /// hands the sink to `ObserverBackend::install_observer`.
    // Constructed only from DLC in production (wired in commit 4) and
    // from unit tests here — the allow silences the "no non-test
    // caller yet" warning during the scaffolding commit.
    #[allow(dead_code)]
    pub(crate) fn new(kernel: Weak<crate::kernel::Kernel>, zone_id: String) -> Self {
        Self {
            kernel,
            zone_id: zone_id.into(),
        }
    }

    /// Propose a metadata row for a backend-owned path.
    ///
    /// * `path` — VFS path (already resolved to the backend's mount
    ///   perspective; the kernel's mount routing is applied by
    ///   `metastore_put`).
    /// * `entry_type` — `DT_REG` or `DT_DIR` from `crate::meta_store`.
    /// * `size` — content size in bytes.  MUST reflect the actual size
    ///   for DT_REG rows (POSIX `read()` short-circuits on
    ///   `st_size == 0`); `0` is correct for DT_DIR.
    /// * `content_id` — backend addressing key (see
    ///   `ObserverBackend` contract in the design doc §3.2).  `None`
    ///   for DT_DIR entries; `Some(backend_path)` for DT_REG on
    ///   passthrough backends.
    ///
    /// Delegates to [`crate::kernel::Kernel::observe_backend_readdir_entry`]
    /// today; commit 4 of this PR inlines the propose logic here and
    /// deletes the kernel-side helper along with the lazy-observation
    /// chain that called it.
    pub fn propose(
        &self,
        path: &str,
        entry_type: u8,
        size: u64,
        content_id: Option<String>,
    ) {
        let Some(kernel) = self.kernel.upgrade() else {
            return;
        };
        kernel.observe_backend_readdir_entry(path, entry_type, &self.zone_id, size, content_id);
    }

    /// Zone the sink is bound to.  Useful for backend logging that
    /// wants to name the mount context.
    pub fn zone_id(&self) -> &str {
        &self.zone_id
    }
}

/// RAII shutdown guard.  Dropping the handle signals every task and
/// thread the backend spawned in `install_observer` to stop.
///
/// The internal `watch::Sender<bool>` supports both async
/// (`shutdown.wait_for(|&v| v).await`) and sync
/// (`*shutdown.borrow()`) observation; backends pick whichever fits
/// the layer they're implementing (tokio task for reconciler, OS
/// thread for `notify` watcher).
pub struct ObservationHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl ObservationHandle {
    /// Constructed by the backend's `install_observer`, alongside one
    /// receiver per task/thread the backend spawns.  Returned to the
    /// caller (DLC) so its Drop can broadcast shutdown.
    pub fn new() -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (Self { shutdown: tx }, rx)
    }

    /// Subscribe another consumer to the shutdown signal.  Used when
    /// the backend needs more than one receiver (e.g. watcher +
    /// reconciler + walker cleanup).
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }
}

impl Drop for ObservationHandle {
    fn drop(&mut self) {
        // Failure means every receiver has already been dropped — the
        // backend has already unwound, no shutdown broadcast required.
        let _ = self.shutdown.send(true);
    }
}

/// Errors surfaced by `ObserverBackend::install_observer`.
///
/// The initial walk must complete before mount is considered ready;
/// its failures ARE fatal (walk error → mount error → operator sees
/// it).  Steady-state watcher failures after install SHOULD be logged
/// by the backend and recovered on the next reconciler tick — they do
/// not propagate through this type.
#[derive(Debug)]
pub enum ObservationError {
    /// Directory walk failed during the initial sync pass.
    Walk(std::io::Error),
    /// Per-file stat failed during the initial sync pass.
    Stat {
        path: String,
        source: std::io::Error,
    },
    /// OS-native watcher failed to install (permissions, unsupported
    /// filesystem, etc.).
    Watcher(String),
}

impl std::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Walk(e) => write!(f, "observer initial walk failed: {e}"),
            Self::Stat { path, source } => {
                write!(f, "observer stat({path}) failed during initial walk: {source}")
            }
            Self::Watcher(msg) => write!(f, "observer watcher install failed: {msg}"),
        }
    }
}

impl std::error::Error for ObservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Walk(e) | Self::Stat { source: e, .. } => Some(e),
            Self::Watcher(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The handle's Drop broadcasts `true` on the shutdown channel; a
    /// consumer that was subscribed sees the transition on their next
    /// borrow.  The channel closes after Drop (sender is gone), which
    /// is fine — the last observed value stays valid for `borrow`.
    #[test]
    fn handle_drop_signals_shutdown() {
        let (handle, rx) = ObservationHandle::new();
        assert!(!*rx.borrow(), "shutdown starts false");
        drop(handle);
        assert!(*rx.borrow(), "shutdown observed true after handle drop");
    }

    /// `subscribe()` produces additional receivers that observe the
    /// same drop broadcast — mirrors the watcher + reconciler pattern.
    #[test]
    fn handle_subscribe_gives_independent_receivers() {
        let (handle, rx1) = ObservationHandle::new();
        let rx2 = handle.subscribe();
        drop(handle);
        assert!(*rx1.borrow());
        assert!(*rx2.borrow());
    }

    /// A sink whose kernel weak-ref cannot upgrade (kernel dropped)
    /// silently no-ops on `propose`.  Used during mount teardown when
    /// backend tasks may still call the sink while kernel is unwinding.
    #[test]
    fn sink_propose_noops_when_kernel_dropped() {
        let sink = ObservationSink::new(Weak::new(), "root".into());
        // Should not panic; propose returns nothing meaningful to
        // assert on the "kernel gone" branch — this is a "does not
        // crash" pin.
        sink.propose("/dropped", crate::meta_store::DT_REG, 0, None);
    }

    /// Sink's `Clone` produces an independent sink pointing at the
    /// same kernel + zone.  Backend distributes clones to
    /// walker/watcher/reconciler.
    #[test]
    fn sink_clone_preserves_zone() {
        let sink = ObservationSink::new(Weak::new(), "corp-eng".into());
        let cloned = sink.clone();
        assert_eq!(cloned.zone_id(), "corp-eng");
    }

    /// A minimal `ObserverBackend` impl compiles and returns a valid
    /// handle — pins the trait shape and its object-safety-adjacent
    /// signature.
    #[test]
    fn trait_impl_compiles_and_returns_handle() {
        struct StubBackend;

        impl ObjectStore for StubBackend {
            fn name(&self) -> &str {
                "stub"
            }
            fn write_content(
                &self,
                _content: &[u8],
                _content_id: &str,
                _ctx: &crate::kernel::OperationContext,
                _offset: u64,
            ) -> Result<crate::abc::object_store::WriteResult, crate::abc::object_store::StorageError>
            {
                unimplemented!()
            }
            fn read_content(
                &self,
                _content_id: &str,
                _ctx: &crate::kernel::OperationContext,
            ) -> Result<Vec<u8>, crate::abc::object_store::StorageError> {
                unimplemented!()
            }
        }

        impl ObserverBackend for StubBackend {
            fn install_observer(
                &self,
                _sink: ObservationSink,
            ) -> Result<ObservationHandle, ObservationError> {
                let (handle, _rx) = ObservationHandle::new();
                Ok(handle)
            }
        }

        let backend = Arc::new(StubBackend);
        let sink = ObservationSink::new(Weak::new(), "root".into());
        let handle = backend.install_observer(sink).expect("install");
        drop(handle);
    }
}
