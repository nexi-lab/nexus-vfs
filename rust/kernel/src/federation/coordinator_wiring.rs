//! Federation kernel-side slot accessors + `/__sys__/zones/` procfs
//! synthesisers.
//!
//! Two §3.B-style kernel slots live here, each a single `Arc<dyn ...>`
//! the host binary installs at boot:
//!
//! * **DistributedCoordinator** (§3.B.1 HAL trait) — the federation
//!   control-plane impl from the raft crate.
//! * **federation cache backend** — single `Arc<dyn ObjectStore>` the
//!   kernel uses to satisfy sys_write / sys_read on federation-peer-
//!   mount placeholders under the uniform local-first contract.
//!   Rooted at `<data_dir>/federation-cache/`; addresses via the
//!   syscall's canonical path so every placeholder mount on this
//!   node shares ONE on-disk root.  SSOT for federation-bound bytes;
//!   `OnceLock` because the cache root is fixed at boot.
//!
//! Both slots live on [`Kernel`] proper (mod.rs) so the field
//! declarations sit next to the other Kernel state; only the
//! accessor methods live in this federation-domain file so
//! `MountEntry` / `RouteResult` in `core/` stay pristine kernel
//! primitives per `docs/KERNEL-ARCHITECTURE.md` §3/§4.

use std::sync::Arc;

use contracts::ZONES_PATH_PREFIX;

use crate::abc::object_store::ObjectStore;
use crate::core::procfs::ProcfsProvider;
use crate::kernel::{Kernel, StatResult};
use crate::meta_store::DT_DIR;

impl Kernel {
    /// Replace the kernel's coordinator slot with a concrete
    /// `DistributedCoordinator` impl. Kernel boots with
    /// `NoopDistributedCoordinator`; the host binary's boot path calls
    /// this with the real `nexus_raft::distributed_coordinator` impl
    /// once per kernel. Mirrors `set_peer_client`.
    pub fn set_distributed_coordinator(
        &self,
        coordinator: Arc<dyn crate::hal::distributed_coordinator::DistributedCoordinator>,
    ) {
        *self.distributed_coordinator.write() = coordinator;
    }

    /// Borrow the current distributed coordinator — read-locked snapshot.
    /// Internal callers use this to issue federation calls without
    /// holding the lock across `.await`. After `set_distributed_coordinator`
    /// runs at boot, this returns the real raft-backed impl; before
    /// then, a `NoopDistributedCoordinator` that errors on every call.
    pub fn distributed_coordinator(
        &self,
    ) -> Arc<dyn crate::hal::distributed_coordinator::DistributedCoordinator> {
        Arc::clone(&self.distributed_coordinator.read())
    }

    /// Bind the federation-cache backend.  Idempotent on second-set
    /// (the slot is [`std::sync::OnceLock`]; subsequent sets silently
    /// drop their argument).  Called by the host binary's boot path
    /// after `set_metastore_path`, with a `PathLocalBackend` rooted
    /// at `<data_dir>/federation-cache/`.
    ///
    /// Without this wiring, [`Self::federation_cache_arc`] returns
    /// `None` and sys_write on a federation-peer-mount placeholder
    /// surfaces a miss (the syscall layer treats no-cache as
    /// "operator declined to enable local-first federation writes
    /// on this node").
    pub fn set_federation_cache(&self, backend: Arc<dyn ObjectStore>) {
        let _ = self.federation_cache.set(backend);
    }

    /// Borrow the federation-cache backend, if any.  Returns `None`
    /// before [`Self::set_federation_cache`] runs — Rust unit-test
    /// embedders that never invoke federation skip wiring and the
    /// federation paths short-circuit cleanly.
    pub fn federation_cache_arc(&self) -> Option<Arc<dyn ObjectStore>> {
        self.federation_cache.get().cloned()
    }

    /// Federation procfs: synthesise a `StatResult` for paths under the
    /// `/__sys__/zones/` virtual namespace.  Read-only — like Linux
    /// `/proc`, callers cannot create / remove a zone by writing to
    /// this path.  Returns `Some` for `/__sys__/zones/` (directory
    /// marker) and `/__sys__/zones/<id>` (per-zone synthesised entry);
    /// `None` otherwise so the caller falls through to normal routing.
    pub(crate) fn zones_procfs_stat(&self, path: &str) -> Option<StatResult> {
        let suffix = path.strip_prefix(ZONES_PATH_PREFIX)?;
        let provider = self.distributed_coordinator();
        // Directory marker.
        if suffix.is_empty() || suffix == "/" {
            return Some(StatResult {
                path: path.to_string(),
                size: 4096,
                content_id: None,
                mime_type: "inode/directory".to_string(),
                is_directory: true,
                entry_type: crate::meta_store::DT_DIR,
                mode: 0o555, // r-x — read-only namespace
                version: 0,
                gen: 0,
                zone_id: Some("root".to_string()),
                created_at_ms: None,
                modified_at_ms: None,
                last_writer_address: None,
                lock: None,
                link_target: None,
                owner_id: None,
            });
        }
        // /__sys__/zones/<id>: synthesise from federation list.
        let zone_id = suffix.trim_start_matches('/');
        if zone_id.is_empty() || zone_id.contains('/') {
            return None;
        }
        if !provider.list_zones(self).iter().any(|z| z == zone_id) {
            return None;
        }
        Some(StatResult {
            path: path.to_string(),
            size: 0,
            content_id: None,
            mime_type: "application/x-nexus-zone".to_string(),
            is_directory: false,
            entry_type: crate::meta_store::DT_REG,
            mode: 0o444,
            version: 0,
            gen: 0,
            zone_id: Some(zone_id.to_string()),
            created_at_ms: None,
            modified_at_ms: None,
            last_writer_address: self.self_address_string(),
            lock: None,
            link_target: None,
            owner_id: None,
        })
    }
}

/// `/__sys__/zones` — the federation procfs view.
///
/// `zones_procfs_stat` above synthesises a per-zone entry for `sys_stat`;
/// this is the matching `readdir`, registered into the
/// [`crate::core::procfs`] registry at kernel boot. Zone membership is
/// cluster topology the peers already know, so unlike the locks and
/// credential views this one is not admin-gated.
pub struct ZonesProcfs;

impl ProcfsProvider for ZonesProcfs {
    fn prefix(&self) -> &str {
        ZONES_PATH_PREFIX
    }

    fn admin_only(&self) -> bool {
        false
    }

    fn readdir(&self, kernel: &Kernel, sub_path: &str) -> Vec<(String, u8)> {
        // The view is flat: zones live directly under it, and a zone id
        // is not a directory to descend into.
        if !sub_path.is_empty() {
            return Vec::new();
        }
        kernel
            .distributed_coordinator()
            .list_zones(kernel)
            .into_iter()
            .map(|zone_id| (zone_id, DT_DIR))
            .collect()
    }
}
