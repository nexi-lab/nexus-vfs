//! VFSRouter — kernel mount table SSOT for **runtime routing state**.
//!
//! Each `MountEntry` is the in-memory record for one mount: storage backend
//! and optional per-mount metastore. Together they form `VFSRouter`, an
//! LPM-routable container keyed by zone-canonical paths.
//!
//! **SSOT scope**: VFSRouter is authoritative for runtime path→backend
//! routing. DT_MOUNT *metadata* (the fact that a mount exists, its zone_id,
//! backend_name) is additionally persisted in the parent zone's metastore
//! so federation can replicate mount topology via raft. VFSRouter is
//! populated on boot from those metastore records + DLC.mount() calls.
//!
//! Access control lives one layer up (rebac); the mount table is pure routing.
//!
//! Concurrency: `DashMap` for lock-free reads on the syscall hot path. Add/
//! remove are rare (mount-lifecycle events) so the per-shard write lock is
//! invisible in practice.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use smallvec::SmallVec;
use std::sync::Arc;

use crate::abc::object_store::ObjectStore;
use crate::meta_store::MetaStore;

// Stack-resident canonical-key buffer for the routing hot path.
// 192 bytes covers `/{zone_id}/{path}` for typical workloads (zone_id
// is a short slug, paths are usually <180 chars). Longer keys spill
// to heap automatically — still correct, just no longer zero-alloc.
//
// Used by [`VFSRouter::route_in_zone`] to skip the `format!`-into-String
// that `canonicalize_mount_path` performs on every syscall.
type CanonKey = SmallVec<[u8; 192]>;

// Core canonicalize logic shared by the String-returning public helper
// and the stack-buffer hot-path form. Writes `/{zone_id}` or
// `/{zone_id}/{stripped_path}` into `buf`, clearing any previous content.
fn canonicalize_into(buf: &mut CanonKey, path: &str, zone_id: &str) {
    buf.clear();
    buf.push(b'/');
    buf.extend_from_slice(zone_id.as_bytes());
    let stripped = path.trim_start_matches('/');
    if !stripped.is_empty() {
        buf.push(b'/');
        buf.extend_from_slice(stripped.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// MountEntry — runtime record for a single mount
// ---------------------------------------------------------------------------

/// Per-mount runtime record.
///
/// `backend` is `Arc` so the root-zone mount's backend can be cheaply
/// cloned into every federation child-zone mount that reuses it.
/// Federation needs shared ownership without re-initialising the
/// backend per child zone.
///
/// `metastore` is `Arc` because the same metastore instance may be handed
/// in from a separate crate (e.g. `rust/raft::ZoneMetaStore`) via
/// `install_metastore`, and that crate keeps its own `Arc` reference to
/// the underlying state machine. Shared ownership is required.
pub struct MountEntry {
    /// Storage backend (CAS local, S3, OpenAI, gRPC remote, …).
    /// `None` means "no Rust backend available" — sys_read/sys_write fall
    /// back to caller-side handling (e.g. Python connector).
    pub backend: Option<Arc<dyn ObjectStore>>,

    /// Per-mount metastore for metadata operations. `None` means use the
    /// kernel's global `Kernel::metastore` instead. Federation mode wires a
    /// `ZoneMetaStore` here per zone.
    pub metastore: Option<Arc<dyn MetaStore>>,

    /// True when this mount is an external connector whose reads/writes
    /// must be handled by Python (no Rust fast path available).
    pub is_external: bool,

    /// For federation mounts: the zone id this mount points INTO.
    /// Populated by `wire_federation_mount_impl`. `None` for plain local
    /// mounts (backend-only, non-federation). Carried through
    /// [`RouteResult::zone_id`] so writes tag inode metadata with the
    /// owning zone rather than the caller's ambient zone, and
    /// `federation_share` can derive `(parent_zone, zone-relative prefix)`
    /// from a global path via the existing routing table.
    pub target_zone_id: Option<String>,

    /// Cached `backend.as_cas().is_some()` — CAS-vs-PAS classification
    /// is fixed at backend-set time, not per syscall. Set by
    /// [`MountEntry::new`] and refreshed by [`VFSRouter::rebind_missing_backends`]
    /// (the only two places `backend` is written), so the cache cannot
    /// drift relative to the backend it describes.
    pub is_cas: bool,
}

impl MountEntry {
    /// Construct a new entry. `metastore` always starts `None`; the metastore
    /// slot is owned by `VFSRouter::install_metastore` and never set through
    /// `add` / `add_mount` / `add_federation_mount` (orthogonal-slot contract).
    pub fn new(backend: Option<Arc<dyn ObjectStore>>) -> Self {
        let is_cas = backend.as_ref().is_some_and(|b| b.as_cas().is_some());
        Self {
            backend,
            metastore: None,
            is_external: false,
            target_zone_id: None,
            is_cas,
        }
    }

    /// Builder-style target-zone setter (federation mounts only).
    pub fn with_target_zone(mut self, target_zone_id: impl Into<String>) -> Self {
        self.target_zone_id = Some(target_zone_id.into());
        self
    }

    /// Builder-style external-flag setter.
    pub fn with_is_external(mut self, is_external: bool) -> Self {
        self.is_external = is_external;
        self
    }
}

// ---------------------------------------------------------------------------
// RouteResult — returned by VFSRouter::route
// ---------------------------------------------------------------------------

/// Result of a successful LPM route lookup.
///
/// `mount_point` carries the **zone-canonical key** (`/{zone_id}{user_path}`),
/// which is the same form `VFSRouter` is keyed by. Pass it straight into
/// `VFSRouter::{read_content, write_content, get_canonical, …}` without
/// re-canonicalizing.
#[derive(Clone)]
pub struct RouteResult {
    /// Zone-canonical key (`/{zone_id}{user_mount_point}`).
    pub mount_point: String,
    /// Path relative to the mount root (no leading slash).
    pub backend_path: String,
    /// Destination zone id for the routed mount. Populated from the
    /// canonicalized key's leading segment so metadata writes use the
    /// mount's zone, not the caller's ambient zone.
    pub zone_id: String,
    /// True when the routed mount is an external connector — Python must
    /// dispatch the operation through a Python-side backend adapter.
    pub is_external: bool,
    /// True when the routed backend is content-addressed (CAS).
    ///
    /// Derived from the backend trait's `as_cas()` downcast — single
    /// source of truth, no string-prefix sniffing on a label.
    pub is_cas: bool,
    /// Per-mount metastore Arc, populated from the same DashMap lookup
    /// that produced the routing result. `None` when the mount has no
    /// per-mount metastore wired — callers fall back to the kernel's
    /// global metastore via [`RouteResult::resolve_metastore`].
    ///
    /// Carried inline so the syscall hot path does not perform a second
    /// `VFSRouter::get_canonical` lookup just to fetch the metastore Arc
    /// after `route()` already did one. Same hot-path cost as the legacy
    /// `route() + dcache.get_entry()` pair.
    pub metastore: Option<Arc<dyn MetaStore>>,
    /// Per-mount backend Arc, populated from the same DashMap lookup that
    /// produced the routing result. `None` when the mount has no Rust
    /// backend (Python-side connector). Hot-path callers dispatch through
    /// the trait method (`route.backend.as_ref()?.read_content(...)`)
    /// instead of going back through a `VFSRouter::read_content` wrapper
    /// that would re-probe the entry table for the same mount we just
    /// routed to.
    pub backend: Option<Arc<dyn ObjectStore>>,
    /// Mirror of [`MountEntry::target_zone_id`].  `Some` when the routed
    /// entry is a federation mount (cross-zone or peer-only same-zone);
    /// `None` for plain local mounts.  Carried inline so io.rs federation
    /// peer dispatch can detect "this route lives on a peer node" without
    /// a second `vfs_router.get_canonical` lookup. `route.zone_id` alone
    /// is the RESOLVED zone (target if set, caller otherwise) — it can't
    /// distinguish "I routed into the caller's own zone" from "I routed
    /// into a federation target that happens to equal the caller's
    /// zone", which is the signal the placeholder MountEntry needs.
    pub target_zone_id: Option<String>,
}

impl RouteResult {
    /// Resolve the metastore for this mount, falling back to a
    /// kernel-supplied global metastore when the mount has no per-mount
    /// override. Returns `None` only when both are absent.
    pub fn resolve_metastore(
        &self,
        global_fallback: Option<&Arc<dyn MetaStore>>,
    ) -> Option<Arc<dyn MetaStore>> {
        self.metastore
            .as_ref()
            .map(Arc::clone)
            .or_else(|| global_fallback.map(Arc::clone))
    }

    /// True when this route is a federation-peer mount — i.e. the routed
    /// MountEntry is the placeholder shape installed by
    /// `wire_mount_core` on non-SSOT voters (no local backend) but
    /// carries a `target_zone_id` pointing at the peer that owns the
    /// LocalConnector for these bytes.
    ///
    /// Used internally by the `via_federation_*` / `supplement_*`
    /// behavior methods below to gate per-route — callers in
    /// `kernel/io.rs` and `kernel/mod.rs` should reach for those
    /// methods rather than predicating on this directly, so the
    /// federation-peer-mount concept stays a one-place check.
    #[inline]
    pub fn is_federation_peer_mount(&self) -> bool {
        self.backend.is_none() && self.target_zone_id.is_some()
    }

    // ── Federation-peer behavior methods ───────────────────────────────
    //
    // Two patterns for federation-peer-mounts (placeholder MountEntry
    // shape; no local backend; target_zone_id points at the SSOT peer):
    //
    // * **PURE-DEFER** (`via_federation_*`) — peer-only dispatch; the
    //   caller's local-side path runs only when this returns `None`,
    //   meaning "this route is not a federation-peer-mount; fall
    //   through to your local handling".  `Some(value)` carries the
    //   peer dispatch result and the caller short-circuits with it.
    //
    // * **SUPPLEMENT** (`supplement_*`) — peer fires ALONGSIDE the
    //   caller's local-side path; no return value.  For mkdir /
    //   rename / setattr, the local metastore mutation must happen
    //   IMMEDIATELY so the joiner's VFSRouter routes children of
    //   the new entry correctly — raft LWW dedupes the peer's
    //   eventual replicated mirror against ours.  See
    //   [[feedback_defer_to_peer_only_for_byte_ops]] for the full
    //   rationale on which syscalls take which pattern.
    //
    // No-op on non-federation-peer-mount routes — the methods become
    // zero-cost when the routed mount has a local backend (the common
    // case).  Internally each delegates to the kernel's
    // `federation_peer_*` dispatch arms; the later HAL collapse
    // re-points these bodies to `kernel.distributed_coordinator()
    // .peer_*` without touching call sites.

    /// Pure-defer write: peer's `NexusVFSService.Write` runs the full
    /// write lifecycle authoritatively on the SSOT side.
    ///
    /// Returns a [`crate::federation::FederationWriteOutcome`] —
    /// three named variants because sys_write must distinguish
    /// "fall through to local" from "return miss without local
    /// fallback".  See the type's docs for the rationale.
    #[inline]
    pub fn via_federation_write(
        &self,
        kernel: &crate::kernel::Kernel,
        peer_path: &str,
        content: &[u8],
    ) -> crate::federation::FederationWriteOutcome {
        use crate::federation::FederationWriteOutcome;
        let Some(target_zone) = self.federation_target_zone() else {
            return FederationWriteOutcome::NotPeer;
        };
        match kernel
            .distributed_coordinator()
            .peer_write(kernel, target_zone, peer_path, content)
        {
            Some(wr) => FederationWriteOutcome::Hit(wr),
            None => FederationWriteOutcome::DispatchMissed,
        }
    }

    /// Pure-defer stat: peer's `NexusVFSService.Stat` is authoritative
    /// for the placeholder mount.  Returns `Some(BackendStat)` on hit,
    /// `None` for non-federation routes or no-peer-hit (the latter is
    /// indistinguishable from "real not found" — same legacy semantics).
    #[inline]
    pub fn via_federation_stat(
        &self,
        kernel: &crate::kernel::Kernel,
        peer_path: &str,
    ) -> Option<crate::abc::object_store::BackendStat> {
        let target_zone = self.federation_target_zone()?;
        kernel
            .distributed_coordinator()
            .peer_stat(kernel, target_zone, peer_path)
    }

    /// Pure-defer readdir: peer's `NexusVFSService.Readdir` enumerates
    /// the placeholder mount's children.  Empty Vec is meaningful
    /// (real empty dir) — distinguish from "not found" by the
    /// `Some(entries)` / `None` split: `Some(_)` = peer dispatch hit
    /// (entries may be empty), `None` = not a federation route.
    #[inline]
    pub fn via_federation_readdir(
        &self,
        kernel: &crate::kernel::Kernel,
        peer_path: &str,
    ) -> Option<Vec<(String, u8)>> {
        let target_zone = self.federation_target_zone()?;
        kernel
            .distributed_coordinator()
            .peer_list_dir(kernel, target_zone, peer_path)
    }

    /// Pure-defer unlink: peer's `NexusVFSService.Delete` runs the
    /// full unlink lifecycle (metastore delete plus backend delete
    /// plus raft replication).
    ///
    /// Returns `Some(true)` when the peer delete succeeded,
    /// `Some(false)` when the route is a federation peer mount but
    /// dispatch missed (peer unreachable, coordinator without an
    /// installed grpc_ops, observability warns fire), and `None`
    /// when this is not a federation route (caller falls through
    /// to local unlink).
    #[inline]
    pub fn via_federation_unlink(
        &self,
        kernel: &crate::kernel::Kernel,
        peer_path: &str,
    ) -> Option<bool> {
        let target_zone = self.federation_target_zone()?;
        Some(
            kernel
                .distributed_coordinator()
                .peer_delete_file(kernel, target_zone, peer_path),
        )
    }

    /// Supplement mkdir: fires the peer's `NexusVFSService.Mkdir`
    /// alongside the caller's local metastore.put for the DT_DIR row.
    /// Best-effort — dispatch failure is logged by the coordinator
    /// observability path, not surfaced to the caller, so the local
    /// flow proceeds regardless.  See module-level rationale.
    #[inline]
    pub fn supplement_mkdir(
        &self,
        kernel: &crate::kernel::Kernel,
        peer_path: &str,
        parents: bool,
        exist_ok: bool,
    ) {
        let Some(target_zone) = self.federation_target_zone() else {
            return;
        };
        let _ = kernel.distributed_coordinator().peer_mkdir(
            kernel,
            target_zone,
            peer_path,
            parents,
            exist_ok,
        );
    }

    /// Supplement rename: fires the peer's `NexusVFSService.Rename`
    /// alongside the caller's local `metastore.rename_path`.
    /// Best-effort — same silent-miss semantics as `supplement_mkdir`.
    #[inline]
    pub fn supplement_rename(
        &self,
        kernel: &crate::kernel::Kernel,
        old_path: &str,
        new_path: &str,
    ) {
        let Some(target_zone) = self.federation_target_zone() else {
            return;
        };
        let _ =
            kernel
                .distributed_coordinator()
                .peer_rename(kernel, target_zone, old_path, new_path);
    }

    /// Supplement setattr (DT_REG only): fires the peer's
    /// `NexusVFSService.Setattr` alongside the caller's local
    /// metastore.put for the DT_REG row.  Best-effort.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn supplement_setattr(
        &self,
        kernel: &crate::kernel::Kernel,
        peer_path: &str,
        mime_type: Option<&str>,
        content_id: Option<&str>,
        modified_at_ms: Option<i64>,
        created_at_ms: Option<i64>,
        size: Option<u64>,
        version: Option<u32>,
    ) {
        let Some(target_zone) = self.federation_target_zone() else {
            return;
        };
        let _ = kernel.distributed_coordinator().peer_setattr(
            kernel,
            target_zone,
            peer_path,
            mime_type,
            content_id,
            modified_at_ms,
            created_at_ms,
            size,
            version,
        );
    }

    /// Internal: return the target zone id for a federation-peer-mount
    /// route, or `None` for plain local routes.  Centralises the
    /// `backend.is_none() && target_zone_id.is_some()` predicate +
    /// the `target_zone_id.as_deref()` extraction so every `via_*` /
    /// `supplement_*` method shares the same gate shape.
    #[inline]
    fn federation_target_zone(&self) -> Option<&str> {
        if self.backend.is_some() {
            return None;
        }
        self.target_zone_id.as_deref()
    }
}

impl std::fmt::Debug for RouteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteResult")
            .field("mount_point", &self.mount_point)
            .field("backend_path", &self.backend_path)
            .field("zone_id", &self.zone_id)
            .field("is_external", &self.is_external)
            .field("is_cas", &self.is_cas)
            .field("metastore", &self.metastore.is_some())
            .field("backend", &self.backend.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// VFSRouter — kernel-owned mount registry
// ---------------------------------------------------------------------------

pub struct VFSRouter {
    entries: DashMap<String, MountEntry>,
}

impl Default for VFSRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl VFSRouter {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    // ── Write ops (called by DLC.mount/unmount) ────────────────────────

    /// Upsert the backend-side fields of a mount entry under its
    /// zone-canonical key. The metastore slot is **never** written here —
    /// it is owned by `install_metastore`.
    ///
    /// Orthogonal-slot contract: each mount entry has two independent
    /// slots — backend-side (backend, is_external, target_zone_id) and
    /// metastore. `add` (and its wrappers `add_mount` /
    /// `add_federation_mount`) own the first; `install_metastore` owns
    /// the second. Neither operation clobbers the other's slot, so the
    /// federation bootstrap order — `attach_raft_zone_to_kernel` installs
    /// the metastore at `/` first, the root DLC mount adds the backend
    /// later (or vice versa) — converges to the same final state without
    /// any preserve-on-conflict heuristic.
    ///
    /// Atomic via `DashMap::entry()` — the read-decide-write sequence
    /// runs under one shard write lock, so a concurrent `install_metastore`
    /// for the same key cannot interleave.
    pub fn add(&self, mount_point: &str, zone_id: &str, entry: MountEntry) {
        debug_assert!(
            entry.metastore.is_none(),
            "VFSRouter::add ignores the metastore slot; callers must use \
             install_metastore (orthogonal-slot contract)",
        );
        let canonical = canonicalize_mount_path(mount_point, zone_id);
        match self.entries.entry(canonical) {
            Entry::Occupied(mut occ) => {
                let preserved_metastore = occ.get().metastore.clone();
                let mut new_entry = entry;
                new_entry.metastore = preserved_metastore;
                *occ.get_mut() = new_entry;
            }
            Entry::Vacant(vac) => {
                vac.insert(entry);
            }
        }
    }

    /// Convenience: build a `MountEntry` from flat args and insert it.
    /// Used by `Kernel::add_mount` so callers don't have to import
    /// `MountEntry` just to register a mount.
    pub fn add_mount(
        &self,
        mount_point: &str,
        zone_id: &str,
        backend: Option<Arc<dyn ObjectStore>>,
        is_external: bool,
    ) {
        self.add(
            mount_point,
            zone_id,
            MountEntry::new(backend).with_is_external(is_external),
        );
    }

    /// Federation variant: install a mount that carries an explicit
    /// `target_zone_id`. Routing through this mount resolves to the
    /// target zone, not the caller's ambient one — so writes tag inode
    /// metadata with the owning zone and `federation_share` can derive
    /// `(parent_zone, zone-relative prefix)` from a global path.
    pub fn add_federation_mount(
        &self,
        mount_point: &str,
        zone_id: &str,
        backend: Option<Arc<dyn ObjectStore>>,
        target_zone_id: &str,
        is_external: bool,
    ) {
        self.add(
            mount_point,
            zone_id,
            MountEntry::new(backend)
                .with_is_external(is_external)
                .with_target_zone(target_zone_id),
        );
    }

    /// Remove a mount. Returns `true` if it existed.
    pub fn remove(&self, mount_point: &str, zone_id: &str) -> bool {
        let canonical = canonicalize_mount_path(mount_point, zone_id);
        self.entries.remove(&canonical).is_some()
    }

    /// Replace (or set) the per-mount metastore on an entry.
    ///
    /// Upsert semantics: if no entry exists under ``canonical_key`` yet,
    /// a bare placeholder entry (no backend) is created and tagged with
    /// the metastore. This lets federation bootstrap attach a
    /// ``ZoneMetaStore`` at ``/`` before the root DLC mount registers its
    /// backend — when the backend mount arrives later, ``add`` preserves
    /// the already-installed metastore.
    ///
    /// Atomic via `DashMap::entry()` — the get-or-insert sequence runs
    /// under one shard write lock, so a concurrent `add` cannot create
    /// an entry between the lookup-miss and the insert and have its
    /// content clobbered.
    pub fn install_metastore(&self, canonical_key: &str, metastore: Arc<dyn MetaStore>) {
        match self.entries.entry(canonical_key.to_string()) {
            Entry::Occupied(mut occ) => {
                occ.get_mut().metastore = Some(metastore);
            }
            Entry::Vacant(vac) => {
                let mut entry = MountEntry::new(None);
                entry.metastore = Some(metastore);
                vac.insert(entry);
            }
        }
    }

    // ── Read ops ───────────────────────────────────────────────────────
    //
    // Returning `dashmap::mapref::one::Ref` (lifetime-tied to the table)
    // keeps the syscall hot path zero-allocation. Callers use the guard
    // immediately and let it drop.

    /// Borrow the entry under an exact canonical key.
    pub fn get_canonical(
        &self,
        canonical_key: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, MountEntry>> {
        self.entries.get(canonical_key)
    }

    /// Borrow the entry for `(mount_point, zone_id)`.
    pub fn get(
        &self,
        mount_point: &str,
        zone_id: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, MountEntry>> {
        let canonical = canonicalize_mount_path(mount_point, zone_id);
        self.entries.get(&canonical)
    }

    /// True if a mount exists under `(mount_point, zone_id)`.
    pub fn has(&self, mount_point: &str, zone_id: &str) -> bool {
        let canonical = canonicalize_mount_path(mount_point, zone_id);
        self.entries.contains_key(&canonical)
    }

    /// Borrow every entry mutably. Used by ``Kernel::release_metastores``
    /// (Issue #3765 Cat-5/6) to drop per-mount ``Arc<dyn MetaStore>`` so the
    /// underlying redb file handles are released on kernel close.
    pub fn entries_iter_mut(
        &self,
    ) -> impl Iterator<Item = dashmap::mapref::multiple::RefMutMulti<'_, String, MountEntry>> {
        self.entries.iter_mut()
    }

    /// All registered canonical keys (sorted). Cheap copy — mounts are rare.
    pub fn canonical_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.entries.iter().map(|e| e.key().clone()).collect();
        keys.sort();
        keys
    }

    /// Snapshot every non-empty backend registered on the mount table.
    ///
    /// Used by `KernelBlobFetcher` to resolve `ReadBlob` by content hash
    /// without caring which mount the blob originally landed on — CAS
    /// backends are content-addressed, so any local mount with the right
    /// blob satisfies the request.
    pub fn backends(&self) -> Vec<Arc<dyn ObjectStore>> {
        self.entries
            .iter()
            .filter_map(|e| e.backend.as_ref().map(Arc::clone))
            .collect()
    }

    /// Rebind `new_backend` into every entry matching `should_rebind`.
    /// Returns the number of entries touched.
    ///
    /// The router stays federation-agnostic — it only provides the
    /// "iterate + atomically update backend + refresh `is_cas`"
    /// mechanism. The caller (currently `Kernel::add_mount` on the
    /// root mount, which has the federation context) supplies the
    /// policy (predicate) that decides which entries should receive
    /// the new backend.
    ///
    /// Typical caller use: fix a boot-order bug where
    /// `RaftDistributedCoordinator::replay_existing_mounts` replays
    /// federation DT_MOUNT entries before Python installs the root
    /// mount that carries this node's CAS backend, leaving those
    /// entries with `backend=None`. The caller predicate
    /// `|e| e.backend.is_none() && e.metastore.is_some()` selects
    /// exactly the stranded-federation mounts; plain backend-only
    /// local mounts (`metastore=None`) and Python-connector mounts
    /// (`metastore=None`) are left alone.
    pub fn rebind_missing_backends(
        &self,
        new_backend: &Arc<dyn ObjectStore>,
        should_rebind: impl Fn(&MountEntry) -> bool,
    ) -> usize {
        let new_is_cas = new_backend.as_cas().is_some();
        let mut rebound = 0;
        for mut entry in self.entries.iter_mut() {
            if should_rebind(entry.value()) {
                entry.backend = Some(Arc::clone(new_backend));
                entry.is_cas = new_is_cas;
                rebound += 1;
            }
        }
        rebound
    }

    /// All user-facing mount points (zone prefix stripped, sorted).
    pub fn mount_points(&self) -> Vec<String> {
        let mut points: Vec<String> = self
            .entries
            .iter()
            .map(|e| extract_zone_from_canonical(e.key()).1)
            .collect();
        points.sort();
        points
    }

    /// User-facing mount points whose per-mount metastore reports the
    /// given ``coherence_key``.
    ///
    /// Each crosslink has its own ``ZoneMetaStore`` allocation, so Arc
    /// identity does not group crosslinks of the same zone — each zone
    /// needs a storage-level identity that survives per-mount wrapping.
    /// ``MetaStore::coherence_key`` exposes that identity (stable
    /// integer; state-machine Arc pointer for raft-backed zones,
    /// ``None`` for standalone ``LocalMetaStore``).
    ///
    /// Kernel stays federation-agnostic — ``coherence_key`` is just an
    /// opaque ``usize``; the kernel never learns "zone id" or any other
    /// federation concept. Apply-side cache coherence fans out through
    /// this primitive: federation passes the state-machine identity,
    /// kernel returns every surface currently bound to it.
    pub fn mount_points_for_coherence_key(&self, key: usize) -> Vec<String> {
        let mut points: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| {
                e.value().metastore.as_ref().and_then(|existing| {
                    (existing.coherence_key() == Some(key))
                        .then(|| extract_zone_from_canonical(e.key()).1)
                })
            })
            .collect();
        points.sort();
        points
    }

    /// Number of mounted entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── LPM routing ────────────────────────────────────────────────────

    /// Longest-prefix-match routing within a zone, with fallback to the
    /// root zone's mounts.
    ///
    /// Walks zone-canonical mount keys from deepest to shallowest. If the
    /// caller's zone has no matching mount, retries once under the root
    /// zone — root mounts are the global default visible to every zone
    /// (federation or standalone). Pure routing — access control
    /// (read-only, admin-only, RBAC) lives in rebac, not here.
    ///
    /// Returns `None` when no mount covers the path. The miss reason is
    /// always the same ("no mount"), so callers construct their own
    /// caller-shaped error (`KernelError::FileNotFound`,
    /// `KernelError::PermissionDenied`, …) at the call site — eliminates
    /// the eager `format!` that the previous `RouteError::NotMounted`
    /// wrapper paid for every miss, including `.ok()` callers that
    /// discarded it.
    pub fn route(&self, path: &str, zone_id: &str) -> Option<RouteResult> {
        let initial = self.route_in_zone(path, zone_id).or_else(|| {
            (zone_id != contracts::ROOT_ZONE_ID)
                .then(|| self.route_in_zone(path, contracts::ROOT_ZONE_ID))
                .flatten()
        })?;

        // Federation-mount recursion: when the LPM hit is a
        // federation_mount (resolved_zone != lookup zone), retry the
        // route inside the target zone's namespace.  Operator-installed
        // driver mounts (e.g. `--mount-driver
        // local-connector:sharedzone:/shared/cc-tasks/founder:{...}`)
        // are keyed under their own zone (`/sharedzone/...`), so an
        // initial root-zone LPM walks through the parent federation
        // mount (`/root/shared` → sharedzone) and hands back the
        // root_backend the federation install carries.  Without this
        // recursion the more-specific driver mount in the target zone
        // is unreachable, and reads/writes against paths under it
        // silently route through root's PathLocal instead of the
        // operator-configured backend.
        //
        // Cost is amortised at most one extra LPM walk per syscall, and
        // ONLY when the first walk actually resolves into a different
        // zone (i.e. the path crosses a federation mount) — the
        // overwhelming hit pattern (`/root/...` paths in the local zone)
        // takes a single walk and the early-return below skips the
        // second.
        if initial.zone_id != zone_id {
            if let Some(deeper) = self.route_in_zone(path, &initial.zone_id) {
                // Only prefer the deeper hit when it's *strictly more
                // specific* than the federation mount we routed
                // through — same canonical mount point means the
                // federation mount itself; keep the initial answer.
                if deeper.mount_point != initial.mount_point {
                    return Some(deeper);
                }
            }
        }

        Some(initial)
    }

    fn route_in_zone(&self, path: &str, zone_id: &str) -> Option<RouteResult> {
        // Stack-buffered canonical key — zero-alloc for typical paths
        // (<192 chars after `/{zone_id}/{path}` expansion). The buffer
        // lives for the function body so `canonical` borrows can outlast
        // the LPM walk's iterative reslices.
        let mut buf: CanonKey = SmallVec::new();
        canonicalize_into(&mut buf, path, zone_id);
        // Inputs are `&str` (validated UTF-8) and we only inject ASCII
        // `'/'`; the byte buffer is necessarily valid UTF-8. Validation
        // is cheap (memchr) but unnecessary work on the hot path —
        // `unwrap` documents the invariant without a release-build
        // branch surviving optimization.
        let canonical: &str = std::str::from_utf8(&buf).expect("UTF-8 by construction");
        let mut current = canonical;

        loop {
            if let Some(entry) = self.entries.get(current) {
                let mount_point = current.to_string();
                let backend_path = strip_mount_prefix(canonical, current);
                let is_external = entry.is_external;
                // CAS-ness is cached at backend-set time (`MountEntry::new` /
                // `rebind_missing_backends`); the hot path just reads.
                let is_cas = entry.is_cas;
                let resolved_zone = entry
                    .target_zone_id
                    .clone()
                    .unwrap_or_else(|| zone_id.to_string());
                let metastore = entry.metastore.as_ref().map(Arc::clone);
                let backend = entry.backend.as_ref().map(Arc::clone);
                let target_zone_id = entry.target_zone_id.clone();
                drop(entry);

                return Some(RouteResult {
                    mount_point,
                    backend_path,
                    zone_id: resolved_zone,
                    is_external,
                    is_cas,
                    metastore,
                    backend,
                    target_zone_id,
                });
            }

            if current == "/" {
                break;
            }
            match current.rfind('/') {
                Some(0) => current = "/",
                Some(pos) => current = &canonical[..pos],
                None => break,
            }
        }
        None
    }

    // Backend-operation dispatch happens at the call site through the
    // pre-resolved ``RouteResult::backend`` Arc (see ``route()``).  The
    // syscall layer in ``kernel/io.rs`` always has a fresh ``RouteResult``
    // in scope, so no second DashMap lookup is needed to reach the
    // backend trait method.
}

// ---------------------------------------------------------------------------
// Path helpers — kernel-public so external crates (e.g. `rust/raft`) can
// produce keys consistent with the table.
// ---------------------------------------------------------------------------

/// Build the zone-canonical key `/{zone_id}{mount_point}`.
///
/// Examples:
/// - `("/workspace/file.txt", "root")` → `"/root/workspace/file.txt"`
/// - `("/", "zone-beta")` → `"/zone-beta"`
pub fn canonicalize_mount_path(path: &str, zone_id: &str) -> String {
    let stripped = path.trim_start_matches('/');
    if stripped.is_empty() {
        format!("/{}", zone_id)
    } else {
        format!("/{}/{}", zone_id, stripped)
    }
}

/// Inverse of [`canonicalize_mount_path`]: split a canonical key back into
/// `(zone_id, mount_point)`.
///
/// Examples:
/// - `"/root/workspace/file.txt"` → `("root", "/workspace/file.txt")`
/// - `"/zone-beta"` → `("zone-beta", "/")`
pub fn extract_zone_from_canonical(canonical: &str) -> (String, String) {
    let trimmed = canonical.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((zone, rest)) => (zone.to_string(), format!("/{}", rest)),
        None => (trimmed.to_string(), "/".to_string()),
    }
}

/// Convert a zone-relative path back to a global (user-facing) path using
/// the zone-canonical mount point.
///
/// Inverse of the zone-key transformation performed by
/// [`Kernel::zone_key`](crate::kernel::Kernel::zone_key): given the
/// canonical mount point and a zone-relative metastore key, reconstruct
/// the global path a user would pass to a syscall.
///
/// Examples:
/// - `("/root/corp", "/eng/foo.txt")` → `"/corp/eng/foo.txt"`
/// - `("/root", "/workspace/file.txt")` → `"/workspace/file.txt"`
/// - `("", "/workspace/file.txt")` → `"/workspace/file.txt"` (no-mount fallback)
pub fn zone_to_global(mount_point: &str, zone_path: &str) -> String {
    if mount_point.is_empty() {
        return zone_path.to_string();
    }
    let (_, user_mp) = extract_zone_from_canonical(mount_point);
    if user_mp == "/" {
        zone_path.to_string()
    } else {
        format!("{}{}", user_mp, zone_path)
    }
}

/// Strip a mount-point prefix from a canonical path to get the
/// backend-relative path (without leading slash).
///
/// **Precondition:** `mount_point` is an LPM prefix of `path` aligned on
/// a `/` boundary (or `mount_point == path`, or `mount_point == "/"`).
/// `VFSRouter::route_in_zone` is the only caller and enforces this by
/// construction (its walk only inspects ancestors at `/` boundaries via
/// `rfind('/')`), but the precondition is implicit; spelling it out as
/// a `debug_assert!` documents the invariant and catches any future
/// misuse (e.g. a caller passing `path="/root/data2/x"` with
/// `mount_point="/root/data"` would otherwise silently produce
/// `"2/x"` instead of a routing miss).
fn strip_mount_prefix(path: &str, mount_point: &str) -> String {
    debug_assert!(
        path == mount_point
            || mount_point == "/"
            || path
                .strip_prefix(mount_point)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/')),
        "strip_mount_prefix called with non-LPM mount_point: path={path:?} \
         mount_point={mount_point:?}",
    );
    if path == mount_point {
        String::new()
    } else if mount_point == "/" {
        path.trim_start_matches('/').to_string()
    } else {
        path[mount_point.len()..]
            .trim_start_matches('/')
            .to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> MountEntry {
        MountEntry::new(None)
    }

    #[test]
    fn test_canonicalize_mount_path() {
        assert_eq!(
            canonicalize_mount_path("/workspace/file.txt", "root"),
            "/root/workspace/file.txt"
        );
        assert_eq!(canonicalize_mount_path("/", "root"), "/root");
        assert_eq!(canonicalize_mount_path("/a/b/c", "zone-1"), "/zone-1/a/b/c");
    }

    #[test]
    fn test_extract_zone_from_canonical() {
        assert_eq!(
            extract_zone_from_canonical("/root/workspace/file.txt"),
            ("root".into(), "/workspace/file.txt".into())
        );
        assert_eq!(
            extract_zone_from_canonical("/root"),
            ("root".into(), "/".into())
        );
        assert_eq!(
            extract_zone_from_canonical("/zone-1/a/b"),
            ("zone-1".into(), "/a/b".into())
        );
    }

    #[test]
    fn test_strip_mount_prefix() {
        assert_eq!(
            strip_mount_prefix("/root/workspace/data/file.txt", "/root/workspace"),
            "data/file.txt"
        );
        assert_eq!(strip_mount_prefix("/root/workspace", "/root/workspace"), "");
        assert_eq!(strip_mount_prefix("/root/a/b", "/root"), "a/b");
    }

    #[test]
    fn test_basic_route() {
        let table = VFSRouter::new();
        table.add("/", "root", entry());
        table.add("/workspace", "root", entry());

        let r = table.route("/workspace/file.txt", "root").unwrap();
        assert_eq!(r.mount_point, "/root/workspace");
        assert_eq!(r.backend_path, "file.txt");
    }

    #[test]
    fn test_route_falls_back_to_root() {
        let table = VFSRouter::new();
        table.add("/", "root", entry());

        let r = table.route("/unknown/path", "root").unwrap();
        assert_eq!(r.mount_point, "/root");
        assert_eq!(r.backend_path, "unknown/path");
    }

    #[test]
    fn test_cross_zone_isolation() {
        let table = VFSRouter::new();
        table.add("/", "root", entry());
        table.add("/shared", "zone-beta", entry());

        // root zone falls back to root mount
        let r = table.route("/workspace/file.txt", "root").unwrap();
        assert_eq!(r.mount_point, "/root");

        // zone-beta sees its own mount
        let r = table.route("/shared/doc.txt", "zone-beta").unwrap();
        assert_eq!(r.mount_point, "/zone-beta/shared");
    }

    #[test]
    fn test_install_metastore_late() {
        use crate::meta_store::{FileMetadata, MetaStoreError};

        // Trivial in-memory MetaStore impl for the test.
        struct DummyMs;
        impl MetaStore for DummyMs {
            fn get(&self, _: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
                Ok(None)
            }
            fn put(&self, _: &str, _: FileMetadata) -> Result<(), MetaStoreError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<bool, MetaStoreError> {
                Ok(false)
            }
            fn list(&self, _: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
                Ok(vec![])
            }
            fn exists(&self, _: &str) -> Result<bool, MetaStoreError> {
                Ok(false)
            }
        }

        let table = VFSRouter::new();
        table.add("/data", "root", entry());
        let canonical = canonicalize_mount_path("/data", "root");

        // Initially no metastore.
        assert!(table.get_canonical(&canonical).unwrap().metastore.is_none());

        table.install_metastore(&canonical, Arc::new(DummyMs));
        assert!(table.get_canonical(&canonical).unwrap().metastore.is_some());
    }

    #[test]
    fn test_mount_management() {
        let table = VFSRouter::new();
        table.add("/data", "root", entry());
        assert!(table.has("/data", "root"));
        assert!(!table.has("/data", "other"));

        assert_eq!(table.canonical_keys(), vec!["/root/data"]);

        assert!(table.remove("/data", "root"));
        assert!(!table.has("/data", "root"));
    }

    // ── zone_to_global tests ─────────────────────────────────────────

    #[test]
    fn zone_to_global_root_mount() {
        // Root zone at "/" → zone-relative = global (no-op)
        assert_eq!(
            zone_to_global("/root", "/workspace/file.txt"),
            "/workspace/file.txt"
        );
        assert_eq!(zone_to_global("/root", "/"), "/");
    }

    #[test]
    fn zone_to_global_non_root_mount() {
        // Mount at "/corp" in root zone → zone-relative "/eng/foo.txt" → global "/corp/eng/foo.txt"
        assert_eq!(
            zone_to_global("/root/corp", "/eng/foo.txt"),
            "/corp/eng/foo.txt"
        );
        assert_eq!(zone_to_global("/root/corp", "/"), "/corp/");
    }

    #[test]
    fn zone_to_global_nested_mount() {
        // Nested mount at "/corp/eng" → zone-relative "/readme.md" → global "/corp/eng/readme.md"
        assert_eq!(
            zone_to_global("/root/corp/eng", "/readme.md"),
            "/corp/eng/readme.md"
        );
    }

    #[test]
    fn zone_to_global_empty_mount_fallback() {
        // No-mount fallback (empty mount_point) → pass-through
        assert_eq!(
            zone_to_global("", "/workspace/file.txt"),
            "/workspace/file.txt"
        );
    }

    #[test]
    fn zone_to_global_round_trip() {
        // canonicalize → route → zone_key → zone_to_global should recover original
        let table = VFSRouter::new();
        table.add("/corp", "root", entry());

        let global = "/corp/eng/foo.txt";
        let route = table.route(global, "root").unwrap();
        let zone_path = if route.backend_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", route.backend_path)
        };
        let recovered = zone_to_global(&route.mount_point, &zone_path);
        assert_eq!(recovered, global);
    }

    /// Federation topology: two DISTINCT ``ZoneMetaStore`` Arcs (with
    /// different ``mount_point``s) can back the same zone's state
    /// machine — they share the same ``coherence_key``. The reverse
    /// lookup must return every surface with that key, and must NOT
    /// match a metastore with a different key (or ``None`` — single-node).
    #[test]
    fn mount_points_for_coherence_key_finds_direct_and_crosslinks() {
        /// Test stub — reports a caller-configured coherence key.
        /// Coherence keys are ``usize``, not ``Arc`` identity, so two
        /// distinct Arcs that report the same key represent two surfaces
        /// of the same underlying storage.
        struct KeyedStub {
            key: Option<usize>,
        }
        impl crate::meta_store::MetaStore for KeyedStub {
            fn get(
                &self,
                _: &str,
            ) -> Result<Option<crate::meta_store::FileMetadata>, crate::meta_store::MetaStoreError>
            {
                Ok(None)
            }
            fn put(
                &self,
                _: &str,
                _: crate::meta_store::FileMetadata,
            ) -> Result<(), crate::meta_store::MetaStoreError> {
                Ok(())
            }
            fn delete(&self, _: &str) -> Result<bool, crate::meta_store::MetaStoreError> {
                Ok(false)
            }
            fn list(
                &self,
                _: &str,
            ) -> Result<Vec<crate::meta_store::FileMetadata>, crate::meta_store::MetaStoreError>
            {
                Ok(Vec::new())
            }
            fn exists(&self, _: &str) -> Result<bool, crate::meta_store::MetaStoreError> {
                Ok(false)
            }
            fn coherence_key(&self) -> Option<usize> {
                self.key
            }
        }

        const CORP_KEY: usize = 0xC0;
        const FAMILY_KEY: usize = 0xFA;

        let corp_a: Arc<dyn MetaStore> = Arc::new(KeyedStub {
            key: Some(CORP_KEY),
        });
        let corp_b: Arc<dyn MetaStore> = Arc::new(KeyedStub {
            key: Some(CORP_KEY),
        }); // DISTINCT Arc, same coherence key — crosslink of the same zone.
        let family: Arc<dyn MetaStore> = Arc::new(KeyedStub {
            key: Some(FAMILY_KEY),
        });

        let table = VFSRouter::new();
        // Orthogonal-slot contract: add_mount fills backend-side, install_metastore
        // fills metastore. Order is irrelevant by construction.
        table.add_mount("/corp", "root", None, false);
        table.install_metastore(&canonicalize_mount_path("/corp", "root"), corp_a);
        table.add_mount("/family/work", "root", None, false);
        table.install_metastore(&canonicalize_mount_path("/family/work", "root"), corp_b);
        table.add_mount("/family", "root", None, false);
        table.install_metastore(&canonicalize_mount_path("/family", "root"), family);

        let mut corp_points = table.mount_points_for_coherence_key(CORP_KEY);
        corp_points.sort();
        assert_eq!(corp_points, vec!["/corp", "/family/work"]);

        let family_points = table.mount_points_for_coherence_key(FAMILY_KEY);
        assert_eq!(family_points, vec!["/family"]);

        // Unknown key → empty.
        assert!(table.mount_points_for_coherence_key(0xDEAD).is_empty());
    }

    // ── RouteResult federation behavior method pins ─────────────────────
    //
    // Two halves of the contract introduced by the FederationPeerClient
    // HAL collapse:
    //   * Non-federation routes (no `target_zone_id`, or with a local
    //     backend) — `via_federation_*` returns `None`, `supplement_*`
    //     is a no-op.  The coordinator MUST NOT be invoked.
    //   * Federation-peer-mount routes (no backend, target_zone_id set)
    //     — methods MUST delegate to the matching
    //     `DistributedCoordinator::peer_*` with the right (target_zone,
    //     path, ...) args.  Silent dispatch failure here would surface
    //     as the Mac↔Win Direction-A wedge.
    //
    // The fake coordinator records each call as a single canonical
    // string — the asserts read like the call site they protect.

    use crate::abc::meta_store::MetaStore;
    use crate::abc::object_store::{BackendStat, WriteResult};
    use crate::federation::FederationWriteOutcome;
    use crate::hal::distributed_coordinator::{
        ClusterInfo, CoordinatorResult, DistributedCoordinator, ShareInfo,
    };
    use contracts::lock_state::Locks;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct RecordingCoordinator {
        calls: Mutex<Vec<String>>,
    }

    impl RecordingCoordinator {
        fn record(&self, line: String) {
            self.calls.lock().push(line);
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().clone()
        }
    }

    impl DistributedCoordinator for RecordingCoordinator {
        // Non-peer-* trait methods are unused by these pins; supply
        // minimal Ok/empty stubs so the trait is satisfied.
        fn list_zones(&self, _kernel: &crate::kernel::Kernel) -> Vec<String> {
            Vec::new()
        }
        fn cluster_info(
            &self,
            _kernel: &crate::kernel::Kernel,
            _zone_id: &str,
        ) -> CoordinatorResult<ClusterInfo> {
            Err("not used by RouteResult pins".into())
        }
        fn create_zone(
            &self,
            _kernel: &crate::kernel::Kernel,
            _zone_id: &str,
        ) -> CoordinatorResult<()> {
            Err("not used by RouteResult pins".into())
        }
        fn remove_zone(
            &self,
            _kernel: &crate::kernel::Kernel,
            _zone_id: &str,
            _force: bool,
        ) -> CoordinatorResult<()> {
            Err("not used by RouteResult pins".into())
        }
        fn join_zone(
            &self,
            _kernel: &crate::kernel::Kernel,
            _zone_id: &str,
            _as_learner: bool,
        ) -> CoordinatorResult<()> {
            Err("not used by RouteResult pins".into())
        }
        fn wire_mount(
            &self,
            _kernel: &crate::kernel::Kernel,
            _parent_zone: &str,
            _mount_path: &str,
            _target_zone: &str,
        ) -> CoordinatorResult<()> {
            Err("not used by RouteResult pins".into())
        }
        fn unwire_mount(
            &self,
            _kernel: &crate::kernel::Kernel,
            _parent_zone: &str,
            _mount_path: &str,
        ) -> CoordinatorResult<()> {
            Err("not used by RouteResult pins".into())
        }
        fn share_zone(
            &self,
            _kernel: &crate::kernel::Kernel,
            _local_path: &str,
            _new_zone_id: &str,
        ) -> CoordinatorResult<ShareInfo> {
            Err("not used by RouteResult pins".into())
        }
        fn lookup_share(
            &self,
            _kernel: &crate::kernel::Kernel,
            _remote_path: &str,
        ) -> CoordinatorResult<Option<ShareInfo>> {
            Ok(None)
        }
        fn metastore_for_zone(
            &self,
            _kernel: &crate::kernel::Kernel,
            _zone_id: &str,
        ) -> CoordinatorResult<Arc<dyn MetaStore>> {
            Err("not used by RouteResult pins".into())
        }
        fn locks_for_zone(
            &self,
            _kernel: &crate::kernel::Kernel,
            _zone_id: &str,
        ) -> CoordinatorResult<Arc<dyn Locks>> {
            Err("not used by RouteResult pins".into())
        }

        // Peer-* overrides we DO observe — every call records the
        // (op, target_zone, key args) so the test asserts read like
        // the call site they protect.
        fn peer_stat(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            peer_path: &str,
        ) -> Option<BackendStat> {
            self.record(format!("peer_stat(target={target_zone}, path={peer_path})"));
            Some(BackendStat {
                size: 42,
                is_dir: false,
            })
        }
        fn peer_write(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            peer_path: &str,
            content: &[u8],
        ) -> Option<WriteResult> {
            self.record(format!(
                "peer_write(target={target_zone}, path={peer_path}, len={})",
                content.len()
            ));
            Some(WriteResult {
                content_id: peer_path.to_string(),
                version: peer_path.to_string(),
                size: content.len() as u64,
            })
        }
        fn peer_list_dir(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            peer_path: &str,
        ) -> Option<Vec<(String, u8)>> {
            self.record(format!(
                "peer_list_dir(target={target_zone}, path={peer_path})"
            ));
            // Empty Vec is meaningful (real empty dir) — pin that
            // the Some-vs-None split passes through unchanged.
            Some(Vec::new())
        }
        fn peer_delete_file(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            peer_path: &str,
        ) -> bool {
            self.record(format!(
                "peer_delete_file(target={target_zone}, path={peer_path})"
            ));
            true
        }
        fn peer_mkdir(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            peer_path: &str,
            parents: bool,
            exist_ok: bool,
        ) -> bool {
            self.record(format!(
                "peer_mkdir(target={target_zone}, path={peer_path}, parents={parents}, exist_ok={exist_ok})"
            ));
            true
        }
        fn peer_rename(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            old_path: &str,
            new_path: &str,
        ) -> bool {
            self.record(format!(
                "peer_rename(target={target_zone}, old={old_path}, new={new_path})"
            ));
            true
        }
        fn peer_setattr(
            &self,
            _kernel: &crate::kernel::Kernel,
            target_zone: &str,
            peer_path: &str,
            _mime_type: Option<&str>,
            _content_id: Option<&str>,
            _modified_at_ms: Option<i64>,
            _created_at_ms: Option<i64>,
            size: Option<u64>,
            _version: Option<u32>,
        ) -> bool {
            self.record(format!(
                "peer_setattr(target={target_zone}, path={peer_path}, size={:?})",
                size
            ));
            true
        }
    }

    fn install_recording_coordinator(kernel: &crate::kernel::Kernel) -> Arc<RecordingCoordinator> {
        let fake = Arc::new(RecordingCoordinator::default());
        kernel.set_distributed_coordinator(fake.clone() as Arc<dyn DistributedCoordinator>);
        fake
    }

    fn route_non_federation() -> RouteResult {
        // No backend + no target_zone_id — plain local mount that
        // never wired federation.  Both predicates fail.
        RouteResult {
            mount_point: "/root".to_string(),
            backend_path: "x".to_string(),
            zone_id: "root".to_string(),
            is_external: false,
            is_cas: false,
            metastore: None,
            backend: None,
            target_zone_id: None,
        }
    }

    fn route_federation_peer() -> RouteResult {
        // No backend + target_zone_id Some — placeholder MountEntry
        // shape installed by `wire_mount_core` on non-SSOT voters.
        RouteResult {
            mount_point: "/sharedzone".to_string(),
            backend_path: "x".to_string(),
            zone_id: "sharedzone".to_string(),
            is_external: false,
            is_cas: false,
            metastore: None,
            backend: None,
            target_zone_id: Some("sharedzone".to_string()),
        }
    }

    #[test]
    fn route_via_federation_stat_non_peer_returns_none_without_invoking_coordinator() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        assert!(route_non_federation()
            .via_federation_stat(&kernel, "/x")
            .is_none());
        assert!(
            fake.calls().is_empty(),
            "non-federation route must not reach the coordinator: got {:?}",
            fake.calls()
        );
    }

    #[test]
    fn route_via_federation_stat_peer_route_calls_coordinator_with_target_zone() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        let stat = route_federation_peer()
            .via_federation_stat(&kernel, "/x")
            .expect("peer dispatch should surface the coordinator hit");
        assert_eq!(stat.size, 42);
        assert_eq!(fake.calls(), vec!["peer_stat(target=sharedzone, path=/x)"]);
    }

    #[test]
    fn route_via_federation_write_non_peer_route_returns_not_peer() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        match route_non_federation().via_federation_write(&kernel, "/x", b"abc") {
            FederationWriteOutcome::NotPeer => {}
            other => panic!("expected NotPeer for local route, got {other:?}"),
        }
        assert!(
            fake.calls().is_empty(),
            "non-federation route must not invoke the coordinator: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn route_via_federation_write_peer_route_hit_carries_canonical_write_result() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        match route_federation_peer().via_federation_write(&kernel, "/x", b"abc") {
            FederationWriteOutcome::Hit(wr) => {
                assert_eq!(wr.size, 3);
                assert_eq!(wr.content_id, "/x");
            }
            other => panic!("expected Hit, got {other:?}"),
        }
        assert_eq!(
            fake.calls(),
            vec!["peer_write(target=sharedzone, path=/x, len=3)"]
        );
    }

    /// Federation route whose dispatch missed (coordinator's
    /// `peer_write` returns None — peer unreachable, observability
    /// warns fire on the coordinator side).  Pinning this separately
    /// from the Hit case guards the no-local-fallback rule that
    /// distinguishes federation-peer-mounts from regular mounts.
    #[test]
    fn route_via_federation_write_peer_route_dispatch_miss_surfaces_dispatch_missed() {
        // Use a fake coordinator whose peer_write returns None to
        // simulate every voter being unreachable.  The dispatch
        // helper would normally fall back through dispatch_to_peers
        // and surface None; this fake bypasses that to test the
        // RouteResult arm directly.
        struct MissCoordinator;
        impl DistributedCoordinator for MissCoordinator {
            fn list_zones(&self, _kernel: &crate::kernel::Kernel) -> Vec<String> {
                Vec::new()
            }
            fn cluster_info(
                &self,
                _kernel: &crate::kernel::Kernel,
                _zone_id: &str,
            ) -> CoordinatorResult<ClusterInfo> {
                Err("unused".into())
            }
            fn create_zone(
                &self,
                _kernel: &crate::kernel::Kernel,
                _zone_id: &str,
            ) -> CoordinatorResult<()> {
                Err("unused".into())
            }
            fn remove_zone(
                &self,
                _kernel: &crate::kernel::Kernel,
                _zone_id: &str,
                _force: bool,
            ) -> CoordinatorResult<()> {
                Err("unused".into())
            }
            fn join_zone(
                &self,
                _kernel: &crate::kernel::Kernel,
                _zone_id: &str,
                _as_learner: bool,
            ) -> CoordinatorResult<()> {
                Err("unused".into())
            }
            fn wire_mount(
                &self,
                _kernel: &crate::kernel::Kernel,
                _parent_zone: &str,
                _mount_path: &str,
                _target_zone: &str,
            ) -> CoordinatorResult<()> {
                Err("unused".into())
            }
            fn unwire_mount(
                &self,
                _kernel: &crate::kernel::Kernel,
                _parent_zone: &str,
                _mount_path: &str,
            ) -> CoordinatorResult<()> {
                Err("unused".into())
            }
            fn share_zone(
                &self,
                _kernel: &crate::kernel::Kernel,
                _local_path: &str,
                _new_zone_id: &str,
            ) -> CoordinatorResult<ShareInfo> {
                Err("unused".into())
            }
            fn lookup_share(
                &self,
                _kernel: &crate::kernel::Kernel,
                _remote_path: &str,
            ) -> CoordinatorResult<Option<ShareInfo>> {
                Ok(None)
            }
            fn metastore_for_zone(
                &self,
                _kernel: &crate::kernel::Kernel,
                _zone_id: &str,
            ) -> CoordinatorResult<Arc<dyn MetaStore>> {
                Err("unused".into())
            }
            fn locks_for_zone(
                &self,
                _kernel: &crate::kernel::Kernel,
                _zone_id: &str,
            ) -> CoordinatorResult<Arc<dyn Locks>> {
                Err("unused".into())
            }
            // The single override that matters: peer_write returns
            // None — the simulated all-voters-unreachable path.
            fn peer_write(
                &self,
                _kernel: &crate::kernel::Kernel,
                _target_zone: &str,
                _peer_path: &str,
                _content: &[u8],
            ) -> Option<WriteResult> {
                None
            }
        }
        let kernel = crate::kernel::Kernel::new();
        kernel.set_distributed_coordinator(
            Arc::new(MissCoordinator) as Arc<dyn DistributedCoordinator>
        );
        match route_federation_peer().via_federation_write(&kernel, "/x", b"abc") {
            FederationWriteOutcome::DispatchMissed => {}
            other => panic!("expected DispatchMissed when peer_write returns None, got {other:?}"),
        }
    }

    #[test]
    fn route_via_federation_readdir_passes_through_empty_vec_as_some() {
        // Empty Vec on peer side is "directory exists but is empty"
        // — distinguish from None ("not a federation route, fall
        // through to local readdir") via the Some/None split.
        let kernel = crate::kernel::Kernel::new();
        let _fake = install_recording_coordinator(&kernel);
        let entries = route_federation_peer()
            .via_federation_readdir(&kernel, "/d")
            .expect("peer dispatch returns Some even for empty dirs");
        assert!(entries.is_empty());
    }

    #[test]
    fn route_via_federation_unlink_wraps_dispatch_bool_in_some() {
        let kernel = crate::kernel::Kernel::new();
        let _fake = install_recording_coordinator(&kernel);
        let result = route_federation_peer().via_federation_unlink(&kernel, "/x");
        assert_eq!(result, Some(true));
    }

    #[test]
    fn route_supplement_mkdir_non_peer_route_is_noop() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        route_non_federation().supplement_mkdir(&kernel, "/d", true, false);
        assert!(
            fake.calls().is_empty(),
            "non-federation supplement_mkdir must not invoke coordinator"
        );
    }

    #[test]
    fn route_supplement_mkdir_peer_route_threads_args_to_coordinator() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        route_federation_peer().supplement_mkdir(&kernel, "/d", true, false);
        assert_eq!(
            fake.calls(),
            vec!["peer_mkdir(target=sharedzone, path=/d, parents=true, exist_ok=false)"]
        );
    }

    #[test]
    fn route_supplement_rename_peer_route_threads_old_and_new_paths() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        route_federation_peer().supplement_rename(&kernel, "/a", "/b");
        assert_eq!(
            fake.calls(),
            vec!["peer_rename(target=sharedzone, old=/a, new=/b)"]
        );
    }

    #[test]
    fn route_supplement_setattr_peer_route_threads_size_arg() {
        let kernel = crate::kernel::Kernel::new();
        let fake = install_recording_coordinator(&kernel);
        route_federation_peer().supplement_setattr(
            &kernel,
            "/f",
            None,
            None,
            None,
            None,
            Some(99),
            None,
        );
        assert_eq!(
            fake.calls(),
            vec!["peer_setattr(target=sharedzone, path=/f, size=Some(99))"]
        );
    }
}
