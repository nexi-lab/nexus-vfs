//! Regression tests for nexi-lab/nexus#4343 — the VFS namespace must
//! survive a kernel restart when a durable metastore path is wired.
//!
//! `Kernel::new()` boots on a tempfile-backed `LocalMetaStore` that drops
//! with the kernel. Production profiles must call `set_metastore_path`
//! with a path inside the data dir; before that wiring existed, every
//! `nexusd-cluster` restart silently wiped the entire namespace while
//! payload bytes stayed on disk.
//!
//! Two tests:
//!   1. With `set_metastore_path` → a registered file is still visible
//!      after dropping the kernel and booting a fresh one on the same
//!      redb file (the fix).
//!   2. Without it → the registration is gone after a "restart"
//!      (documents the ephemeral-boot-store footgun the cluster profile
//!      must avoid).
//!
//! All tests exercise the public Kernel API only.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};

// ── Minimal in-memory backend (mirrors service_hook_lifecycle.rs) ────
//
// Content does NOT survive the simulated restart — that is fine: these
// tests assert on namespace *metadata* (sys_stat), which is exactly what
// the metastore owns.

#[derive(Default)]
struct MemBackend {
    blobs: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

impl ObjectStore for MemBackend {
    fn name(&self) -> &str {
        "mem"
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        _ctx: &OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        let mut map = self.blobs.lock().unwrap();
        let entry = map.entry(content_id.to_string()).or_default();
        let start = offset as usize;
        if start > entry.len() {
            entry.resize(start, 0);
        }
        let end = start + content.len();
        if end > entry.len() {
            entry.resize(end, 0);
        }
        entry[start..end].copy_from_slice(content);
        let size = entry.len() as u64;
        Ok(WriteResult {
            content_id: content_id.to_string(),
            version: content_id.to_string(),
            size,
        })
    }

    fn read_content(
        &self,
        content_id: &str,
        _ctx: &OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        self.blobs
            .lock()
            .unwrap()
            .get(content_id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(content_id.into()))
    }

    fn get_content_size(&self, content_id: &str) -> Result<u64, StorageError> {
        self.blobs
            .lock()
            .unwrap()
            .get(content_id)
            .map(|d| d.len() as u64)
            .ok_or_else(|| StorageError::NotFound(content_id.into()))
    }
}

/// Boot a kernel, optionally wiring a durable metastore, and mount the
/// in-memory backend at "/".
///
/// Order matters and mirrors the cluster profile: the durable metastore
/// is wired BEFORE the first mount so the DT_MOUNT entry lands in the
/// durable store, not the boot tempfile.
fn boot(metastore: Option<&Path>) -> (Kernel, OperationContext) {
    let k = Kernel::new();
    if let Some(ms) = metastore {
        k.set_metastore_path(ms.to_str().expect("utf-8 metastore path"))
            .expect("open durable metastore");
    }
    let backend = Arc::new(MemBackend::default());
    k.sys_setattr(
        "/",
        2, // DT_MOUNT
        "mem",
        Some(backend as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("mount / with MemBackend");

    let ctx = OperationContext::new("test", "root", true, None, true);
    (k, ctx)
}

#[test]
fn namespace_survives_kernel_restart_with_durable_metastore() {
    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");

    {
        let (k, ctx) = boot(Some(&ms));
        KernelSyscall::sys_write(&k, "/docs/report.md", &ctx, b"v1 bytes", 0).expect("write");
        assert!(
            KernelSyscall::sys_stat(&k, "/docs/report.md", kernel::ROOT_ZONE_ID).is_some(),
            "file must be visible immediately after write"
        );
        // Release the redb handle the way a clean shutdown does (#3765),
        // so the second boot can open the same file.
        k.release_metastores();
    }

    let (k2, _ctx) = boot(Some(&ms));
    assert!(
        KernelSyscall::sys_stat(&k2, "/docs/report.md", kernel::ROOT_ZONE_ID).is_some(),
        "a registered file must survive a kernel restart when the \
         metastore is durable (nexi-lab/nexus#4343)"
    );
}

#[test]
fn non_root_mount_entry_row_survives_kernel_restart() {
    // A non-root DT_MOUNT goes through DLC::mount, which persists the
    // entry into the (parent-routed) metastore — and since #4343 fails
    // closed when that persist fails or no store is available.
    //
    // Scope honesty: this proves the durable *metadata row* survives a
    // kernel restart (visible via sys_stat with only the root mount
    // re-established). Replaying the row back into the VFSRouter as a
    // live route is the daemon/raft layer's job
    // (`replay_existing_mounts`, see nexus-vfs#41) and is covered by
    // the raft-side tests — a bare kernel does not replay routes.
    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");

    {
        let (k, _ctx) = boot(Some(&ms));
        let sub_backend = Arc::new(MemBackend::default());
        k.sys_setattr(
            "/sub",
            2, // DT_MOUNT
            "mem-sub",
            Some(sub_backend as Arc<dyn ObjectStore>),
            None,
            None,
            "",
            kernel::ROOT_ZONE_ID,
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None, // created_at_ms
            None, // link_target
            None, // source
            None, // metastore
        )
        .expect("mount /sub");
        assert!(
            KernelSyscall::sys_stat(&k, "/sub", kernel::ROOT_ZONE_ID).is_some(),
            "mount entry visible after mounting"
        );
        k.release_metastores();
    }

    // Second boot: only "/" is re-mounted (what the daemon does at boot).
    let (k2, _ctx) = boot(Some(&ms));
    let stat = KernelSyscall::sys_stat(&k2, "/sub", kernel::ROOT_ZONE_ID)
        .expect("non-root DT_MOUNT row must survive a kernel restart (nexi-lab/nexus#4343)");
    assert_eq!(
        stat.entry_type,
        2, // DT_MOUNT
        "the surviving row must still be a DT_MOUNT entry, not a plain file"
    );
}

#[test]
fn remount_persists_dt_mount_row_into_parent_store_not_child() {
    // Regression (#4343 review round 3): DLC::mount used to route
    // `mount_point` itself when picking the store for the DT_MOUNT row.
    // On a REMOUNT of an existing mount that carries a per-mount
    // metastore, that exact-match routes to the child — the row lands
    // in the child's own store and the parent's copy goes stale. The
    // fix walks up to the parent path first (symmetric with unmount).
    //
    // Discriminator: remount /sub (same zone — canonical routing keys
    // embed the zone, so only a same-zone remount hits the exact-match
    // trap), then open both stores directly. The child's per-mount
    // store must stay CLEAN; the old code wrote the remount row there.
    use kernel::meta_store::{LocalMetaStore, MetaStore};

    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");
    let sub_ms_path = td.path().join("sub-mount.redb");

    {
        let (k, _ctx) = boot(Some(&ms));
        let mount_sub = |per_mount: Arc<dyn MetaStore>| {
            k.sys_setattr(
                "/sub",
                2, // DT_MOUNT
                "mem-sub",
                Some(Arc::new(MemBackend::default()) as Arc<dyn ObjectStore>),
                Some(per_mount),
                None,
                "",
                kernel::ROOT_ZONE_ID,
                false,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None, // created_at_ms
                None, // link_target
                None, // source
                None, // metastore
            )
        };
        let sub_store: Arc<dyn MetaStore> =
            Arc::new(LocalMetaStore::open(&sub_ms_path).expect("open per-mount store"));
        mount_sub(Arc::clone(&sub_store)).expect("first mount /sub");
        // Same-zone remount: route(mount_point) now exact-matches /sub
        // itself — the row must STILL go to the parent store.
        mount_sub(sub_store).expect("remount /sub");
        k.release_metastores();
    }

    let parent = LocalMetaStore::open(&ms).expect("reopen parent store");
    let row = parent
        .get("/sub")
        .expect("read parent store")
        .expect("DT_MOUNT row for /sub must live in the PARENT store");
    assert_eq!(row.entry_type, 2, "row must be a DT_MOUNT entry");

    let child = LocalMetaStore::open(&sub_ms_path).expect("reopen child store");
    assert!(
        child.get("/sub").expect("read child store").is_none(),
        "the DT_MOUNT row for /sub must NOT leak into /sub's own \
         per-mount store on remount (old exact-match routing wrote it there)"
    );
}

#[test]
fn cross_zone_mount_without_replicated_parent_store_uses_durable_global_fallback() {
    // #4343 review rounds 4-5: a cross-zone DT_MOUNT row should land in
    // the parent zone's REPLICATED store, but the documented
    // `--mount-driver` boot shape mounts "/" backend-only before zone
    // wiring — hard-failing would break those boots. The contract for
    // now: the mount SUCCEEDS, the row lands in the node-local durable
    // global store (local-only durability, warned at runtime), and the
    // proper root-store wiring is tracked with nexus-vfs#44.
    use kernel::meta_store::{LocalMetaStore, MetaStore};

    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");

    {
        let (k, _ctx) = boot(Some(&ms)); // "/" mounted with NO per-mount store
        let backend = Arc::new(MemBackend::default());
        k.sys_setattr(
            "/corp",
            2, // DT_MOUNT
            "mem-corp",
            Some(backend as Arc<dyn ObjectStore>),
            None,
            None,
            "",
            "zone-corp", // != parent zone ("root")
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None, // created_at_ms
            None, // link_target
            None, // source
            None, // metastore
        )
        .expect("cross-zone mount with bare parent must still succeed (warn-only)");
        k.release_metastores();
    }

    let global = LocalMetaStore::open(&ms).expect("reopen global store");
    let row = global
        .get("/corp")
        .expect("read global store")
        .expect("cross-zone DT_MOUNT row must be durable in the global fallback store");
    assert_eq!(row.entry_type, 2);
    assert_eq!(row.target_zone_id.as_deref(), Some("zone-corp"));
}

#[test]
fn cross_zone_unmount_removes_durable_row_and_live_route() {
    // #4343 review round 6: the live route is installed under the
    // mount's TARGET zone while the durable row lives in the parent
    // zone's store. sys_unlink must remove BOTH — removing the row but
    // leaving the target-zone route accessible (or vice versa) is the
    // half-unmounted state the fail-closed work exists to prevent.
    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");

    let (k, ctx) = boot(Some(&ms));
    k.sys_setattr(
        "/corp",
        2, // DT_MOUNT
        "mem-corp",
        Some(Arc::new(MemBackend::default()) as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        "zone-corp",
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("cross-zone mount /corp");
    assert!(
        k.has_mount("/corp", "zone-corp"),
        "live route present in the target zone after mounting"
    );

    let unlink =
        KernelSyscall::sys_unlink(&k, "/corp", &ctx, false).expect("cross-zone unmount succeeds");
    assert!(unlink.hit, "unlink reports the mount as removed");
    assert!(
        !k.has_mount("/corp", "zone-corp"),
        "live route must be gone from the TARGET zone after unmount"
    );
    assert!(
        !k.has_mount("/corp", kernel::ROOT_ZONE_ID),
        "no stray route under the parent zone either"
    );
    assert!(
        KernelSyscall::sys_stat(&k, "/corp", kernel::ROOT_ZONE_ID).is_none(),
        "durable DT_MOUNT row must be gone after unmount"
    );
}

#[test]
fn orphan_mount_row_unlinks_after_restart_without_live_route() {
    // #4343 review round 8 counter-case: after a restart the durable
    // DT_MOUNT rows exist but no routes are replayed (bare kernel).
    // Unlinking such an orphan row must SUCCEED row-only — refusing
    // because no live route can be removed would make post-restart
    // cleanup impossible.
    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");

    {
        let (k, _ctx) = boot(Some(&ms));
        k.sys_setattr(
            "/corp",
            2, // DT_MOUNT
            "mem-corp",
            Some(Arc::new(MemBackend::default()) as Arc<dyn ObjectStore>),
            None,
            None,
            "",
            "zone-corp",
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None, // created_at_ms
            None, // link_target
            None, // source
            None, // metastore
        )
        .expect("cross-zone mount /corp");
        k.release_metastores();
    }

    // Restart: only "/" re-mounted, /corp row durable but route absent.
    let (k2, ctx) = boot(Some(&ms));
    assert!(
        !k2.has_mount("/corp", "zone-corp"),
        "precondition: no live route after restart (bare kernel does not replay)"
    );
    assert!(
        KernelSyscall::sys_stat(&k2, "/corp", kernel::ROOT_ZONE_ID).is_some(),
        "precondition: durable row survived the restart"
    );

    let unlink = KernelSyscall::sys_unlink(&k2, "/corp", &ctx, false)
        .expect("unlinking an orphan mount row must succeed");
    assert!(unlink.hit, "row-only unlink still counts as a removal");
    assert!(
        KernelSyscall::sys_stat(&k2, "/corp", kernel::ROOT_ZONE_ID).is_none(),
        "durable row must be gone after the orphan unlink"
    );
}

#[test]
fn unmount_keeps_route_when_durable_row_delete_fails() {
    // #4343 review round 5: with the metastore durable by default, a
    // failed DT_MOUNT row delete must NOT let the unmount look
    // successful — the stale row would resurrect the mount on the next
    // restart/replay. DLC::unmount fails closed and keeps the route.
    use kernel::meta_store::{FileMetadata, LocalMetaStore, MetaStore, MetaStoreError};

    /// Delegates everything to an inner LocalMetaStore; `delete` always
    /// fails — simulates a redb/raft write error during unmount.
    struct FailingDeleteStore(LocalMetaStore);
    impl MetaStore for FailingDeleteStore {
        fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
            self.0.get(path)
        }
        fn put(&self, path: &str, metadata: FileMetadata) -> Result<(), MetaStoreError> {
            self.0.put(path, metadata)
        }
        fn delete(&self, _path: &str) -> Result<bool, MetaStoreError> {
            Err(MetaStoreError::IOError("injected delete failure".into()))
        }
        fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
            self.0.list(prefix)
        }
        fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
            self.0.exists(path)
        }
    }

    let td = tempfile::tempdir().expect("tempdir");
    let root_store: Arc<dyn MetaStore> = Arc::new(FailingDeleteStore(
        LocalMetaStore::open(&td.path().join("root.redb")).expect("open root store"),
    ));

    let k = Kernel::new();
    let mount = |path: &str, zone: &str, per_mount: Option<Arc<dyn MetaStore>>| {
        k.sys_setattr(
            path,
            2, // DT_MOUNT
            "mem",
            Some(Arc::new(MemBackend::default()) as Arc<dyn ObjectStore>),
            per_mount,
            None,
            "",
            zone,
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None, // created_at_ms
            None, // link_target
            None, // source
            None, // metastore
        )
    };
    mount("/", kernel::ROOT_ZONE_ID, Some(Arc::clone(&root_store)))
        .expect("mount / with failing-delete store");
    mount("/sub", "zone-corp", None).expect("mount /sub (cross-zone)");

    let ctx = OperationContext::new("test", "root", true, None, true);
    let unlink = KernelSyscall::sys_unlink(&k, "/sub", &ctx, false);
    assert!(
        unlink.is_err(),
        "sys_unlink of a mount must fail when the durable DT_MOUNT row \
         cannot be deleted"
    );
    assert!(
        KernelSyscall::sys_stat(&k, "/sub", kernel::ROOT_ZONE_ID).is_some(),
        "the mount must still be present after the failed unmount \
         (fail closed — no silent route removal with a stale durable row)"
    );
    assert!(
        k.has_mount("/sub", "zone-corp"),
        "the LIVE route must remain installed after the failed unmount — \
         the row alone passing sys_stat would not prove route retention"
    );

    // Batch mode must surface the same error per item — it used to map
    // every Err into a silent hit=false miss (#4343 review round 9),
    // hiding the fail-closed signal from batch callers.
    let batch = k.sys_unlink(
        &[kernel::kernel::UnlinkRequest {
            path: "/sub".to_string(),
            recursive: false,
        }],
        &ctx,
    );
    // Force the multi-item code path too (single-item fast path already
    // propagates): a second, nonexistent path must be a plain miss.
    let batch_multi = k.sys_unlink(
        &[
            kernel::kernel::UnlinkRequest {
                path: "/sub".to_string(),
                recursive: false,
            },
            kernel::kernel::UnlinkRequest {
                path: "/no-such-file.txt".to_string(),
                recursive: false,
            },
        ],
        &ctx,
    );
    assert!(
        batch[0].is_err(),
        "single-item batch unlink must surface the fail-closed unmount error"
    );
    assert!(
        batch_multi[0].is_err(),
        "multi-item batch unlink must surface the fail-closed unmount error \
         instead of mapping it to a hit=false miss"
    );
    assert!(
        matches!(&batch_multi[1], Ok(r) if !r.hit),
        "a genuinely missing path stays an Ok(hit=false) miss in batch mode"
    );
    assert!(
        KernelSyscall::sys_stat(&k, "/sub", kernel::ROOT_ZONE_ID).is_some(),
        "the mount must still be present after failed batch unmounts"
    );
    assert!(
        k.has_mount("/sub", "zone-corp"),
        "the LIVE route must remain installed after failed batch unmounts"
    );
}

#[test]
fn cross_zone_mount_persists_row_into_parent_per_mount_store() {
    // Companion to the fail-closed test: when the parent DOES carry a
    // per-mount store (ZoneMetaStore in production; LocalMetaStore here),
    // the cross-zone DT_MOUNT row must land in THAT store.
    use kernel::meta_store::{LocalMetaStore, MetaStore};

    let td = tempfile::tempdir().expect("tempdir");
    let root_ms_path = td.path().join("root-mount.redb");

    let k = Kernel::new();
    let root_store: Arc<dyn MetaStore> =
        Arc::new(LocalMetaStore::open(&root_ms_path).expect("open root per-mount store"));
    k.sys_setattr(
        "/",
        2, // DT_MOUNT
        "mem",
        Some(Arc::new(MemBackend::default()) as Arc<dyn ObjectStore>),
        Some(root_store),
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("mount / with per-mount store");

    k.sys_setattr(
        "/corp",
        2, // DT_MOUNT
        "mem-corp",
        Some(Arc::new(MemBackend::default()) as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        "zone-corp",
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("cross-zone mount with replicated parent store");

    k.release_metastores();
    drop(k);

    let root_store = LocalMetaStore::open(&root_ms_path).expect("reopen root store");
    let row = root_store
        .get("/corp")
        .expect("read root store")
        .expect("cross-zone DT_MOUNT row must land in the parent's per-mount store");
    assert_eq!(row.entry_type, 2);
    assert_eq!(row.target_zone_id.as_deref(), Some("zone-corp"));
}

#[test]
fn non_root_mount_without_parent_route_fails_closed() {
    // #4343 follow-up: with EXISTING topology, a non-root mount whose
    // parent cannot be routed has nowhere to persist its DT_MOUNT
    // entry. Installing it anyway would create a route that silently
    // vanishes on restart — DLC::mount must reject it. (An EMPTY
    // router is the bootstrap exception — covered by the test below.)
    let td = tempfile::tempdir().expect("tempdir");
    let ms = td.path().join("metastore.redb");

    let k = Kernel::new();
    k.set_metastore_path(ms.to_str().expect("utf-8 metastore path"))
        .expect("open durable metastore");
    // Existing topology WITHOUT a root mount: /vault is routable,
    // /orphan has no enclosing route.
    let vault_backend = Arc::new(MemBackend::default());
    k.sys_setattr(
        "/vault",
        2, // DT_MOUNT
        "mem-vault",
        Some(vault_backend as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("first-mount bootstrap of /vault on an empty router must be allowed");
    let backend = Arc::new(MemBackend::default());
    let mounted = k.sys_setattr(
        "/orphan",
        2, // DT_MOUNT
        "mem",
        Some(backend as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    );
    assert!(
        mounted.is_err(),
        "mounting a non-root path with no parent route (and existing \
         topology) must fail closed instead of installing an \
         unpersistable mount"
    );
}

#[test]
fn first_mount_bootstrap_of_non_root_subtree_is_allowed() {
    // Downstream services bootstrap their subtree as the very first
    // mount on a bare kernel (nexus password vault mounts /vault with
    // no root mount). An empty router has no parent zone to persist
    // into — exactly like the root bootstrap — so this must succeed.
    let k = Kernel::new();
    let backend = Arc::new(MemBackend::default());
    k.sys_setattr(
        "/vault",
        2, // DT_MOUNT
        "mem-vault",
        Some(backend as Arc<dyn ObjectStore>),
        None,
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None, // created_at_ms
        None, // link_target
        None, // source
        None, // metastore
    )
    .expect("first-mount bootstrap on an empty router must be allowed");
    assert!(k.has_mount("/vault", kernel::ROOT_ZONE_ID));
}

#[test]
fn namespace_is_lost_across_restart_without_durable_metastore() {
    // The footgun this crate's boot default creates: no set_metastore_path
    // → registrations live in the kernel's boot tempdir and die with it.
    {
        let (k, ctx) = boot(None);
        KernelSyscall::sys_write(&k, "/docs/report.md", &ctx, b"v1 bytes", 0).expect("write");
        assert!(KernelSyscall::sys_stat(&k, "/docs/report.md", kernel::ROOT_ZONE_ID).is_some());
    }

    let (k2, _ctx) = boot(None);
    assert!(
        KernelSyscall::sys_stat(&k2, "/docs/report.md", kernel::ROOT_ZONE_ID).is_none(),
        "without a durable metastore the namespace does not survive — \
         production profiles must wire set_metastore_path"
    );
}
