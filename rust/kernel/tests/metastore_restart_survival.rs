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
use kernel::abi::KernelAbi;
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
        KernelAbi::sys_write(&k, "/docs/report.md", &ctx, b"v1 bytes", 0).expect("write");
        assert!(
            KernelAbi::sys_stat(&k, "/docs/report.md", kernel::ROOT_ZONE_ID).is_some(),
            "file must be visible immediately after write"
        );
        // Release the redb handle the way a clean shutdown does (#3765),
        // so the second boot can open the same file.
        k.release_metastores();
    }

    let (k2, _ctx) = boot(Some(&ms));
    assert!(
        KernelAbi::sys_stat(&k2, "/docs/report.md", kernel::ROOT_ZONE_ID).is_some(),
        "a registered file must survive a kernel restart when the \
         metastore is durable (nexi-lab/nexus#4343)"
    );
}

#[test]
fn namespace_is_lost_across_restart_without_durable_metastore() {
    // The footgun this crate's boot default creates: no set_metastore_path
    // → registrations live in the kernel's boot tempdir and die with it.
    {
        let (k, ctx) = boot(None);
        KernelAbi::sys_write(&k, "/docs/report.md", &ctx, b"v1 bytes", 0).expect("write");
        assert!(KernelAbi::sys_stat(&k, "/docs/report.md", kernel::ROOT_ZONE_ID).is_some());
    }

    let (k2, _ctx) = boot(None);
    assert!(
        KernelAbi::sys_stat(&k2, "/docs/report.md", kernel::ROOT_ZONE_ID).is_none(),
        "without a durable metastore the namespace does not survive — \
         production profiles must wire set_metastore_path"
    );
}
