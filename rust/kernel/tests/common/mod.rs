//! Shared harness for the kernel's integration tests.
//!
//! `MemBackend` had drifted into three identical copies across this directory —
//! every test that needs the kernel to accept bytes needs the same forty lines,
//! and a fourth copy is a fourth place for "what does a backend have to do"
//! to be answered differently. One definition, so a change to the
//! [`ObjectStore`] surface breaks the harness once instead of three times.
//!
//! `dead_code` is allowed because Cargo compiles this module into EVERY test
//! binary that declares it, and each one uses a subset — an unused helper here is
//! the module doing its job, not a leftover.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::kernel::{Kernel, OperationContext};

/// In-memory [`ObjectStore`]: enough for write + read round-trips, and nothing
/// else. Content does NOT survive being dropped, which is deliberate — the tests
/// here assert on NAMESPACE metadata, which the metastore owns.
#[derive(Default)]
pub struct MemBackend {
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

/// Mount a fresh [`MemBackend`] at `/`.
///
/// Separate from any kernel construction: a test that wires a durable metastore
/// must do so BEFORE the first mount, so the `DT_MOUNT` row lands in the durable
/// store rather than the boot tempfile. Keeping the mount its own call leaves that
/// ordering visible in the test instead of buried in a helper.
pub fn mount_mem_root(k: &Kernel) {
    let backend = Arc::new(MemBackend::default());
    k.sys_setattr(
        "/",
        &admin_ctx(),
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
        None, // remote_metastore
    )
    .expect("mount / with MemBackend");
}

/// Admin + system-bypass context. Every test here is about namespace mechanics,
/// not authorization.
#[must_use]
pub fn admin_ctx() -> OperationContext {
    OperationContext::new("test", "root", true, None, true)
}
