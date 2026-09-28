//! Regression test for nexi-lab/nexus-vfs#345 — a metastore that cannot be read must
//! not be reported as an empty directory.
//!
//! `scan_mount_into` took the listing with `.ok()`, so a `MetaStoreError` became
//! `None` and the block was skipped: the caller got an empty `Vec` and there was no
//! trace of the failure anywhere. Discovery is built on this call — agent
//! enumeration, the conversation index a receiver tails — and those callers act on
//! emptiness: a broadcast over "no recipients" reports success having delivered
//! nothing. An unreadable store and an empty namespace call for opposite actions and
//! produced identical output.
//!
//! What this test pins is the MERGE semantics, which is the part a reader is most
//! likely to get wrong when touching it: one mount failing does not invalidate the
//! others. The listing continues with what the remaining mounts hold, rather than
//! collapsing to nothing — and the failure is a WARN naming the prefix, because
//! `sys_readdir` returns a `Vec` and widening that to a `Result` would reach the
//! plugin ABI (a C dispatch seam) to carry an error nearly no caller can act on. The
//! remote half of the distinction belongs in `ReaddirResponse`, not in the syscall.

mod common;

use std::sync::{Arc, Mutex};

use kernel::abc::meta_store::{FileMetadata, MetaStore, MetaStoreError};
use kernel::kernel::syscall::{KernelSyscall, ReaddirOpts};
use kernel::kernel::Kernel;

/// A metastore whose `list` always fails. Everything else answers "nothing here",
/// which is what a store with an unreadable index looks like from outside.
#[derive(Default)]
struct UnreadableStore;

impl MetaStore for UnreadableStore {
    fn get(&self, _path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
        Ok(None)
    }

    fn put(&self, _path: &str, _metadata: FileMetadata) -> Result<(), MetaStoreError> {
        Ok(())
    }

    fn delete(&self, _path: &str) -> Result<bool, MetaStoreError> {
        Ok(false)
    }

    fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        Err(MetaStoreError::IOError(format!(
            "index unreadable while listing {prefix}"
        )))
    }

    fn exists(&self, _path: &str) -> Result<bool, MetaStoreError> {
        Ok(false)
    }
}

/// A writer that keeps what was logged, so the test can assert the WARN fired.
///
/// The fix for #345 is observable ONLY as a log line — the syscall's return type is
/// unchanged on purpose — so a test that skips this asserts nothing about it: delete
/// the `warn!` and the emptiness assertions below still pass.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn names(k: &Kernel, dir: &str) -> Vec<String> {
    KernelSyscall::sys_readdir(k, dir, kernel::ROOT_ZONE_ID, true, ReaddirOpts::default())
        .into_iter()
        .map(|(path, _)| path.rsplit('/').next().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn one_unreadable_mount_does_not_empty_the_rest_of_the_listing() {
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::WARN)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let k = Kernel::new();
    common::mount_mem_root(&k);
    let ctx = common::admin_ctx();

    KernelSyscall::sys_write(&k, "/kept.txt", &ctx, b"still here", 0).expect("write under root");

    // A subtree whose own store cannot be listed.
    k.sys_setattr(
        "/broken",
        2, // DT_MOUNT
        "mem",
        Some(Arc::new(common::MemBackend::default())
            as Arc<dyn kernel::abc::object_store::ObjectStore>),
        Some(Arc::new(UnreadableStore) as Arc<dyn MetaStore>),
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
        None,
        None,
        None,
        None,
    )
    .expect("mount /broken with an unreadable store");

    // The root listing still answers for the mounts that CAN be read. A fix that
    // propagated the error instead would have deleted `kept.txt` from this answer,
    // which is why the error is reported rather than returned.
    let root = names(&k, "/");
    assert!(
        root.iter().any(|n| n == "kept.txt"),
        "a sibling mount's failure must not remove readable entries; got {root:?}"
    );

    // And the unreadable subtree itself lists nothing — the case the WARN exists for,
    // since this answer is indistinguishable from an empty directory at the syscall.
    assert!(
        names(&k, "/broken").is_empty(),
        "an unreadable store has nothing to report"
    );

    // The fix itself: the failure is REPORTED. Without this the test would pass on a
    // build with the `warn!` deleted, which is the state #345 describes.
    let logged = String::from_utf8_lossy(&logs.0.lock().expect("log buffer")).to_string();
    assert!(
        logged.contains("metastore listing failed"),
        "the failed store read must be reported, not swallowed; logs were:
{logged}"
    );
    assert!(
        logged.contains("/broken"),
        "the report must name the prefix that failed; logs were:
{logged}"
    );
}
