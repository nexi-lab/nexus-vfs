//! Compose unresolved Managed metadata with the actual CAS backend and Kernel.

use kernel::kernel::syscall::KernelSyscall;
use kernel::meta_store::{ConditionalMetadataError, FileMetadata, MetaStore};
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneManager;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

#[path = "../common/ports.rs"]
mod ports;

struct Runtime(Arc<ZoneManager>);

impl Drop for Runtime {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

#[test]
fn unresolved_managed_store_keeps_first_ordinary_reads_open_and_owned_operations_closed() {
    use backends::storage::cas_local::CasLocalBackend;
    use kernel::abc::object_store::ObjectStore;
    use kernel::core::stream::wal::WalStreamCore;
    use kernel::kernel::convenience::{KernelConvenience, MountOptions};
    use kernel::kernel::{Kernel, OperationContext};
    use kernel::meta_store::DT_REG;

    let dir = TempDir::new().unwrap();
    let bind = format!("127.0.0.1:{}", ports::free_port());
    let runtime = Runtime(
        ZoneManager::with_node_id(
            "ordinary-managed-fixture",
            1,
            dir.path().to_str().unwrap(),
            vec![],
            &bind,
            None,
            Some(format!("http://{bind}")),
            None,
        )
        .unwrap(),
    );
    let root = runtime.0.create_zone("root", vec![]).unwrap();
    assert!(root.wait_for_leader(Duration::from_secs(10)));
    let ready = Arc::new(ZoneMetaStore::new(
        root.consensus_node().clone(),
        runtime.0.runtime_handle(),
        "/".into(),
    ));
    let ctx = OperationContext::new("ordinary-reader", "root", true, None, true);
    let backend = Arc::new(CasLocalBackend::new(&dir.path().join("cas"), true).unwrap());
    let bytes = b"first read must not depend on provider discovery";
    let written = backend.write_content(bytes, "/ordinary", &ctx, 0).unwrap();
    ready
        .put(
            "/ordinary",
            FileMetadata {
                path: "/ordinary".into(),
                entry_type: DT_REG,
                content_id: Some(written.content_id),
                size: bytes.len() as u64,
                zone_id: Some("root".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let ordinary = WalStreamCore::new(ready.clone(), "/ordinary-wal".into());
    ordinary.write_sync(b"ordinary managed WAL").unwrap();

    let deferred = || {
        ZoneMetaStore::deferred_arc(
            runtime.0.registry(),
            "root",
            runtime.0.runtime_handle(),
            "/".into(),
            "/".into(),
        )
    };
    let store = deferred();
    assert!(store.as_guarded_records().is_some());
    let kernel = Kernel::new();
    kernel
        .mount(
            "/",
            MountOptions::new(&ctx, "local")
                .with_backend(backend)
                .with_metastore(store.clone()),
        )
        .unwrap();
    assert!(
        store.as_guarded_records().is_some(),
        "root mount must leave the actual Deferred provider unresolved"
    );
    // A top-level path has no ancestor lookup that could resolve the provider
    // before the first ordinary admission check.
    assert_eq!(
        KernelSyscall::sys_read(&kernel, "/ordinary", &ctx, 0, 0)
            .unwrap()
            .data,
        Some(bytes.to_vec())
    );
    assert!(store.as_guarded_records().is_none());

    let retained = deferred();
    assert!(retained.as_guarded_records().is_some());
    let wal = WalStreamCore::new(retained.clone(), "/ordinary-wal".into());
    assert_eq!(
        wal.read_at(0).unwrap(),
        Some(b"ordinary managed WAL".to_vec())
    );
    assert!(retained.as_guarded_records().is_none());
    assert!(matches!(
        kernel::meta_store::ConditionalMetadata::read_versioned(ready.as_ref(), "/ordinary"),
        Err(ConditionalMetadataError::Unsupported)
    ));
    // The resolution error is not equivalent to discovering Managed membership.
    let missing = ZoneMetaStore::deferred_arc(
        runtime.0.registry(),
        "missing-zone",
        runtime.0.runtime_handle(),
        "/".into(),
        "/".into(),
    );
    assert!(missing
        .as_guarded_records()
        .unwrap()
        .check_unscoped_io("/ordinary")
        .is_err());
}
