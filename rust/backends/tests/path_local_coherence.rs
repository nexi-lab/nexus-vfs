#![cfg(all(unix, feature = "driver-path-local"))]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use backends::storage::path_local::PathLocalBackend;
use kernel::abc::meta_store::{DT_DIR, DT_LINK, DT_REG, DT_STREAM};
use kernel::abc::object_store::ObjectStore;
use kernel::kernel::convenience::KernelConvenience;
use kernel::kernel::{Kernel, KernelError, OperationContext, ReadRequest, WriteRequest};

fn setup(root: &Path) -> (Kernel, OperationContext) {
    setup_backend(Arc::new(PathLocalBackend::new(root, false).unwrap()))
}

fn setup_backend(backend: Arc<dyn ObjectStore>) -> (Kernel, OperationContext) {
    let kernel = Kernel::new();
    kernel
        .vfs_router_arc()
        .add_mount("/", "root", Some(backend), false);
    let context = OperationContext::new("owner", "root", false, None, false);
    let result = kernel
        .sys_write(
            &[WriteRequest {
                path: "/document.txt".into(),
                content: b"original contents".to_vec(),
                offset: 0,
            }],
            &context,
        )
        .pop()
        .unwrap()
        .unwrap();
    assert!(result.hit);
    (kernel, context)
}

fn read(kernel: &Kernel, context: &OperationContext) -> Result<Vec<u8>, KernelError> {
    kernel
        .sys_read(
            &[ReadRequest {
                path: "/document.txt".into(),
                offset: 0,
                len: None,
                timeout_ms: 0,
            }],
            context,
        )
        .pop()
        .unwrap()
        .map(|result| result.data.unwrap())
}

#[test]
fn kernel_reads_replacement_from_the_backend_after_external_atomic_save() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, context) = setup(root.path());
    assert_eq!(read(&kernel, &context).unwrap(), b"original contents");

    let replacement = root.path().join("replacement.txt");
    std::fs::write(&replacement, b"updated").unwrap();
    std::fs::rename(replacement, root.path().join("document.txt")).unwrap();

    assert_eq!(read(&kernel, &context).unwrap(), b"updated");
}

#[test]
fn kernel_does_not_read_deleted_contents_from_a_cached_descriptor() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, context) = setup(root.path());
    assert_eq!(read(&kernel, &context).unwrap(), b"original contents");

    std::fs::remove_file(root.path().join("document.txt")).unwrap();

    assert!(matches!(
        read(&kernel, &context),
        Err(KernelError::FileNotFound(_))
    ));
}

#[test]
fn stat_revalidates_reference_files_without_rewriting_durable_metadata() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, context) = setup(root.path());
    let before = kernel.sys_stat("/document.txt", "root").unwrap();
    std::fs::write(root.path().join("document.txt"), b"short").unwrap();
    std::fs::set_permissions(
        root.path().join("document.txt"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let after = kernel.sys_stat("/document.txt", "root").unwrap();
    assert_eq!(after.size, 5);
    assert_eq!(after.mode, 0o700);
    assert_eq!(after.gen, before.gen);
    assert_eq!(after.version, before.version);
    assert_eq!(after.owner_id, before.owner_id);
    assert_eq!(read(&kernel, &context).unwrap(), b"short");

    std::fs::remove_file(root.path().join("document.txt")).unwrap();
    assert!(kernel.sys_stat("/document.txt", "root").is_none());
    let entries = kernel.sys_readdir("/", "root", false, Default::default());
    assert!(!entries.iter().any(|(path, _)| path == "/document.txt"));

    std::fs::write(root.path().join("document.txt"), b"recreated").unwrap();
    let recreated = kernel.sys_stat("/document.txt", "root").unwrap();
    assert_eq!(recreated.size, 9);
    assert_eq!(recreated.gen, before.gen);
}

#[test]
fn stat_reports_executable_mode_for_a_file_created_outside_the_kernel() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, _) = setup(root.path());
    let script = root.path().join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\nprintf ready").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let stat = kernel.sys_stat("/run.sh", "root").unwrap();
    assert_eq!(stat.mode, 0o700);
    assert_eq!(stat.size, 22);
}

#[test]
#[cfg(feature = "driver-local-connector")]
fn local_connector_uses_the_same_reference_revalidation() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, _) = setup_backend(Arc::new(
        backends::storage::local_connector::LocalConnectorBackend::new(root.path(), true, false)
            .unwrap(),
    ));
    std::fs::write(root.path().join("document.txt"), b"changed").unwrap();
    assert_eq!(kernel.sys_stat("/document.txt", "root").unwrap().size, 7);
    std::fs::remove_file(root.path().join("document.txt")).unwrap();
    assert!(kernel.sys_stat("/document.txt", "root").is_none());
    assert!(kernel
        .sys_readdir("/", "root", false, Default::default())
        .is_empty());
}

#[test]
fn reference_revalidation_preserves_virtual_entries_and_implicit_directories() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, _) = setup(root.path());
    for (path, kind, target) in [
        ("/virtual", DT_DIR, None),
        ("/virtual/metadata-only", DT_REG, None),
        ("/virtual/log", DT_STREAM, None),
        ("/virtual/alias", DT_LINK, Some("/document.txt")),
        ("/implicit/metadata-only", DT_REG, None),
    ] {
        kernel
            .sys_setattr(
                path,
                i32::from(kind),
                "",
                None,
                None,
                None,
                "memory",
                "root",
                false,
                1024,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                target,
                None,
                None,
            )
            .unwrap();
        assert_eq!(kernel.sys_stat(path, "root").unwrap().entry_type, kind);
    }
    assert!(!root.path().join("virtual").exists());
    assert_eq!(
        kernel.sys_stat("/implicit", "root").unwrap().entry_type,
        DT_DIR
    );
    let entries = kernel.sys_readdir("/virtual", "root", false, Default::default());
    assert_eq!(entries.len(), 3);
}

#[test]
fn native_permission_changes_apply_to_the_executed_file_and_reject_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, context) = setup(root.path());
    kernel
        .set_file_mode("/document.txt", &context, 0o700)
        .unwrap();
    assert_eq!(
        kernel.sys_stat("/document.txt", "root").unwrap().mode,
        0o700
    );
    assert_eq!(
        std::fs::metadata(root.path().join("document.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(kernel
        .set_file_mode("/document.txt", &context, 0o4700)
        .is_err());
    assert!(kernel.set_file_mode("/missing", &context, 0o700).is_err());
    std::os::unix::fs::symlink("document.txt", root.path().join("alias")).unwrap();
    assert!(kernel.set_file_mode("/alias", &context, 0o600).is_err());
    assert_eq!(
        kernel.sys_stat("/document.txt", "root").unwrap().mode,
        0o700
    );
}

#[test]
fn mkdir_recreates_deleted_native_directories_and_does_not_publish_failed_creates() {
    let root = tempfile::tempdir().unwrap();
    let (kernel, context) = setup(root.path());
    KernelConvenience::mkdir(&kernel, "/project", &context, true, true).unwrap();
    kernel.set_file_mode("/project", &context, 0o700).unwrap();
    assert_eq!(kernel.sys_stat("/project", "root").unwrap().mode, 0o700);
    std::fs::remove_dir(root.path().join("project")).unwrap();
    KernelConvenience::mkdir(&kernel, "/project", &context, true, true).unwrap();
    assert!(root.path().join("project").is_dir());
    assert!(
        KernelConvenience::mkdir(&kernel, "/document.txt/child", &context, true, true).is_err()
    );
    assert!(kernel.sys_stat("/document.txt/child", "root").is_none());
}
