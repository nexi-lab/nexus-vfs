#![cfg(all(unix, feature = "driver-path-local"))]

use std::path::Path;
use std::sync::Arc;

use backends::storage::path_local::PathLocalBackend;
use kernel::kernel::{Kernel, KernelError, OperationContext, ReadRequest, WriteRequest};

fn setup(root: &Path) -> (Kernel, OperationContext) {
    let kernel = Kernel::new();
    let backend = Arc::new(PathLocalBackend::new(root, false).unwrap());
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
