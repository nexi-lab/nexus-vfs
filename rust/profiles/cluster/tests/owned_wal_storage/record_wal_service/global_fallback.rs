//! Preserve captured native metadata, including absence, across actual I/O.

use super::service;
use backends::storage::path_local::PathLocalBackend;
use kernel::abc::object_store::{ObjectStore, StorageError, WriteResult};
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext, ReadRequest};
use kernel::meta_store::{FileMetadata, LocalMetaStore, MetaStore};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct NativeStore {
    inner: PathLocalBackend,
    reads: AtomicUsize,
    writes: AtomicUsize,
    after_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl NativeStore {
    fn open(path: &std::path::Path) -> Self {
        Self {
            inner: PathLocalBackend::new(path, true).unwrap(),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            after_read: Mutex::new(None),
        }
    }
}

impl ObjectStore for NativeStore {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        ctx: &OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_content(content, content_id, ctx, offset)
    }

    fn read_content(
        &self,
        content_id: &str,
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let result = self.inner.read_content(content_id, ctx)?;
        let callback = self.after_read.lock().unwrap().take();
        if let Some(callback) = callback {
            callback();
        }
        Ok(result)
    }
}

fn seed_replacement(path: &std::path::Path, backend: Arc<NativeStore>) -> FileMetadata {
    let kernel = Kernel::new();
    kernel.release_metastores();
    kernel.set_metastore_path(path.to_str().unwrap()).unwrap();
    kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local").with_backend(backend),
        )
        .unwrap();
    KernelSyscall::sys_write(&kernel, "/ordinary", &service(), b"independent B bytes", 0).unwrap();
    assert_eq!(
        KernelSyscall::sys_read(&kernel, "/ordinary", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"independent B bytes".to_vec())
    );
    kernel.release_metastores();
    LocalMetaStore::open(path)
        .unwrap()
        .get("/ordinary")
        .unwrap()
        .unwrap()
}

fn read_with_initially_absent_metastore(batch: bool) {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let b_path = b_dir.path().join("metadata.redb");
    let a_backend = Arc::new(NativeStore::open(&a_dir.path().join("content")));
    let b_backend = Arc::new(NativeStore::open(&b_dir.path().join("content")));
    let b_image = seed_replacement(&b_path, b_backend.clone());
    let kernel = Arc::new(Kernel::new());
    kernel.release_metastores();
    kernel.set_read_batch_max_concurrency(1);
    kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local").with_backend(a_backend.clone()),
        )
        .unwrap();
    let paths = if batch { &['a', 'b'][..] } else { &['a'][..] };
    let mut requests = Vec::new();
    for name in paths {
        let key = format!("raw-{name}");
        a_backend
            .write_content(key.as_bytes(), &key, &service(), 0)
            .unwrap();
        let path = format!("/{key}");
        // Ordinary native reads work with neither a mounted nor global store.
        assert_eq!(
            KernelSyscall::sys_read(kernel.as_ref(), &path, &service(), 0, 0)
                .unwrap()
                .data,
            Some(key.as_bytes().to_vec())
        );
        requests.push(ReadRequest {
            path,
            offset: 0,
            len: None,
            timeout_ms: 0,
        });
    }
    let weak = Arc::downgrade(&kernel);
    let replacement_path = b_path.clone();
    *a_backend.after_read.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade()
            .unwrap()
            .set_metastore_path(replacement_path.to_str().unwrap())
            .unwrap();
    }));
    let a_reads = a_backend.reads.load(Ordering::SeqCst);
    let b_reads = b_backend.reads.load(Ordering::SeqCst);
    let mut peer = service();
    peer.propagates_cross_node = true;
    let results = Kernel::sys_read(kernel.as_ref(), &requests, &peer);
    assert_eq!(results.len(), requests.len());
    for (result, request) in results.into_iter().zip(&requests) {
        assert_eq!(
            result.unwrap().data,
            Some(request.path.trim_start_matches('/').as_bytes().to_vec())
        );
    }
    assert!(a_backend.after_read.lock().unwrap().is_none());
    assert_eq!(
        a_backend.reads.load(Ordering::SeqCst),
        a_reads + paths.len()
    );
    assert_eq!(b_backend.reads.load(Ordering::SeqCst), b_reads);
    kernel.release_metastores();
    let replacement = LocalMetaStore::open(&b_path).unwrap();
    for request in &requests {
        assert!(
            replacement.get(&request.path).unwrap().is_none(),
            "captured absence must not publish native A observation into later B"
        );
    }
    assert_eq!(replacement.get("/ordinary").unwrap().unwrap(), b_image);
}

#[test]
fn kernel_native_read_keeps_absent_metadata_after_global_install_during_io() {
    read_with_initially_absent_metastore(false);
}

#[test]
fn kernel_native_batch_keeps_absent_metadata_after_global_install_during_io() {
    read_with_initially_absent_metastore(true);
}

#[test]
fn kernel_native_copy_requires_captured_destination_store_before_content_io() {
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(NativeStore::open(&directory.path().join("source")));
    let destination = Arc::new(NativeStore::open(&directory.path().join("destination")));
    let source_store =
        Arc::new(LocalMetaStore::open(&directory.path().join("source.redb")).unwrap());
    let b_path = directory.path().join("later.redb");
    let b_backend = Arc::new(NativeStore::open(&directory.path().join("later")));
    let b_image = seed_replacement(&b_path, b_backend);
    let kernel = Arc::new(Kernel::new());
    kernel.release_metastores();
    // Persist child mount topology through the root store while leaving the
    // global fallback and destination mount's own metadata slot absent.
    kernel
        .mount(
            "/",
            MountOptions::new(&service(), "local")
                .with_backend(Arc::new(NativeStore::open(&directory.path().join("root"))))
                .with_metastore(source_store.clone()),
        )
        .unwrap();
    kernel
        .mount(
            "/source",
            MountOptions::new(&service(), "local")
                .with_backend(source.clone())
                .with_metastore(source_store.clone()),
        )
        .unwrap();
    kernel
        .mount(
            "/destination",
            MountOptions::new(&service(), "local").with_backend(destination.clone()),
        )
        .unwrap();
    assert!(kernel
        .vfs_router_arc()
        .route("/destination/copied", "root")
        .unwrap()
        .metastore
        .is_none());
    KernelSyscall::sys_write(
        kernel.as_ref(),
        "/source/input",
        &service(),
        b"original bytes",
        0,
    )
    .unwrap();
    assert!(
        kernel
            .sys_copy("/source/input", "/source/ordinary-copy", &service())
            .unwrap()
            .hit
    );
    assert_eq!(
        KernelSyscall::sys_read(kernel.as_ref(), "/source/ordinary-copy", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"original bytes".to_vec())
    );
    let source_image = source_store.get("/source/input").unwrap().unwrap();
    let source_reads = source.reads.load(Ordering::SeqCst);
    let destination_writes = destination.writes.load(Ordering::SeqCst);
    let weak = Arc::downgrade(&kernel);
    let replacement_path = b_path.clone();
    *source.after_read.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade()
            .unwrap()
            .set_metastore_path(replacement_path.to_str().unwrap())
            .unwrap();
    }));
    let result = kernel.sys_copy("/source/input", "/destination/copied", &service());
    assert!(
        matches!(result, Err(kernel::kernel::KernelError::IOError(ref error))
            if error.contains("sys_copy: no metastore")),
        "copy without a captured destination store must refuse before content I/O"
    );
    assert_eq!(
        source.reads.load(Ordering::SeqCst),
        source_reads,
        "copy performed source I/O without captured destination metadata"
    );
    assert_eq!(
        destination.writes.load(Ordering::SeqCst),
        destination_writes,
        "copy wrote bytes without captured destination metadata"
    );
    assert!(source.after_read.lock().unwrap().is_some());
    assert!(!directory.path().join("destination/copied").exists());
    assert_eq!(
        source_store.get("/source/input").unwrap().unwrap(),
        source_image
    );
    // Consume the armed cut through an allowed real read, proving that the
    // later store is usable and the copy was refused before reaching the cut.
    assert_eq!(
        KernelSyscall::sys_read(kernel.as_ref(), "/source/input", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"original bytes".to_vec())
    );
    assert!(source.after_read.lock().unwrap().is_none());
    kernel.release_metastores();
    let replacement = LocalMetaStore::open(&b_path).unwrap();
    assert!(replacement.get("/destination/copied").unwrap().is_none());
    assert_eq!(replacement.get("/ordinary").unwrap().unwrap(), b_image);
}

#[test]
fn kernel_global_fallback_observes_captured_native_store_after_replacement() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_path = a_dir.path().join("metadata.redb");
    let b_path = b_dir.path().join("metadata.redb");
    let a_backend = Arc::new(NativeStore::open(&a_dir.path().join("content")));
    let b_backend = Arc::new(NativeStore::open(&b_dir.path().join("content")));
    a_backend
        .write_content(b"native original A bytes", "raw", &service(), 0)
        .unwrap();
    let original = LocalMetaStore::open(&a_path).unwrap();
    assert!(original.get("/raw").unwrap().is_none());
    drop(original);
    let a = Arc::new(Kernel::new());
    a.release_metastores();
    a.set_metastore_path(a_path.to_str().unwrap()).unwrap();
    a.mount(
        "/",
        MountOptions::new(&service(), "local").with_backend(a_backend.clone()),
    )
    .unwrap();
    let b = Kernel::new();
    b.release_metastores();
    b.set_metastore_path(b_path.to_str().unwrap()).unwrap();
    b.mount(
        "/",
        MountOptions::new(&service(), "local").with_backend(b_backend.clone()),
    )
    .unwrap();
    KernelSyscall::sys_write(&b, "/ordinary", &service(), b"independent B bytes", 0).unwrap();
    assert_eq!(
        KernelSyscall::sys_read(&b, "/ordinary", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"independent B bytes".to_vec())
    );
    b.release_metastores();
    let replacement = LocalMetaStore::open(&b_path).unwrap();
    let b_image = replacement.get("/ordinary").unwrap().unwrap();
    assert!(replacement.get("/raw").unwrap().is_none());
    drop(replacement);
    assert!(a
        .vfs_router_arc()
        .route("/raw", "root")
        .unwrap()
        .metastore
        .is_none());
    let b_reads = b_backend.reads.load(Ordering::SeqCst);
    let weak = Arc::downgrade(&a);
    let replacement_path = b_path.clone();
    let replacement_backend = b_backend.clone();
    *a_backend.after_read.lock().unwrap() = Some(Box::new(move || {
        let kernel = weak.upgrade().unwrap();
        kernel
            .set_metastore_path(replacement_path.to_str().unwrap())
            .unwrap();
        kernel
            .mount(
                "/",
                MountOptions::new(&service(), "local").with_backend(replacement_backend),
            )
            .unwrap();
    }));
    let mut peer = service();
    peer.propagates_cross_node = true;
    assert_eq!(
        KernelSyscall::sys_read(a.as_ref(), "/raw", &peer, 0, 0)
            .unwrap()
            .data,
        Some(b"native original A bytes".to_vec())
    );
    assert!(a_backend.after_read.lock().unwrap().is_none());
    assert_eq!(b_backend.reads.load(Ordering::SeqCst), b_reads);
    a.release_metastores();
    // Reopening the actual files also proves the old global snapshot drained.
    let original = LocalMetaStore::open(&a_path).unwrap();
    let replacement = LocalMetaStore::open(&b_path).unwrap();
    assert!(replacement.get("/raw").unwrap().is_none());
    assert_eq!(replacement.get("/ordinary").unwrap().unwrap(), b_image);
    let observed = original.get("/raw").unwrap().unwrap();
    assert_eq!(observed.content_id.as_deref(), Some("raw"));
    assert_eq!(
        a_backend
            .read_content(observed.content_id.as_deref().unwrap(), &service())
            .unwrap(),
        b"native original A bytes"
    );
}
