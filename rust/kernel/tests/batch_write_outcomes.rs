mod common;

use std::sync::{Arc, Mutex};

use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::{Kernel, WriteRequest};
use kernel::meta_store::{FileMetadata, LocalMetaStore, MetaStore, MetaStoreError};
use kernel::{FileEvent, FileEventType, MutationObserver};

struct RefusingStore(LocalMetaStore);

impl MetaStore for RefusingStore {
    fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
        self.0.get(path)
    }

    fn put(&self, path: &str, metadata: FileMetadata) -> Result<(), MetaStoreError> {
        if path.ends_with("/refused") {
            return Err(MetaStoreError::IOError("injected commit failure".into()));
        }
        self.0.put(path, metadata)
    }

    fn delete(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.0.delete(path)
    }

    fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        self.0.list(prefix)
    }

    fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.0.exists(path)
    }
}

#[derive(Default)]
struct Writes(Mutex<Vec<String>>);

impl MutationObserver for Writes {
    fn on_mutation(&self, event: &FileEvent) {
        if event.event_type == FileEventType::FileWrite {
            self.0.lock().unwrap().push(event.path.clone());
        }
    }
}

#[test]
fn a_commit_failure_keeps_its_request_identity_after_a_miss() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(RefusingStore(
        LocalMetaStore::open(&directory.path().join("namespace.redb")).unwrap(),
    ));
    let kernel = Kernel::new();
    let ctx = common::admin_ctx();
    kernel.mount("/", MountOptions::new(&ctx, "mem")).unwrap();
    kernel
        .mount(
            "/files",
            MountOptions::new(&ctx, "mem")
                .with_backend(Arc::new(common::MemBackend::default()))
                .with_metastore(store.clone()),
        )
        .unwrap();
    // A second mount uses the actual global metastore and grouped commit.
    kernel
        .mount(
            "/global",
            MountOptions::new(&ctx, "mem").with_backend(Arc::new(common::MemBackend::default())),
        )
        .unwrap();
    let writes = Arc::new(Writes::default());
    let handle = kernel.enlist_hook_only_service("write-observer").unwrap();
    kernel.register_service_observer(&handle, writes.clone(), "writes".into(), u32::MAX);
    let paths = [
        "/unmounted/miss",
        "/files/kept",
        "/files/refused",
        "/global/kept",
    ];
    let requests: Vec<_> = paths
        .iter()
        .map(|path| WriteRequest {
            path: (*path).into(),
            content: path.as_bytes().to_vec(),
            offset: 0,
        })
        .collect();

    let results = kernel.sys_write(&requests, &ctx);

    assert_eq!(results.len(), requests.len());
    assert!(matches!(&results[0], Ok(result) if !result.hit));
    assert!(
        matches!(&results[1], Ok(result) if result.hit),
        "a sibling failure must preserve a committed result"
    );
    let error = results[2]
        .as_ref()
        .err()
        .expect("failed commit must be an error on its original request");
    assert!(error.to_string().contains("injected commit failure"));
    assert!(matches!(&results[3], Ok(result) if result.hit));
    assert!(store.exists("/files/kept").unwrap());
    assert!(!store.exists("/files/refused").unwrap());
    assert_eq!(
        kernel
            .read("/files/kept", &ctx, 0, 0)
            .unwrap()
            .data
            .unwrap(),
        b"/files/kept"
    );
    assert_eq!(
        kernel
            .read("/global/kept", &ctx, 0, 0)
            .unwrap()
            .data
            .unwrap(),
        b"/global/kept"
    );
    assert_eq!(*writes.0.lock().unwrap(), ["/files/kept", "/global/kept"]);

    // A failed request releases its lock, allowing a subsequent write to finish.
    assert!(kernel.write("/files/refused", &ctx, b"retry", 0).is_err());
    assert!(
        kernel
            .write("/files/another", &ctx, b"next", 0)
            .unwrap()
            .hit
    );
}
