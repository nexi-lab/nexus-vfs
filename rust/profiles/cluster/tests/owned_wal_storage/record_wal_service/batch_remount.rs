//! Replace the actual mount between batch resolution and content fan-out.

use super::regular_reads::CountedCas;
use super::unscoped_reads::scoped_refusal;
use super::{service, Fixture, OWNER};
use kernel::extensions::conditional_metadata::ConditionalMetadata;
use kernel::extensions::guarded_records::GuardedRecords;
use kernel::extensions::record_protection::RecordProtection;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, ReadRequest};
use kernel::meta_store::{FileMetadata, MetaStore, MetaStoreError};
use nexus_raft::zone_meta_store::ZoneMetaStore;
use std::sync::{Arc, Mutex};

type Replacement = Box<dyn FnOnce() + Send>;

struct ReplaceAfterGet {
    inner: Arc<ZoneMetaStore>,
    on_path: &'static str,
    replacement: Mutex<Option<Replacement>>,
}

impl MetaStore for ReplaceAfterGet {
    fn as_guarded_records(&self) -> Option<&dyn GuardedRecords> {
        self.inner.as_guarded_records()
    }

    fn as_record_protection(&self) -> Option<&dyn RecordProtection> {
        self.inner.as_record_protection()
    }

    fn as_conditional_metadata(&self) -> Option<&dyn ConditionalMetadata> {
        self.inner.as_conditional_metadata()
    }

    fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
        let value = self.inner.get(path)?;
        if path == self.on_path {
            let replacement = self.replacement.lock().unwrap().take();
            if let Some(replace) = replacement {
                replace();
            }
        }
        Ok(value)
    }

    fn put(&self, path: &str, value: FileMetadata) -> Result<(), MetaStoreError> {
        self.inner.put(path, value)
    }

    fn delete(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.inner.delete(path)
    }

    fn list(&self, path: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        self.inner.list(path)
    }

    fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.inner.exists(path)
    }
}

#[test]
fn kernel_batch_read_keeps_captured_store_and_backend_across_same_name_remount() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_backend = Arc::new(CountedCas::new(&a_dir.path().join("cas")));
    let b_backend = Arc::new(CountedCas::new(&b_dir.path().join("cas")));
    let (a, mounted) = Fixture::open_with_components(
        a_dir.path(),
        |inner| {
            Arc::new(ReplaceAfterGet {
                inner,
                on_path: "/second",
                replacement: Mutex::new(None),
            })
        },
        a_backend.clone(),
    );
    let b = Fixture::open_with_components(b_dir.path(), |store| store, b_backend.clone()).0;
    for path in ["/first", "/second"] {
        KernelSyscall::sys_write(a.kernel.as_ref(), path, &service(), b"original A bytes", 0)
            .unwrap();
        KernelSyscall::sys_write(
            b.kernel.as_ref(),
            path,
            &service(),
            b"replacement B bytes",
            0,
        )
        .unwrap();
    }
    let owner = b.enroll();
    b.kernel
        .protect_record_content("/second", &service())
        .unwrap();
    b.kernel
        .bind_record_content_owner("/second", OWNER, &service(), &owner)
        .unwrap();
    let b_image = b.store.get("/second").unwrap().unwrap();
    let weak = Arc::downgrade(&a.kernel);
    let store = b.store.clone();
    let backend = b_backend.clone();
    *mounted.replacement.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade()
            .unwrap()
            .mount(
                "/",
                MountOptions::new(&service(), "local")
                    .with_backend(backend)
                    .with_metastore(store),
            )
            .unwrap();
    }));
    let b_counts = b_backend.counts();
    let requests = ["/first", "/second"].map(|path| ReadRequest {
        path: path.into(),
        offset: 0,
        len: None,
        timeout_ms: 0,
    });
    let results = Kernel::sys_read(a.kernel.as_ref(), &requests, &service());
    assert!(
        mounted.replacement.lock().unwrap().is_none(),
        "replacement cut was not reached"
    );
    for result in results {
        assert_eq!(result.unwrap().data, Some(b"original A bytes".to_vec()));
    }
    assert_eq!(
        b_backend.counts(),
        b_counts,
        "batch touched the replacement backend"
    );
    assert_eq!(b.store.get("/second").unwrap().unwrap(), b_image);
    assert_eq!(
        KernelSyscall::sys_read(a.kernel.as_ref(), "/first", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"replacement B bytes".to_vec())
    );
    scoped_refusal(KernelSyscall::sys_read(
        a.kernel.as_ref(),
        "/second",
        &service(),
        0,
        0,
    ));
    assert_eq!(
        a.store.get("/first").unwrap().unwrap().content_id,
        a.store.get("/second").unwrap().unwrap().content_id
    );
}

fn copy_across_replaced_mount(is_cas: bool) {
    use backends::storage::{cas_local::CasLocalBackend, path_local::PathLocalBackend};
    use kernel::abc::object_store::ObjectStore;

    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let backend = |root: &std::path::Path| -> Arc<dyn ObjectStore> {
        if is_cas {
            Arc::new(CasLocalBackend::new_durable(root).unwrap())
        } else {
            Arc::new(PathLocalBackend::new(root, true).unwrap())
        }
    };
    let a_backend = backend(&a_dir.path().join("content"));
    let b_backend = backend(&b_dir.path().join("content"));
    let (a, mounted) = Fixture::open_with_components(
        a_dir.path(),
        |inner| {
            Arc::new(ReplaceAfterGet {
                inner,
                on_path: "/source",
                replacement: Mutex::new(None),
            })
        },
        a_backend.clone(),
    );
    let b = Fixture::open_with_components(b_dir.path(), |store| store, b_backend.clone()).0;
    for (fixture, bytes) in [
        (&a, b"original A bytes".as_slice()),
        (&b, b"replacement B bytes"),
    ] {
        KernelSyscall::sys_write(fixture.kernel.as_ref(), "/source", &service(), bytes, 0).unwrap();
        assert!(
            fixture
                .kernel
                .sys_copy("/source", "/ordinary", &service())
                .unwrap()
                .hit
        );
        assert_eq!(
            KernelSyscall::sys_read(fixture.kernel.as_ref(), "/ordinary", &service(), 0, 0)
                .unwrap()
                .data,
            Some(bytes.to_vec())
        );
    }
    let a_source = a.store.get("/source").unwrap().unwrap();
    let b_source = b.store.get("/source").unwrap().unwrap();
    let a_ordinary = a.store.get("/ordinary").unwrap().unwrap();
    let b_ordinary = b.store.get("/ordinary").unwrap().unwrap();
    let weak = Arc::downgrade(&a.kernel);
    let store = b.store.clone();
    let target = b_backend.clone();
    *mounted.replacement.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade()
            .unwrap()
            .mount(
                "/",
                MountOptions::new(&service(), "local")
                    .with_backend(target)
                    .with_metastore(store),
            )
            .unwrap();
    }));
    let copied = a.kernel.sys_copy("/source", "/copied", &service()).unwrap();
    assert!(copied.hit);
    assert!(
        mounted.replacement.lock().unwrap().is_none(),
        "source-read replacement cut was not reached"
    );
    assert!(a.store.get("/copied").unwrap().is_none());
    let published = b.store.get("/copied").unwrap().unwrap();
    let id = published.content_id.as_deref().unwrap();
    if is_cas {
        assert!(
            b_backend.as_cas().unwrap().content_exists(id),
            "copy metadata refers to bytes absent from the captured destination backend"
        );
    } else {
        assert!(
            !a_dir.path().join("content/copied").exists(),
            "copy wrote destination bytes into the captured source backend"
        );
        assert_eq!(
            std::fs::read(b_dir.path().join("content/copied")).unwrap(),
            b"original A bytes"
        );
    }
    assert_eq!(
        b_backend.read_content(id, &service()).unwrap(),
        b"original A bytes"
    );
    assert_eq!(
        KernelSyscall::sys_read(a.kernel.as_ref(), "/copied", &service(), 0, 0)
            .unwrap()
            .data,
        Some(b"original A bytes".to_vec())
    );
    assert_eq!(a.store.get("/source").unwrap().unwrap(), a_source);
    assert_eq!(b.store.get("/source").unwrap().unwrap(), b_source);
    assert_eq!(a.store.get("/ordinary").unwrap().unwrap(), a_ordinary);
    assert_eq!(b.store.get("/ordinary").unwrap().unwrap(), b_ordinary);
    drop(a);
}

#[test]
fn kernel_cas_copy_keeps_content_and_metadata_paired_across_mount_replacement() {
    copy_across_replaced_mount(true);
}

#[test]
fn kernel_native_file_copy_keeps_content_and_metadata_paired_across_mount_replacement() {
    copy_across_replaced_mount(false);
}
