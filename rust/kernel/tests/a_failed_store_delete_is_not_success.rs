mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use kernel::abc::meta_store::{FileMetadata, MetaStore, MetaStoreError};
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::Kernel;

#[derive(Default)]
struct FailingStore {
    entries: Mutex<BTreeMap<String, FileMetadata>>,
    failure: AtomicU8,
}

impl FailingStore {
    fn check(&self, operation: u8) -> Result<(), MetaStoreError> {
        if self.failure.load(Ordering::SeqCst) == operation {
            Err(MetaStoreError::IOError("injected store failure".into()))
        } else {
            Ok(())
        }
    }
}

impl MetaStore for FailingStore {
    fn get(&self, path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
        self.check(1)?;
        Ok(self.entries.lock().unwrap().get(path).cloned())
    }

    fn put(&self, path: &str, metadata: FileMetadata) -> Result<(), MetaStoreError> {
        self.entries.lock().unwrap().insert(path.into(), metadata);
        Ok(())
    }

    fn delete(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.check(4)?;
        Ok(self.entries.lock().unwrap().remove(path).is_some())
    }

    fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        self.check(2)?;
        Ok(self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.path.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
        Ok(self.entries.lock().unwrap().contains_key(path))
    }

    fn delete_batch(&self, paths: &[String]) -> Result<usize, MetaStoreError> {
        self.check(3)?;
        let mut entries = self.entries.lock().unwrap();
        Ok(paths
            .iter()
            .filter(|path| entries.remove(*path).is_some())
            .count())
    }
}

#[test]
fn recursive_removal_propagates_store_failures_and_releases_its_lock() {
    for failure in 1..=4 {
        let kernel = Kernel::new();
        let store = Arc::new(FailingStore::default());
        let ctx = common::admin_ctx();
        kernel
            .mount(
                "/",
                MountOptions::new(&ctx, "mem")
                    .with_backend(Arc::new(common::MemBackend::default()))
                    .with_metastore(store.clone()),
            )
            .unwrap();
        kernel.mkdir("/skills", &ctx, true, true).unwrap();
        kernel.write("/skills/run.sh", &ctx, b"script", 0).unwrap();
        store.failure.store(failure, Ordering::SeqCst);

        let error = kernel
            .rmdir("/skills", &ctx, true)
            .err()
            .expect("store failure must propagate");
        assert!(
            error.to_string().contains("injected store failure"),
            "{error}"
        );
        store.failure.store(0, Ordering::SeqCst);
        assert!(
            store.exists("/skills").unwrap(),
            "failed removal must retain the directory row"
        );
        if failure < 4 {
            assert!(
                store.exists("/skills/run.sh").unwrap(),
                "no child deletion was acknowledged"
            );
        }
        assert!(
            kernel.rmdir("/skills", &ctx, true).unwrap().hit,
            "a failed store operation must release the directory lock for retry"
        );
        assert!(!store.exists("/skills").unwrap());
        assert!(!store.exists("/skills/run.sh").unwrap());
    }
}
