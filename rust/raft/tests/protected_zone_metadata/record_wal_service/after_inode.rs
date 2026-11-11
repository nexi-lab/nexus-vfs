//! Inject a read failure only after the actual Raft inode commit is visible.

use super::{service, Fixture, HISTORY, OWNER};
use kernel::extensions::conditional_metadata::ConditionalMetadata;
use kernel::extensions::guarded_records::GuardedRecords;
use kernel::extensions::record_protection::RecordProtection;
use kernel::kernel::conditional_content::ConditionalContentError;
use kernel::meta_store::{FileMetadata, MetaStore, MetaStoreError, StreamSegment, DT_STREAM};
use kernel::stream::StreamBackend;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

const CUT: &str = "post-inode handle-admission read fault";

/// Keep every mutation, revision and WAL read in the real store. The only
/// injected result is one metadata read failure after the new inode exists.
struct FailAfterInode {
    inner: Arc<nexus_raft::zone_meta_store::ZoneMetaStore>,
    armed: AtomicBool,
    faults: AtomicUsize,
}

impl MetaStore for FailAfterInode {
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
        let result = self.inner.get(path)?;
        if path == HISTORY
            && result
                .as_ref()
                .is_some_and(|metadata| metadata.entry_type == DT_STREAM)
            && self.armed.swap(false, Ordering::SeqCst)
        {
            self.faults.fetch_add(1, Ordering::SeqCst);
            return Err(MetaStoreError::IOError(CUT.into()));
        }
        Ok(result)
    }

    fn put(&self, path: &str, metadata: FileMetadata) -> Result<(), MetaStoreError> {
        self.inner.put(path, metadata)
    }

    fn delete(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.inner.delete(path)
    }

    fn list(&self, prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
        self.inner.list(prefix)
    }

    fn exists(&self, path: &str) -> Result<bool, MetaStoreError> {
        self.inner.exists(path)
    }

    fn coherence_key(&self) -> Option<usize> {
        self.inner.coherence_key()
    }

    fn stream_tail(&self, prefix: &str) -> Result<u64, MetaStoreError> {
        self.inner.stream_tail(prefix)
    }

    fn stream_floor(&self, prefix: &str) -> Result<u64, MetaStoreError> {
        self.inner.stream_floor(prefix)
    }

    fn stream_earliest(&self, prefix: &str) -> Result<u64, MetaStoreError> {
        self.inner.stream_earliest(prefix)
    }

    fn get_stream_entry(&self, key: &str) -> Result<Option<Vec<u8>>, MetaStoreError> {
        self.inner.get_stream_entry(key)
    }

    fn find_stream_segment(
        &self,
        prefix: &str,
        seq: u64,
    ) -> Result<Option<StreamSegment>, MetaStoreError> {
        self.inner.find_stream_segment(prefix, seq)
    }

    fn list_stream_segments(&self, prefix: &str) -> Result<Vec<StreamSegment>, MetaStoreError> {
        self.inner.list_stream_segments(prefix)
    }
}

#[test]
fn kernel_owned_wal_post_commit_admission_fault_requires_original_readback() {
    use kernel::core::stream::wal::wal_stream_prefix;

    let directory = tempfile::tempdir().unwrap();
    let (fixture, fault) = Fixture::open_with_store(directory.path(), true, |inner| {
        Arc::new(FailAfterInode {
            inner,
            armed: AtomicBool::new(true),
            faults: AtomicUsize::new(0),
        })
    });
    let owner = fixture.enroll();
    match fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
    {
        Err(ConditionalContentError::Unknown(message)) => assert!(message.contains(CUT)),
        Err(other) => panic!("post-commit failure must retain its outcome: {other:?}"),
        Ok(_) => panic!("the failed admission must not return a ready handle"),
    }
    assert_eq!(fault.faults.load(Ordering::SeqCst), 1);
    let committed = fixture
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(HISTORY)
        .unwrap()
        .unwrap();
    assert_eq!(committed.metadata.entry_type, DT_STREAM);
    assert!(!committed.version.is_empty());
    let prefix = wal_stream_prefix(HISTORY);
    assert_eq!(fixture.store.stream_tail(&prefix).unwrap(), 0);

    // Read back the original path/owner, rather than create another lifetime.
    let original = fixture
        .kernel
        .open_record_wal(HISTORY, &service(), &owner)
        .unwrap();
    let initialization = b"original initialization operation";
    assert_eq!(StreamBackend::push(&original, initialization).unwrap(), 0);
    assert_eq!(original.read_at(0).unwrap(), Some(initialization.to_vec()));
    assert!(fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .is_err());
    drop(original);
    let restored = fixture
        .kernel
        .open_record_wal(HISTORY, &service(), &owner)
        .unwrap();
    assert_eq!(restored.read_at(0).unwrap(), Some(initialization.to_vec()));
    assert_eq!(fixture.store.stream_tail(&prefix).unwrap(), 1);
    let after = fixture
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(HISTORY)
        .unwrap()
        .unwrap();
    assert_eq!(after.version, committed.version);
    assert_eq!(after.metadata, committed.metadata);
}
