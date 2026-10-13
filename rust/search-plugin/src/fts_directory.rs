//! Windows FTS metadata replacement while readers briefly hold a file open.

use std::io;
use std::path::Path;
use std::sync::Arc;

use tantivy::directory::error::{
    DeleteError, LockError, OpenDirectoryError, OpenReadError, OpenWriteError,
};
use tantivy::directory::{
    Directory, DirectoryLock, FileHandle, Lock, MmapDirectory, WatchCallback, WatchHandle, WritePtr,
};

#[derive(Debug, Clone)]
pub(crate) struct FtsDirectory(MmapDirectory);

impl FtsDirectory {
    pub(crate) fn open(path: &Path) -> Result<Self, OpenDirectoryError> {
        MmapDirectory::open(path).map(Self)
    }
}

fn replace_metadata(mut operation: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    let mut retries = 10;
    loop {
        match operation() {
            // Windows readers without FILE_SHARE_DELETE can briefly prevent
            // MoveFileEx from replacing metadata. Retry this atomic operation,
            // whose data is unchanged, while the caller still holds Tantivy's
            // metadata lock. Never replay an IndexWriter transaction.
            Err(error) if retries > 0 && matches!(error.raw_os_error(), Some(5 | 32)) => {
                retries -= 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

impl Directory for FtsDirectory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        self.0.get_file_handle(path)
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        self.0.delete(path)
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        self.0.exists(path)
    }

    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        self.0.open_write(path)
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        self.0.atomic_read(path)
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        replace_metadata(|| self.0.atomic_write(path, data))
    }

    fn sync_directory(&self) -> io::Result<()> {
        self.0.sync_directory()
    }

    fn acquire_lock(&self, lock: &Lock) -> Result<DirectoryLock, LockError> {
        self.0.acquire_lock(lock)
    }

    fn watch(&self, callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        self.0.watch(callback)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;

    use super::*;

    fn hold_reader(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            // FILE_SHARE_READ | FILE_SHARE_WRITE; replacement needs DELETE too.
            .share_mode(0x1 | 0x2)
            .open(path)
            .unwrap()
    }

    #[test]
    fn replacement_survives_a_short_lived_windows_reader_without_partial_bytes() {
        let root = tempfile::tempdir().unwrap();
        let directory = FtsDirectory::open(root.path()).unwrap();
        let path = Path::new(".managed.json");
        directory
            .atomic_write(path, b"old committed facts")
            .unwrap();
        let mut reader = Some(hold_reader(&root.path().join(path)));
        let mut attempts = 0;
        replace_metadata(|| {
            attempts += 1;
            let result = directory.0.atomic_write(path, b"new committed facts");
            if attempts == 1 {
                let error = result.as_ref().unwrap_err();
                assert!(matches!(error.raw_os_error(), Some(5 | 32)));
                assert_eq!(directory.atomic_read(path).unwrap(), b"old committed facts");
                drop(reader.take());
            }
            result
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(directory.atomic_read(path).unwrap(), b"new committed facts");
    }

    #[test]
    fn persistent_windows_reader_returns_an_error_and_keeps_committed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let directory = FtsDirectory::open(root.path()).unwrap();
        let path = Path::new("meta.json");
        directory
            .atomic_write(path, b"old committed facts")
            .unwrap();
        let reader = hold_reader(&root.path().join(path));
        let error = directory
            .atomic_write(path, b"new committed facts")
            .unwrap_err();
        assert!(matches!(error.raw_os_error(), Some(5 | 32)));
        assert_eq!(directory.atomic_read(path).unwrap(), b"old committed facts");
        drop(reader);
        directory
            .atomic_write(path, b"new committed facts")
            .unwrap();
        assert_eq!(directory.atomic_read(path).unwrap(), b"new committed facts");
    }

    #[test]
    fn unrelated_storage_errors_return_without_retry() {
        let mut attempts = 0;
        let error = replace_metadata(|| {
            attempts += 1;
            // ERROR_DISK_FULL is a storage failure, not reader contention.
            Err(io::Error::from_raw_os_error(112))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(112));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn blocked_fts_commit_fails_without_publishing_and_recovers_after_release() {
        let root = tempfile::tempdir().unwrap();
        let index = crate::fts_index::FtsIndex::open_or_create(root.path().to_owned()).unwrap();
        index
            .add_document("/old", 0, "gentian durable facts", None)
            .unwrap();
        index.commit().unwrap();
        let reader = hold_reader(&root.path().join("meta.json"));
        index
            .add_document("/new", 0, "orchid pending facts", None)
            .unwrap();
        assert!(index.commit().is_err());
        assert!(index.writer_status().last_fault.is_some());
        assert_eq!(index.search("gentian", 10, None).unwrap().len(), 1);
        assert!(index.search("orchid", 10, None).unwrap().is_empty());
        drop(reader);
        index
            .add_document("/new", 0, "orchid pending facts", None)
            .unwrap();
        index.commit().unwrap();
        assert!(index.writer_status().last_fault.is_none());
        assert_eq!(index.search("gentian", 10, None).unwrap().len(), 1);
        assert_eq!(index.search("orchid", 10, None).unwrap().len(), 1);
    }
}
