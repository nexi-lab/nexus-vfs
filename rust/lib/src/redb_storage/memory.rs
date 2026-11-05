//! Sparse, zero-filled byte storage for ephemeral redb databases.

use std::collections::BTreeMap;
use std::io;
use std::sync::RwLock;

use redb::StorageBackend;

fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("memory database lock poisoned")
}

const PAGE_BYTES: usize = 4096;
const PAGE_BYTES_U64: u64 = PAGE_BYTES as u64;

#[derive(Debug, Default)]
struct Buffer {
    len: u64,
    pages: BTreeMap<u64, Box<[u8; PAGE_BYTES]>>,
}

impl Buffer {
    fn check_range(&self, offset: u64, size: usize) -> io::Result<()> {
        let end = u64::try_from(size)
            .ok()
            .and_then(|size| offset.checked_add(size));
        if end.is_some_and(|end| end <= self.len) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory database range exceeds its length",
            ))
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct SparseMemoryBackend(RwLock<Buffer>);

impl StorageBackend for SparseMemoryBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.read().map_err(lock_error)?.len)
    }

    fn read(&self, mut offset: u64, mut output: &mut [u8]) -> io::Result<()> {
        let state = self.0.read().map_err(lock_error)?;
        state.check_range(offset, output.len())?;
        while !output.is_empty() {
            let start = (offset % PAGE_BYTES_U64) as usize;
            let size = output.len().min(PAGE_BYTES - start);
            let (current, rest) = output.split_at_mut(size);
            match state.pages.get(&(offset / PAGE_BYTES_U64)) {
                Some(page) => current.copy_from_slice(&page[start..start + size]),
                None => current.fill(0),
            }
            output = rest;
            offset += size as u64;
        }
        Ok(())
    }

    fn write(&self, mut offset: u64, mut input: &[u8]) -> io::Result<()> {
        let mut state = self.0.write().map_err(lock_error)?;
        state.check_range(offset, input.len())?;
        while !input.is_empty() {
            let start = (offset % PAGE_BYTES_U64) as usize;
            let size = input.len().min(PAGE_BYTES - start);
            let page = state
                .pages
                .entry(offset / PAGE_BYTES_U64)
                .or_insert_with(|| Box::new([0; PAGE_BYTES]));
            page[start..start + size].copy_from_slice(&input[..size]);
            input = &input[size..];
            offset += size as u64;
        }
        Ok(())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let mut state = self.0.write().map_err(lock_error)?;
        if len < state.len {
            let retained = len.div_ceil(PAGE_BYTES_U64);
            drop(state.pages.split_off(&retained));
            let tail = (len % PAGE_BYTES_U64) as usize;
            if tail != 0 {
                if let Some(page) = state.pages.get_mut(&(len / PAGE_BYTES_U64)) {
                    page[tail..].fill(0);
                }
            }
        }
        state.len = len;
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_growth_cross_page_writes_and_truncate_regrow_preserve_byte_semantics() {
        let backend = SparseMemoryBackend::default();
        let size = 8 * 1024 * 1024 * 1024;
        backend.set_len(size).unwrap();
        assert!(backend.0.read().unwrap().pages.is_empty());
        let offset = size - PAGE_BYTES_U64 - 3;
        backend.write(offset, b"cross-boundary").unwrap();
        let mut bytes = [255; 18];
        backend.read(offset - 2, &mut bytes).unwrap();
        assert_eq!(&bytes, b"\0\0cross-boundary\0\0");
        backend.set_len(offset + 5).unwrap();
        backend.set_len(size).unwrap();
        backend.read(offset - 2, &mut bytes).unwrap();
        assert_eq!(&bytes, b"\0\0cross\0\0\0\0\0\0\0\0\0\0\0");
        backend.set_len(0).unwrap();
        assert!(backend.0.read().unwrap().pages.is_empty());
    }

    #[test]
    fn invalid_ranges_fail_before_read_or_write_and_empty_end_ranges_are_valid() {
        let backend = SparseMemoryBackend::default();
        backend.set_len(5).unwrap();
        backend.write(0, b"hello").unwrap();
        assert_eq!(
            backend.write(4, b"xx").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let mut bytes = [9; 5];
        assert!(backend.read(u64::MAX, &mut bytes).is_err());
        assert_eq!(bytes, [9; 5]);
        backend.read(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
        backend.read(5, &mut []).unwrap();
        backend.write(5, &[]).unwrap();
    }

    #[test]
    fn redb_transactions_commit_abort_and_reclaim_storage_on_sparse_backing() {
        use redb::{ReadableDatabase, TableDefinition};
        const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("records");
        let mut database = super::super::create_in_memory().unwrap();
        let bytes = vec![23; PAGE_BYTES * 3 + 7];
        let transaction = database.begin_write().unwrap();
        transaction
            .open_table(TABLE)
            .unwrap()
            .insert(1, bytes.as_slice())
            .unwrap();
        transaction.commit().unwrap();
        let aborted = database.begin_write().unwrap();
        aborted
            .open_table(TABLE)
            .unwrap()
            .insert(1, b"aborted".as_slice())
            .unwrap();
        aborted.abort().unwrap();
        let snapshot = database.begin_read().unwrap();
        assert_eq!(
            snapshot
                .open_table(TABLE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            bytes
        );
        drop(snapshot);
        database.compact().unwrap();
        let snapshot = database.begin_read().unwrap();
        assert_eq!(
            snapshot
                .open_table(TABLE)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            bytes
        );
    }
}
