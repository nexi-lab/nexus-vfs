//! Durable DT_STREAM backed by a distributed `MetaStore` (R19.1b').
//!
//! Writes append into the metastore's stream-entries side table —
//! `LocalMetaStore` returns `NotSupported` (so this backend only
//! activates when federation has installed a distributed impl like
//! `ZoneMetaStore`); `ZoneMetaStore` proposes
//! `Command::AppendStreamEntry` so peers see the entry via raft commit.
//! No `FileMetadata` round-trip, no hex encoding, no overlap with the
//! file-metadata key space.
//!
//! ## Layering
//!
//! `WalStreamCore` is a kernel primitive — it lives next to the other
//! `StreamBackend` impls in `crate::core::stream` and only knows about
//! the kernel-internal `MetaStore` HAL trait.  Replication (raft, future
//! alternatives) is the metastore impl's concern, not this struct's.
//! Federation-tier code never reaches in here directly.
//!
//! ## Offsets are assigned by the store, not the caller
//!
//! `write_sync` hands the payload to `MetaStore::append_stream_entry` and
//! gets back the offset the entry was assigned at the store's serialization
//! point (for `ZoneMetaStore`, the raft apply). The core keeps NO local
//! sequence counter, so several writers over the same stream — even on
//! different nodes — can never collide on an offset: the total order is the
//! raft log's. A write is durable (raft-committed) once `write_sync` returns;
//! there is no async buffer that could silently drop it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::abc::meta_store::MetaStore;
use crate::stream::{StreamBackend, StreamError};

/// Side-table key prefix for wal-stream entries. Every entry is keyed
/// `{WAL_STREAM_KEY_PREFIX}{stream_id}/{seq}` (see [`WalStreamCore::new`]).
/// SSOT for the format so [`watch_path_from_wal_stream_key`] can reverse
/// it — the two are round-trip-tested together.
pub const WAL_STREAM_KEY_PREFIX: &str = "/__wal_stream__/";

/// Recover the watched file path from a wal-stream entry key OR stream prefix.
///
/// `stream_id` is the DT_STREAM's path (the path a `sys_watch` is parked on).
/// The A2A stream-wakeup observer passes the applied `AppendStreamEntry`'s
/// stream prefix (`{WAL_STREAM_KEY_PREFIX}{stream_id}/`); the trailing `/`
/// lets the same parse recover `stream_id` whether the input is the prefix or
/// a full `{WAL_STREAM_KEY_PREFIX}{stream_id}/{seq}` entry key. Returns `None`
/// for anything not under `WAL_STREAM_KEY_PREFIX` (e.g. a bare path).
pub fn watch_path_from_wal_stream_key(key: &str) -> Option<&str> {
    // key == "{WAL_STREAM_KEY_PREFIX}{stream_id}/{seq}"; recover stream_id.
    let rest = key.strip_prefix(WAL_STREAM_KEY_PREFIX)?;
    let (path, _seq) = rest.rsplit_once('/')?;
    (!path.is_empty()).then_some(path)
}

/// WAL-backed stream core. Every write is proposed through the distributed
/// `MetaStore`, which assigns the offset and commits it before `write_sync`
/// returns; `read_at` reads committed entries back by offset. Holds no local
/// state beyond the `closed` flag — the entries and their offset cursor live
/// in the store (the raft state machine), which is the single source of truth.
pub struct WalStreamCore {
    store: Arc<dyn MetaStore>,
    stream_id: String,
    prefix: String,
    closed: AtomicBool,
}

impl WalStreamCore {
    pub fn new(store: Arc<dyn MetaStore>, stream_id: String) -> Self {
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}{stream_id}/");
        Self {
            store,
            stream_id,
            prefix,
            closed: AtomicBool::new(false),
        }
    }

    fn key(&self, seq: u64) -> String {
        format!("{}{seq}", self.prefix)
    }

    /// Append `data` and return the offset the store assigned it.
    ///
    /// Blocks until `store.append_stream_entry` confirms durability — i.e.
    /// raft has committed the entry, the state machine has assigned its offset
    /// (in committed order, so concurrent writers never collide), and any peer
    /// reading the same store sees it. This is the sole write path; a wal
    /// DT_STREAM exists to REPLICATE, so a write that can't commit fails loud
    /// rather than buffering and dropping.
    pub fn write_sync(&self, data: &[u8]) -> Result<u64, String> {
        if self.closed.load(Ordering::Acquire) {
            return Err(format!("WAL stream {} is closed", self.stream_id));
        }
        self.store
            .append_stream_entry(&self.prefix, data)
            .map_err(|e| format!("append_stream_entry({}): {e:?}", self.prefix))
    }

    /// Read the entry at `seq`.  `Ok(Some(bytes))` if present;
    /// `Ok(None)` if not yet written; `Err` if the stream is closed
    /// and no more data will arrive at this offset.
    pub fn read_at(&self, seq: u64) -> Result<Option<Vec<u8>>, String> {
        let key = self.key(seq);
        let bytes_opt = self
            .store
            .get_stream_entry(&key)
            .map_err(|e| format!("get_stream_entry({key}): {e:?}"))?;
        match bytes_opt {
            Some(bytes) => Ok(Some(bytes)),
            None => {
                if self.closed.load(Ordering::Acquire) {
                    Err(format!("WAL stream {} closed at seq {seq}", self.stream_id))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn read_batch(&self, start_seq: u64, count: usize) -> Result<(Vec<Vec<u8>>, u64), String> {
        let mut items = Vec::with_capacity(count);
        let mut seq = start_seq;
        for _ in 0..count {
            match self.read_at(seq) {
                Ok(Some(data)) => {
                    items.push(data);
                    seq += 1;
                }
                Ok(None) => break,
                Err(_) if !items.is_empty() => break,
                Err(e) => return Err(e),
            }
        }
        Ok((items, seq))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// The stream's tail (number of entries written), read from the store — the
    /// SSOT that reflects EVERY writer's appends, not just this node's.
    pub fn tail(&self) -> u64 {
        self.store.stream_tail(&self.prefix).unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

// ---------------------------------------------------------------------------
// StreamBackend impl — `setattr_stream(io_profile="wal")` registers a
// WalStreamCore alongside MemoryStreamBackend and SharedMemoryStreamBackend.
// Python never sees WalStreamCore directly; dispatch goes through the
// standard stream syscalls.
// ---------------------------------------------------------------------------

impl StreamBackend for WalStreamCore {
    fn push(&self, data: &[u8]) -> Result<usize, StreamError> {
        // Durable + fail-loud. A wal DT_STREAM exists to REPLICATE, so a push
        // waits for the raft commit and surfaces failure (no reachable leader /
        // propose rejected) instead of buffering and dropping. A2A messaging —
        // and any "a sibling replica must see this" contract — needs it. The
        // syscall handler already blocks on this same propose for file writes,
        // so it is no new blocking surface.
        self.write_sync(data).map(|seq| seq as usize).map_err(|e| {
            tracing::warn!(
                stream_id = %self.stream_id,
                error = %e,
                "wal DT_STREAM push failed to replicate — write rejected (fail-loud)"
            );
            StreamError::Closed("wal DT_STREAM push failed to replicate (no reachable leader?)")
        })
    }

    fn read_at(&self, offset: usize) -> Result<(Vec<u8>, usize), StreamError> {
        match WalStreamCore::read_at(self, offset as u64) {
            Ok(Some(data)) => Ok((data, offset + 1)),
            Ok(None) => Err(StreamError::Empty),
            Err(_) => Err(StreamError::ClosedEmpty),
        }
    }

    fn read_batch(
        &self,
        offset: usize,
        count: usize,
    ) -> Result<(Vec<Vec<u8>>, usize), StreamError> {
        WalStreamCore::read_batch(self, offset as u64, count)
            .map(|(items, next)| (items, next as usize))
            .map_err(|_| StreamError::ClosedEmpty)
    }

    fn close(&self) {
        WalStreamCore::close(self);
    }

    fn is_closed(&self) -> bool {
        WalStreamCore::is_closed(self)
    }

    fn tail_offset(&self) -> usize {
        WalStreamCore::tail(self) as usize
    }

    fn msg_count(&self) -> usize {
        WalStreamCore::tail(self) as usize
    }
}

// ---------------------------------------------------------------------------
// Unit tests — in-memory MetaStore mock, no raft runtime needed.
//
// The mock mirrors the real store's contract: it — not the caller — assigns
// each append's offset (here, the current count under the prefix), so the
// tests exercise the SAME "store assigns the offset" path the raft state
// machine implements.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abc::meta_store::{FileMetadata, MetaStoreError};
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Mutex;

    #[test]
    fn wal_stream_key_round_trips_to_watch_path() {
        // Construct the key EXACTLY as WalStreamCore does (prefix + seq),
        // then recover the stream_id — the path a sys_watch is parked on.
        // This pins the observer's parse to the real key format so the two
        // cannot drift (the bug that let a plain-path test key mask the
        // real `__wal_stream__/…` shape).
        for (stream_id, seq) in [
            ("/agents/win-ai/chat-with-me", 0u64),
            ("/proc/p1/chat-with-me", 42),
        ] {
            let key = format!("{WAL_STREAM_KEY_PREFIX}{stream_id}/{seq}");
            assert_eq!(
                watch_path_from_wal_stream_key(&key),
                Some(stream_id),
                "observer must recover the watched path from the real wal key"
            );
        }
        // Pipe keys (DT_PIPE) are not A2A mailboxes → no wake.
        assert_eq!(
            watch_path_from_wal_stream_key("/__wal_pipe__//proc/p1/notify/0"),
            None
        );
        // A bare path (no prefix/seq) is not a wal key.
        assert_eq!(
            watch_path_from_wal_stream_key("/agents/x/chat-with-me"),
            None
        );
    }

    struct MemKvStore {
        inner: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl MetaStore for MemKvStore {
        fn get(&self, _path: &str) -> Result<Option<FileMetadata>, MetaStoreError> {
            Ok(None)
        }
        fn put(&self, _path: &str, _meta: FileMetadata) -> Result<(), MetaStoreError> {
            Ok(())
        }
        fn delete(&self, _path: &str) -> Result<bool, MetaStoreError> {
            Ok(false)
        }
        fn list(&self, _prefix: &str) -> Result<Vec<FileMetadata>, MetaStoreError> {
            Ok(Vec::new())
        }
        fn exists(&self, _path: &str) -> Result<bool, MetaStoreError> {
            Ok(false)
        }
        // Mirror the real store: the STORE assigns the offset (here, the count
        // of existing entries under the prefix) under a lock, so concurrent
        // writers — one core or several over the same store — never collide.
        fn append_stream_entry(
            &self,
            stream_prefix: &str,
            data: &[u8],
        ) -> Result<u64, MetaStoreError> {
            let mut inner = self.inner.lock().unwrap();
            let seq = inner.keys().filter(|k| k.starts_with(stream_prefix)).count() as u64;
            inner.insert(format!("{stream_prefix}{seq}"), data.to_vec());
            Ok(seq)
        }
        fn get_stream_entry(&self, key: &str) -> Result<Option<Vec<u8>>, MetaStoreError> {
            Ok(self.inner.lock().unwrap().get(key).cloned())
        }
        fn stream_tail(&self, stream_prefix: &str) -> Result<u64, MetaStoreError> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(stream_prefix))
                .count() as u64)
        }
    }

    fn store() -> Arc<dyn MetaStore> {
        Arc::new(MemKvStore {
            inner: Mutex::new(BTreeMap::new()),
        })
    }

    fn core() -> WalStreamCore {
        WalStreamCore::new(store(), "test".into())
    }

    /// The core keeps NO local cursor — the store owns it. A fresh instance
    /// over a store that already holds entries (a restart / failover) resumes
    /// PAST the tail on its very first read of `tail()`, and its next write
    /// lands past the existing entries instead of overwriting seq 0.
    #[test]
    fn cursor_is_store_owned_across_restart() {
        let store = store();

        // First writer instance: three durable entries at seq 0,1,2.
        {
            let c1 = WalStreamCore::new(Arc::clone(&store), "mbox".into());
            assert_eq!(c1.write_sync(b"m0").unwrap(), 0);
            assert_eq!(c1.write_sync(b"m1").unwrap(), 1);
            assert_eq!(c1.write_sync(b"m2").unwrap(), 2);
        } // c1 dropped — simulates a writer restart / failover.

        // Fresh instance over the SAME store sees the tail from the store, not
        // a local counter, so its next write is seq 3 — no overwrite.
        let c2 = WalStreamCore::new(Arc::clone(&store), "mbox".into());
        assert_eq!(c2.tail(), 3, "tail is read from the store");
        assert_eq!(
            c2.write_sync(b"m3").unwrap(),
            3,
            "post-restart write must not overwrite an existing seq"
        );
        assert_eq!(c2.read_at(0).unwrap(), Some(b"m0".to_vec()));
        assert_eq!(c2.read_at(2).unwrap(), Some(b"m2".to_vec()));
        assert_eq!(c2.read_at(3).unwrap(), Some(b"m3".to_vec()));
    }

    /// The exact multi-writer case the old client-side `next_seq` lost: TWO
    /// live cores over the SAME store, interleaved. Each write gets a distinct,
    /// gap-free offset from the store — nothing is overwritten. With the old
    /// per-core counter both would have picked seq 0 and clobbered each other.
    #[test]
    fn two_cores_same_store_never_collide() {
        let store = store();
        let a = WalStreamCore::new(Arc::clone(&store), "shared".into());
        let b = WalStreamCore::new(Arc::clone(&store), "shared".into());

        assert_eq!(a.write_sync(b"a0").unwrap(), 0);
        assert_eq!(b.write_sync(b"b1").unwrap(), 1);
        assert_eq!(a.write_sync(b"a2").unwrap(), 2);

        // All three survive at distinct offsets, visible through either core.
        assert_eq!(a.read_at(0).unwrap(), Some(b"a0".to_vec()));
        assert_eq!(b.read_at(1).unwrap(), Some(b"b1".to_vec()));
        assert_eq!(a.read_at(2).unwrap(), Some(b"a2".to_vec()));
        assert_eq!(a.tail(), 3);
        assert_eq!(b.tail(), 3);
    }

    #[test]
    fn write_then_read_single_entry() {
        let c = core();
        let seq = c.write_sync(b"hello").unwrap();
        assert_eq!(seq, 0);
        let data = c.read_at(0).unwrap().unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(c.tail(), 1);
    }

    #[test]
    fn read_past_tail_returns_none_when_open() {
        let c = core();
        c.write_sync(b"a").unwrap();
        assert_eq!(c.read_at(0).unwrap(), Some(b"a".to_vec()));
        assert_eq!(c.read_at(1).unwrap(), None);
    }

    #[test]
    fn read_past_tail_errors_when_closed() {
        let c = core();
        c.write_sync(b"a").unwrap();
        c.close();
        assert!(c.read_at(1).is_err());
    }

    #[test]
    fn write_after_close_errors() {
        let c = core();
        c.close();
        assert!(c.write_sync(b"x").is_err());
    }

    #[test]
    fn binary_data_full_byte_range() {
        let c = core();
        let payload: Vec<u8> = (0u8..=255).collect();
        c.write_sync(&payload).unwrap();
        assert_eq!(c.read_at(0).unwrap(), Some(payload));
    }

    #[test]
    fn concurrent_writes_unique_seqs() {
        let c = Arc::new(core());
        let handles: Vec<_> = (0u8..8)
            .map(|i| {
                let c = Arc::clone(&c);
                std::thread::spawn(move || c.write_sync(&[i]).unwrap())
            })
            .collect();
        let seqs: HashSet<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(seqs.len(), 8, "every concurrent write gets a distinct offset");
        assert_eq!(c.tail(), 8);
        for seq in 0..8u64 {
            assert!(c.read_at(seq).unwrap().is_some());
        }
    }
}
