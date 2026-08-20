//! StreamManager — owns DT_STREAM buffer registry with blocking wait.
//!
//! `DashMap<String, Arc<dyn StreamBackend>>` enables heterogeneous backends
//! (memory, shared memory, future gRPC proxy).
//!
//! Blocking read uses `parking_lot::Condvar` so the waiter parks
//! without spinning; `StreamNotify` wakes blocked readers after each
//! `push` (or after `close`).

use crate::stream::{MemoryStreamBackend, StreamBackend, StreamError};
use dashmap::DashMap;
use parking_lot::{Condvar, Mutex};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Builds a backend for a path whose local registration is missing — the seam
/// the kernel injects (via [`StreamManager::set_materializer`]) so a wal
/// DT_STREAM created on a PEER, whose entries replicated in but whose local
/// handle was never built, can be resolved on first read/write instead of
/// failing `NotFound`. `None` ⇒ not materializable here (not a replicated
/// stream / federation not wired) ⇒ the caller keeps the genuine miss.
///
/// Deliberately opaque: the manager stays a pure registry and never learns
/// about the metastore / raft / zones — that knowledge lives entirely in the
/// injected closure, so no upward dependency leaks into `core::stream`.
type StreamMaterializer = Box<dyn Fn(&str) -> Option<Arc<dyn StreamBackend>> + Send + Sync>;

// ---------------------------------------------------------------------------
// Per-stream notification
// ---------------------------------------------------------------------------

struct StreamNotify {
    mutex: Mutex<()>,
    not_empty: Condvar,
}

impl StreamNotify {
    fn new() -> Self {
        Self {
            mutex: Mutex::new(()),
            not_empty: Condvar::new(),
        }
    }

    /// Wake one blocked reader (after push). Acquires mutex to avoid
    /// lost-wakeup race — see `write_nowait` comment.
    #[inline]
    fn wake_readers(&self) {
        let _g = self.mutex.lock();
        self.not_empty.notify_one();
    }

    /// Wake all blocked readers (shutdown / close). Acquires mutex.
    #[inline]
    fn wake_all_readers(&self) {
        let _g = self.mutex.lock();
        self.not_empty.notify_all();
    }
}

// ---------------------------------------------------------------------------
// StreamManager
// ---------------------------------------------------------------------------

/// Registry of active DT_STREAM buffers with blocking wait support.
pub struct StreamManager {
    buffers: DashMap<String, Arc<dyn StreamBackend>>,
    notify: DashMap<String, Arc<StreamNotify>>,
    /// Miss-materializer injected once at federation boot. `None` on a
    /// non-federated kernel, so [`Self::resolve`] is then behaviourally
    /// identical to a bare `buffers.get` — the lazy path only ever affects
    /// federated cold reads.
    materializer: OnceLock<StreamMaterializer>,
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            buffers: DashMap::new(),
            notify: DashMap::new(),
            materializer: OnceLock::new(),
        }
    }

    /// Install the miss-materializer (once). The kernel calls this at
    /// federation boot with a closure that builds a `WalStreamCore` over the
    /// path's zone metastore. Idempotent — a second set is silently dropped.
    pub fn set_materializer(&self, f: StreamMaterializer) {
        let _ = self.materializer.set(f);
    }

    /// THE single point every data op (read/write/tail) resolves a backend
    /// through. A registry hit returns the backend; a miss delegates to the
    /// injected materializer (a peer-created wal DT_STREAM whose entries
    /// replicated in but whose local handle was never built).
    ///
    /// Routing ALL data ops through here is the invariant that makes "a new
    /// read/write op forgot to materialize" *unrepresentable*: the backend is
    /// private, so no op can reach it any other way. Lifecycle ops
    /// (`create`/`register`/`destroy`/`close`/`has`) deliberately do NOT go
    /// through here — they operate on the local registry as such.
    ///
    /// Hot path (hit) is inlined to a single `DashMap` lookup — zero call
    /// overhead vs. the pre-chokepoint code; the cold miss is out-of-line.
    #[inline]
    fn resolve(&self, path: &str) -> Option<Arc<dyn StreamBackend>> {
        if let Some(b) = self.buffers.get(path) {
            return Some(Arc::clone(b.value()));
        }
        self.materialize_miss(path)
    }

    /// Cold path of [`Self::resolve`]: ask the injected materializer, register
    /// what it built (idempotent — another thread may have won the race), and
    /// return the *canonical* registered backend. Kept `#[cold]` +
    /// `#[inline(never)]` so its bulk never bloats the inlined hot path.
    #[cold]
    #[inline(never)]
    fn materialize_miss(&self, path: &str) -> Option<Arc<dyn StreamBackend>> {
        let backend = (self.materializer.get()?)(path)?;
        // Ignore `Exists`: a concurrent resolve may have registered first.
        let _ = self.register(path, backend);
        self.buffers.get(path).map(|r| Arc::clone(r.value()))
    }

    /// Create a new in-memory stream backend and register it.
    pub fn create(&self, path: &str, capacity: usize) -> Result<(), StreamManagerError> {
        if self.buffers.contains_key(path) {
            return Err(StreamManagerError::Exists(path.to_string()));
        }
        let buf = MemoryStreamBackend::new(capacity);
        self.buffers.insert(path.to_string(), Arc::new(buf));
        self.notify
            .insert(path.to_string(), Arc::new(StreamNotify::new()));
        Ok(())
    }

    /// Register an external backend (SHM, gRPC, etc.).
    pub fn register(
        &self,
        path: &str,
        backend: Arc<dyn StreamBackend>,
    ) -> Result<(), StreamManagerError> {
        if self.buffers.contains_key(path) {
            return Err(StreamManagerError::Exists(path.to_string()));
        }
        self.buffers.insert(path.to_string(), backend);
        self.notify
            .insert(path.to_string(), Arc::new(StreamNotify::new()));
        Ok(())
    }

    /// Destroy a stream — close, notify waiters, and remove from registry.
    pub fn destroy(&self, path: &str) -> Result<(), StreamManagerError> {
        match self.buffers.remove(path) {
            Some((_, buf)) => {
                buf.close();
                if let Some((_, n)) = self.notify.remove(path) {
                    n.wake_all_readers();
                }
                Ok(())
            }
            None => Err(StreamManagerError::NotFound(path.to_string())),
        }
    }

    /// Signal close (keep in registry for drain).
    pub fn close(&self, path: &str) -> Result<(), StreamManagerError> {
        match self.buffers.get(path) {
            Some(buf) => {
                buf.close();
                if let Some(n) = self.notify.get(path) {
                    n.wake_all_readers();
                }
                Ok(())
            }
            None => Err(StreamManagerError::NotFound(path.to_string())),
        }
    }

    /// Check if a stream exists.
    pub fn has(&self, path: &str) -> bool {
        self.buffers.contains_key(path)
    }

    /// Non-blocking write. Returns byte offset.
    pub fn write_nowait(&self, path: &str, data: &[u8]) -> Result<usize, StreamManagerError> {
        let buf = self
            .resolve(path)
            .ok_or_else(|| StreamManagerError::NotFound(path.to_string()))?;
        let offset = buf.push(data).map_err(StreamManagerError::Backend)?;
        // Wake blocked readers — see StreamNotify::wake_all_readers doc.
        if let Some(notify) = self.notify.get(path) {
            notify.wake_all_readers();
        }
        Ok(offset)
    }

    /// Wake every blocking reader parked on `path` WITHOUT appending — the
    /// cross-machine apply-observer hook.
    ///
    /// A `read_at_blocking` reader parks on the per-path condvar, which is
    /// signalled only by the node-local write path ([`Self::write_nowait`]).
    /// On a **replica** a peer's `AppendStreamEntry` is materialised into the
    /// durable WAL by the raft apply loop — never `write_nowait` — so the
    /// parked reader is never signalled by the write itself. The stream-wakeup
    /// apply-observer calls this AFTER the entry is durably applied; the woken
    /// reader re-checks its offset against the now-committed WAL (through
    /// [`Self::resolve`]) and returns the new frame. This is the DT_STREAM twin
    /// of `Kernel::wake_file_watch` (which wakes the *other* cross-machine wait
    /// primitive, `sys_watch`); the A2A mailbox tail uses THIS one.
    ///
    /// Returns `false` (no-op) when no reader has ever registered `path` — the
    /// notify slot is created lazily by `create`/`register`/`resolve`, so an
    /// absent slot means nothing is parked to wake, and a later reader takes
    /// the fast path over the already-committed data.
    pub fn wake_waiters(&self, path: &str) -> bool {
        match self.notify.get(path) {
            Some(n) => {
                n.wake_all_readers();
                true
            }
            None => false,
        }
    }

    /// Read one message at byte offset. Returns (data, next_offset) or None if empty.
    pub fn read_at(
        &self,
        path: &str,
        offset: usize,
    ) -> Result<Option<(Vec<u8>, usize)>, StreamManagerError> {
        let buf = self
            .resolve(path)
            .ok_or_else(|| StreamManagerError::NotFound(path.to_string()))?;
        match buf.read_at(offset) {
            Ok((data, next)) => Ok(Some((data, next))),
            Err(StreamError::Empty) => Ok(None),
            Err(StreamError::ClosedEmpty) => Err(StreamManagerError::Closed(path.to_string())),
            Err(e) => Err(StreamManagerError::Backend(e)),
        }
    }

    /// Blocking read at offset — waits for data with Condvar.
    ///
    /// Called by `Kernel::stream_read_at_blocking`.
    pub fn read_at_blocking(
        &self,
        path: &str,
        offset: usize,
        timeout_ms: u64,
    ) -> Result<(Vec<u8>, usize), StreamManagerError> {
        let buf = self
            .resolve(path)
            .ok_or_else(|| StreamManagerError::NotFound(path.to_string()))?;
        let notify = Arc::clone(
            self.notify
                .get(path)
                .ok_or_else(|| StreamManagerError::NotFound(path.to_string()))?
                .value(),
        );

        // Fast path
        match buf.read_at(offset) {
            Ok((data, next)) => return Ok((data, next)),
            Err(StreamError::ClosedEmpty) => {
                return Err(StreamManagerError::Closed(path.to_string()));
            }
            Err(StreamError::Empty) => {}
            Err(e) => return Err(StreamManagerError::Backend(e)),
        }

        // Slow path: wait on condvar
        let timeout = Duration::from_millis(timeout_ms);
        let deadline = std::time::Instant::now() + timeout;
        let mut guard = notify.mutex.lock();

        loop {
            match buf.read_at(offset) {
                Ok((data, next)) => return Ok((data, next)),
                Err(StreamError::ClosedEmpty) => {
                    return Err(StreamManagerError::Closed(path.to_string()));
                }
                Err(StreamError::Empty) => {}
                Err(e) => return Err(StreamManagerError::Backend(e)),
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(StreamManagerError::WouldBlock(
                    "stream read timeout".to_string(),
                ));
            }
            if notify.not_empty.wait_for(&mut guard, remaining).timed_out() {
                match buf.read_at(offset) {
                    Ok((data, next)) => return Ok((data, next)),
                    Err(StreamError::ClosedEmpty) => {
                        return Err(StreamManagerError::Closed(path.to_string()));
                    }
                    _ => {
                        return Err(StreamManagerError::WouldBlock(
                            "stream read timeout".to_string(),
                        ));
                    }
                }
            }
        }
    }

    /// Read up to `count` messages starting from byte offset.
    pub fn read_batch(
        &self,
        path: &str,
        offset: usize,
        count: usize,
    ) -> Result<(Vec<Vec<u8>>, usize), StreamManagerError> {
        let buf = self
            .resolve(path)
            .ok_or_else(|| StreamManagerError::NotFound(path.to_string()))?;
        buf.read_batch(offset, count)
            .map_err(StreamManagerError::Backend)
    }

    /// Collect all message payloads from the earliest surviving offset,
    /// concatenated into one Vec.
    ///
    /// Walks the whole readable stream, joining payload bytes (without the
    /// per-frame length prefix). One kernel call replaces a per-frame `read_at`
    /// loop. Starts at `earliest_offset()` (0 for every backend except a trimmed
    /// WAL stream, whose earliest frames were dropped by retention) so a full
    /// read never begins below the retention floor and never sees `Truncated`.
    ///
    /// Returns empty Vec if the stream has no data. Used by LLM
    /// backends for the `collect_all + CAS persist` pattern after the
    /// producer finishes pumping tokens.
    pub fn collect_all_payloads(&self, path: &str) -> Result<Vec<u8>, StreamManagerError> {
        let buf = self
            .resolve(path)
            .ok_or_else(|| StreamManagerError::NotFound(path.to_string()))?;
        let tail = buf.tail_offset();
        let mut out = Vec::with_capacity(tail);
        let mut offset = buf.earliest_offset();
        loop {
            match buf.read_at(offset) {
                Ok((data, next)) => {
                    out.extend_from_slice(&data);
                    offset = next;
                }
                Err(StreamError::Empty) | Err(StreamError::ClosedEmpty) => break,
                Err(e) => return Err(StreamManagerError::Backend(e)),
            }
        }
        Ok(out)
    }

    /// Get a backend reference (for sys_read/sys_write fast-path). Resolves
    /// through the chokepoint, so a cold sys_read/sys_write of a peer-created
    /// wal stream materializes its local handle instead of missing.
    pub fn get(&self, path: &str) -> Option<Arc<dyn StreamBackend>> {
        self.resolve(path)
    }

    /// Current tail (write offset) of a registered stream.
    ///
    /// Returns `None` if no stream is registered at `path`. Callers use
    /// this for the seek-to-end pattern: `cursor = tail(path)` then
    /// `read_at(path, cursor)` skips all history and blocks for new data.
    pub fn tail(&self, path: &str) -> Option<usize> {
        self.resolve(path).map(|b| b.tail_offset())
    }

    /// Append all entries from `from` (starting at `from_offset`) into `to`.
    ///
    /// Analogous to a read-then-write splice between two DT_STREAMs. `to` must
    /// already exist. Reads `from` with `read_batch` and appends each entry to
    /// `to` with `push`. Returns `(messages_forwarded, next_from_offset)`.
    ///
    /// Non-destructive: `from` is not modified (DT_STREAM reads are always
    /// offset-based, never consuming).
    #[allow(dead_code)]
    pub fn forward(
        &self,
        from: &str,
        to: &str,
        from_offset: usize,
    ) -> Result<(usize, usize), StreamManagerError> {
        let src = self
            .resolve(from)
            .ok_or_else(|| StreamManagerError::NotFound(from.to_string()))?;
        let dst = self
            .resolve(to)
            .ok_or_else(|| StreamManagerError::NotFound(to.to_string()))?;

        let mut offset = from_offset;
        let mut forwarded = 0usize;

        loop {
            match src.read_at(offset) {
                Ok((data, next)) => {
                    dst.push(&data).map_err(StreamManagerError::Backend)?;
                    offset = next;
                    forwarded += 1;
                }
                Err(StreamError::Empty | StreamError::ClosedEmpty) => break,
                Err(e) => return Err(StreamManagerError::Backend(e)),
            }
        }

        if forwarded > 0 {
            if let Some(notify) = self.notify.get(to) {
                notify.wake_readers();
            }
        }

        Ok((forwarded, offset))
    }

    /// List all stream paths.
    pub fn list(&self) -> Vec<String> {
        self.buffers.iter().map(|r| r.key().clone()).collect()
    }

    /// Close all streams (shutdown).
    pub fn close_all(&self) {
        for entry in self.buffers.iter() {
            entry.value().close();
        }
        for entry in self.notify.iter() {
            entry.wake_all_readers();
        }
    }
}

// ---------------------------------------------------------------------------
// StreamManagerError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StreamManagerError {
    Exists(String),
    NotFound(String),
    Closed(String),
    WouldBlock(String),
    Backend(StreamError),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_collect_all_payloads_empty() {
        let sm = StreamManager::new();
        sm.create("/s/empty", 1024).unwrap();
        let data = sm.collect_all_payloads("/s/empty").unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_collect_all_payloads_single() {
        let sm = StreamManager::new();
        sm.create("/s/one", 1024).unwrap();
        sm.write_nowait("/s/one", b"hello").unwrap();
        let data = sm.collect_all_payloads("/s/one").unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_collect_all_payloads_multi() {
        let sm = StreamManager::new();
        sm.create("/s/multi", 4096).unwrap();
        sm.write_nowait("/s/multi", b"aaa").unwrap();
        sm.write_nowait("/s/multi", b"bbb").unwrap();
        sm.write_nowait("/s/multi", b"ccc").unwrap();
        let data = sm.collect_all_payloads("/s/multi").unwrap();
        assert_eq!(data, b"aaabbbccc");
    }

    #[test]
    fn test_collect_all_payloads_after_close() {
        let sm = StreamManager::new();
        sm.create("/s/closed", 1024).unwrap();
        sm.write_nowait("/s/closed", b"before").unwrap();
        sm.close("/s/closed").unwrap();
        let data = sm.collect_all_payloads("/s/closed").unwrap();
        assert_eq!(data, b"before");
    }

    #[test]
    fn test_collect_all_payloads_not_found() {
        let sm = StreamManager::new();
        let result = sm.collect_all_payloads("/s/nope");
        assert!(result.is_err());
    }

    #[test]
    fn test_tail_empty_stream() {
        let sm = StreamManager::new();
        sm.create("/s/empty", 1024).unwrap();
        assert_eq!(sm.tail("/s/empty"), Some(0));
    }

    #[test]
    fn test_tail_after_push() {
        // Frame layout is [4B u32 LE length][N bytes payload]; tail tracks
        // the post-frame write offset, so after one 5-byte push it lands at 9.
        let sm = StreamManager::new();
        sm.create("/s/one", 1024).unwrap();
        sm.write_nowait("/s/one", b"hello").unwrap();
        assert_eq!(sm.tail("/s/one"), Some(4 + 5));
        sm.write_nowait("/s/one", b"world!").unwrap();
        assert_eq!(sm.tail("/s/one"), Some(4 + 5 + 4 + 6));
    }

    #[test]
    fn test_tail_missing_path_returns_none() {
        let sm = StreamManager::new();
        assert_eq!(sm.tail("/s/nope"), None);
    }

    /// Regression test for the lost-wakeup race.
    #[test]
    fn read_at_blocking_no_lost_wakeup_under_concurrent_writes() {
        const ITERATIONS: usize = 1000;
        const READ_TIMEOUT_MS: u64 = 250;

        let mgr = Arc::new(StreamManager::new());
        // Larger capacity than pipe equivalent — stream stores all
        // messages until close, so the buffer must hold all 1000.
        mgr.create("/stream", 64 * 1024).expect("create stream");

        let writer_done = Arc::new(AtomicUsize::new(0));
        let reader_received = Arc::new(AtomicUsize::new(0));

        let writer_mgr = Arc::clone(&mgr);
        let writer_done_w = Arc::clone(&writer_done);
        let writer = thread::spawn(move || {
            for i in 0..ITERATIONS {
                if i % 4 == 0 {
                    thread::sleep(Duration::from_micros(10));
                }
                let payload = format!("msg-{i:04}").into_bytes();
                writer_mgr
                    .write_nowait("/stream", &payload)
                    .expect("write_nowait");
                writer_done_w.fetch_add(1, Ordering::Relaxed);
            }
        });

        let reader_mgr = Arc::clone(&mgr);
        let reader_received_r = Arc::clone(&reader_received);
        let reader = thread::spawn(move || {
            let mut offset = 0usize;
            let mut got = 0usize;
            while got < ITERATIONS {
                match reader_mgr.read_at_blocking("/stream", offset, READ_TIMEOUT_MS) {
                    Ok((_data, next)) => {
                        offset = next;
                        got += 1;
                        reader_received_r.store(got, Ordering::Relaxed);
                    }
                    Err(StreamManagerError::WouldBlock(_)) => {
                        panic!("reader timed out after {got} reads; lost-wakeup race regression?");
                    }
                    Err(e) => panic!("reader failed: {e:?}"),
                }
            }
        });

        writer.join().expect("writer thread");
        reader.join().expect("reader thread");

        assert_eq!(writer_done.load(Ordering::Relaxed), ITERATIONS);
        assert_eq!(reader_received.load(Ordering::Relaxed), ITERATIONS);

        mgr.destroy("/stream").expect("destroy");
    }

    /// Sanity check that destroy() wakes a parked blocking reader
    /// instead of leaving it stuck until timeout.
    #[test]
    fn read_at_blocking_wakes_on_destroy() {
        let mgr = Arc::new(StreamManager::new());
        mgr.create("/closeme", 1024).expect("create");

        let reader_mgr = Arc::clone(&mgr);
        let reader = thread::spawn(move || {
            // Long timeout — must return early on destroy notification.
            reader_mgr.read_at_blocking("/closeme", 0, 30_000)
        });

        thread::sleep(Duration::from_millis(50));

        mgr.destroy("/closeme").expect("destroy");

        let result = reader.join().expect("reader thread");
        match result {
            Err(StreamManagerError::Closed(_)) => {}
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    /// Regression for the cross-machine A2A tail wake.
    ///
    /// On a **replica**, a peer's `AppendStreamEntry` is materialised into the
    /// backend by the raft apply loop — NOT [`StreamManager::write_nowait`] —
    /// so the backend gains a frame WITHOUT the condvar signal a local write
    /// carries. A `read_at_blocking` tail parked there is therefore never woken
    /// by the write itself; the stream-wakeup apply-observer must signal it via
    /// [`StreamManager::wake_waiters`]. This test reproduces that exact
    /// decoupling: it pushes straight into the backend (the out-of-band apply
    /// path) and then relies SOLELY on `wake_waiters` to wake the reader —
    /// `write_nowait` is never called, so a no-op `wake_waiters` would leave
    /// the reader parked until its timeout and fail the test.
    #[test]
    fn wake_waiters_wakes_a_reader_over_an_out_of_band_backend_push() {
        let path = "/agents/peer/chat-with-me";
        let backend = Arc::new(MemoryStreamBackend::new(4096));
        let sm = Arc::new(StreamManager::new());
        // `register` keeps the notify slot the reader parks on; we retain the
        // backend Arc to push into it out-of-band (the raft apply loop's role).
        sm.register(path, backend.clone())
            .expect("register backend");

        let reader_sm = Arc::clone(&sm);
        let reader = thread::spawn(move || {
            // Empty at offset 0 → the reader parks on the condvar. Timeout is
            // the failure backstop: a broken `wake_waiters` surfaces as
            // `WouldBlock` here rather than hanging the suite.
            reader_sm.read_at_blocking(path, 0, 3_000)
        });
        // Let the reader actually reach the condvar wait before the frame lands.
        thread::sleep(Duration::from_millis(100));

        // Out-of-band materialisation: the frame is now readable, but nothing
        // signalled the condvar (this is the replica apply path, not a write).
        backend.push(b"from-a-peer").expect("apply-side push");

        // The observer's wake is the SOLE waker — proves the fix end to end.
        assert!(
            sm.wake_waiters(path),
            "wake_waiters must find the registered notify slot"
        );
        let (data, _next) = reader
            .join()
            .expect("reader thread")
            .expect("reader must wake via wake_waiters and read the out-of-band frame");
        assert_eq!(data, b"from-a-peer");

        // No slot for an unknown path → no-op, reported as false.
        assert!(!sm.wake_waiters("/agents/nobody/chat-with-me"));
    }
}
