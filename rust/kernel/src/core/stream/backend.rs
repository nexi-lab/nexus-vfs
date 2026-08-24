//! StreamBackend pillar — uniform interface for DT_STREAM IPC backends.
//!
//! In-memory reference impl `MemoryStreamBackend` lives in
//! `crate::stream`; SHM, stdio, WAL, and remote variants live in
//! sibling files.

#[derive(Debug)]
pub enum StreamError {
    Closed(&'static str),
    Full(usize, usize),
    Empty,
    ClosedEmpty,
    Oversized(usize, usize),
    InvalidOffset(usize, usize),
    /// Read below the retention floor: the requested offset was dropped by
    /// trimming. `(earliest, requested)` — Kafka OffsetOutOfRange. The reader
    /// should reset to `earliest`.
    Truncated(usize, usize),
}

/// Uniform interface for stream backends (memory, shared memory, future gRPC).
///
/// Enables `DashMap<String, Arc<dyn StreamBackend>>` in StreamManager for
/// heterogeneous backend dispatch.
pub trait StreamBackend: Send + Sync {
    fn push(&self, data: &[u8]) -> Result<usize, StreamError>;
    fn read_at(&self, offset: usize) -> Result<(Vec<u8>, usize), StreamError>;
    fn read_batch(&self, offset: usize, count: usize)
        -> Result<(Vec<Vec<u8>>, usize), StreamError>;
    fn close(&self);
    fn is_closed(&self) -> bool;
    fn tail_offset(&self) -> usize;
    fn msg_count(&self) -> usize;

    /// Lowest offset still readable — the retention floor. `0` for backends
    /// without retention (the default). A full scan (`collect_all`) starts here
    /// so a trimmed stream is read from its earliest surviving frame rather than
    /// from a dropped offset. Only the WAL backend with a cold tier overrides it.
    fn earliest_offset(&self) -> usize {
        0
    }

    /// Unix-ms timestamp of the most recent successful append; `None` when
    /// the stream has never been appended to, or when the backend does not
    /// track wall-clock time on push (some read-only or forwarding backends).
    /// Used by `sys_stat` to surface a stream's `modified_at_ms` field —
    /// same POSIX `st_mtime` semantic as regular files, since the metastore
    /// entry's `modified_at_ms` is not maintained for streams (writes short-
    /// circuit into the stream buffer and never touch the metastore row).
    /// Consumers include search-plugin recency scoring, audit-tier
    /// staleness checks, and cross-agent mailbox catch-up freshness gates.
    ///
    /// # Empty-append semantics
    ///
    /// `push(&[])` is a no-op — the tail does not advance, no bytes commit,
    /// and `last_append_ms` does NOT update.  Matches POSIX `st_mtime`:
    /// `write(fd, "", 0)` does not modify a file.  A caller that wants the
    /// stamp to move on every push regardless of payload can wrap the call
    /// in `if !data.is_empty()` at their layer + stamp their own clock;
    /// nothing in this trait forces the semantic.
    fn last_append_ms(&self) -> Option<i64> {
        None
    }
}
