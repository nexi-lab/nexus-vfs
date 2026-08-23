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

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

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

/// Cold-tier blob store for sealed WAL DT_STREAM segments — the content half of
/// tiered storage, injected by the kernel so `WalStreamCore` never reaches up
/// into the VFS router / CAS engine / peer client. It only knows "write these
/// bytes, get back an id" and "read the blob for this id (local content store,
/// else a whole-blob fetch from the seal node)". The kernel impl composes the
/// SAME path a DT_REG file's content takes: local `ObjectStore::write_content` /
/// `read_content`, and a `ReadBlob` peer fetch from `origin` on a local miss.
pub trait ColdSegmentStore: Send + Sync {
    /// This node's advertise address — recorded as a sealed segment's fetch
    /// `origin`. `None` on a node without a published address (single-node).
    fn self_origin(&self) -> Option<String>;

    /// Write a sealed segment blob for `stream_id` and return the content-store
    /// id to record in the segment index. `base` disambiguates path-addressed
    /// backends (content-addressed ones derive the id from the bytes and ignore
    /// it).
    fn write_segment(&self, stream_id: &str, base: u64, bytes: &[u8]) -> Result<String, String>;

    /// Read a sealed segment blob by `content_id`: local content store first,
    /// else a whole-blob peer fetch from `origin` (the node that sealed it).
    fn read_segment(
        &self,
        stream_id: &str,
        content_id: &str,
        origin: &str,
    ) -> Result<Vec<u8>, String>;
}

/// When to roll the hot tail into a cold segment. Mirrors Kafka's active-segment
/// sizing: keep the most-recent `hot_window` seqs hot (local, wakeup-driving),
/// and once the tail runs `seal_batch` past that, seal a `seal_batch`-sized
/// range off the front.
#[derive(Clone, Copy, Debug)]
pub struct SealPolicy {
    /// Seqs kept hot (never sealed) — the tail-follow + wakeup window.
    pub hot_window: u64,
    /// Seqs sealed per roll, once `tail >= floor + hot_window + seal_batch`.
    pub seal_batch: u64,
}

impl SealPolicy {
    /// Production keep-forever default: a 1024-seq hot window, 512-seq rolls.
    /// Overridable via `NEXUS_STREAM_HOT_WINDOW` / `NEXUS_STREAM_SEAL_BATCH`.
    pub const KEEP_FOREVER: SealPolicy = SealPolicy {
        hot_window: 1024,
        seal_batch: 512,
    };

    /// Whether sealing is enabled at all (a zero batch = never seal).
    fn seals(&self) -> bool {
        self.seal_batch > 0
    }
}

/// 4-byte magic prefixing every segment blob, so a corrupt / wrong blob fails
/// loud on extract instead of returning garbage bytes.
const SEGMENT_MAGIC: &[u8; 4] = b"NXS1";

/// Serialize frames `[base, base+frames.len())` into one immutable segment blob.
///
/// Layout (all big-endian): `[magic 4][base u64][count u32][len u32 × count]
/// [payloads…]`. The per-frame length table makes `extract_frame` O(1) in
/// position (`seq - base`) instead of walking length-prefixed frames.
fn encode_segment(base: u64, frames: &[Vec<u8>]) -> Vec<u8> {
    let payload_bytes: usize = frames.iter().map(|f| f.len()).sum();
    let mut out = Vec::with_capacity(4 + 8 + 4 + frames.len() * 4 + payload_bytes);
    out.extend_from_slice(SEGMENT_MAGIC);
    out.extend_from_slice(&base.to_be_bytes());
    out.extend_from_slice(&(frames.len() as u32).to_be_bytes());
    for f in frames {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
    }
    for f in frames {
        out.extend_from_slice(f);
    }
    out
}

/// Extract the frame at absolute `seq` from a segment blob whose declared base
/// is `base`. Fails loud on a bad magic, a base mismatch (wrong blob for this
/// index entry), an out-of-range seq, or a truncated body — a cold read must
/// never silently return the wrong bytes.
fn extract_frame(blob: &[u8], base: u64, seq: u64) -> Result<Vec<u8>, String> {
    if blob.len() < 16 || &blob[0..4] != SEGMENT_MAGIC {
        return Err("segment blob: bad magic / too short".to_string());
    }
    let blob_base = u64::from_be_bytes(blob[4..12].try_into().unwrap());
    if blob_base != base {
        return Err(format!(
            "segment blob base {blob_base} != index base {base} (wrong blob)"
        ));
    }
    let count = u32::from_be_bytes(blob[12..16].try_into().unwrap()) as u64;
    if seq < base || seq >= base + count {
        return Err(format!(
            "seq {seq} out of segment range [{base}, {})",
            base + count
        ));
    }
    let idx = (seq - base) as usize;
    let count = count as usize;
    let lens_start = 16usize;
    let payloads_start = lens_start + count * 4;
    if blob.len() < payloads_start {
        return Err("segment blob: truncated length table".to_string());
    }
    // Sum lengths before idx to find this frame's offset; read idx's length.
    let mut offset = payloads_start;
    let mut this_len = 0usize;
    for i in 0..=idx {
        let l = u32::from_be_bytes(
            blob[lens_start + i * 4..lens_start + i * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if i == idx {
            this_len = l;
        } else {
            offset += l;
        }
    }
    let end = offset
        .checked_add(this_len)
        .ok_or("segment blob: length overflow")?;
    if blob.len() < end {
        return Err("segment blob: truncated payload".to_string());
    }
    Ok(blob[offset..end].to_vec())
}

/// WAL-backed stream core. Every write is proposed through the distributed
/// `MetaStore`, which assigns the offset and commits it before `write_sync`
/// returns; `read_at` reads committed entries back by offset — transparently
/// from the hot side-table or, for seqs below the seal floor, from a cold
/// segment. Holds no durable local state beyond the `closed` flag — entries,
/// their cursor, the floor, and the segment index all live in the store (the
/// raft state machine), the single source of truth. The cold-tier fields are
/// pure runtime accelerators (a seal guard + a one-segment read cache).
pub struct WalStreamCore {
    store: Arc<dyn MetaStore>,
    stream_id: String,
    prefix: String,
    closed: AtomicBool,
    /// Cold tier. `None` ⇒ hot-only (pre-P1 behaviour, unbounded-in-raft);
    /// `Some` ⇒ seal+spill enabled. The kernel injects it for wal streams.
    cold: Option<Arc<dyn ColdSegmentStore>>,
    /// Roll thresholds (only consulted when `cold` is `Some`).
    policy: SealPolicy,
    /// At-most-one-seal-in-flight guard per stream — a push spawns a background
    /// seal only when this flips false→true, and the seal thread clears it.
    seal_in_flight: Arc<AtomicBool>,
    /// Last floor this node observed, so the push-side seal gate is a cheap
    /// atomic compare — no metastore round-trip per append. Advisory: the
    /// authoritative floor is re-read inside the seal thread.
    known_floor: Arc<AtomicU64>,
    /// Last cold segment fetched, cached so a scan across cold data (e.g.
    /// `collect_all`) fetches+parses each segment once, not once per frame.
    seg_cache: Arc<Mutex<Option<CachedSegment>>>,
    /// Cold-storage retention in bytes. `0` ⇒ keep-forever (the default, and
    /// what audit/transcript use). `>0` ⇒ trim: once sealed cold storage exceeds
    /// this, the seal thread drops the oldest segments and advances `earliest`.
    /// From the stream's inode capacity.
    retention: u64,
    /// Unix-ms of the last successful push, stamped locally on each
    /// commit.  `0` sentinel = never appended locally (this replica
    /// may have received frames via raft replay before ever taking a
    /// leader-side write; consumers should treat `None` as "unknown"
    /// and fall back to the metastore's `modified_at_ms` if any).
    /// Read via [`StreamBackend::last_append_ms`] — surfaced through
    /// `sys_stat` for search recency / audit staleness / mailbox
    /// catch-up freshness gates.  Wall-clock, not raft-committed,
    /// because it is a per-replica cache; a global "when did any
    /// replica last accept a push" would need a raft-replicated
    /// field on the WAL frame itself (out of scope here).
    last_append_ms: AtomicI64,
}

/// One cached cold segment: `(base, end, blob)`. The `blob` is shared so the
/// cache and an in-flight extract can hold it without a copy.
type CachedSegment = (u64, u64, Arc<Vec<u8>>);

impl WalStreamCore {
    /// Hot-only WAL core — no cold tier, so it never seals (the pre-P1
    /// unbounded-in-raft behaviour). Used by non-federated callers and by every
    /// existing unit test.
    pub fn new(store: Arc<dyn MetaStore>, stream_id: String) -> Self {
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}{stream_id}/");
        Self {
            store,
            stream_id,
            prefix,
            closed: AtomicBool::new(false),
            cold: None,
            policy: SealPolicy::KEEP_FOREVER,
            seal_in_flight: Arc::new(AtomicBool::new(false)),
            known_floor: Arc::new(AtomicU64::new(0)),
            seg_cache: Arc::new(Mutex::new(None)),
            retention: 0,
            last_append_ms: AtomicI64::new(0),
        }
    }

    /// WAL core with tiered storage: appends past `policy.hot_window +
    /// seal_batch` roll off the front into cold segments stored via `cold`,
    /// bounding the raft state machine. `retention` bytes bound the cold storage
    /// (`0` = keep-forever). The kernel injects this for federated wal streams.
    pub fn with_cold_tier(
        store: Arc<dyn MetaStore>,
        stream_id: String,
        cold: Arc<dyn ColdSegmentStore>,
        policy: SealPolicy,
        retention: u64,
    ) -> Self {
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}{stream_id}/");
        Self {
            store,
            stream_id,
            prefix,
            closed: AtomicBool::new(false),
            cold: Some(cold),
            policy,
            seal_in_flight: Arc::new(AtomicBool::new(false)),
            known_floor: Arc::new(AtomicU64::new(0)),
            seg_cache: Arc::new(Mutex::new(None)),
            retention,
            last_append_ms: AtomicI64::new(0),
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
        // Hot path unchanged: try the entry row first (local, O(1), drives
        // wakeup). A hit returns immediately — no floor/segment lookup.
        if let Some(bytes) = self
            .store
            .get_stream_entry(&key)
            .map_err(|e| format!("get_stream_entry({key}): {e:?}"))?
        {
            return Ok(Some(bytes));
        }
        // Hot miss. With a cold tier wired, a seq below the seal floor was
        // spilled to a segment — resolve it transparently (ABI unchanged). A
        // seq whose segment was trimmed by retention has no index entry, so
        // `read_cold` returns `Ok(None)`; the StreamBackend wrapper reports it as
        // `Truncated` (it can tell trimmed from not-yet-written via `earliest`).
        if let Some(cold) = &self.cold {
            let floor = self
                .store
                .stream_floor(&self.prefix)
                .map_err(|e| format!("stream_floor({}): {e:?}", self.prefix))?;
            if seq < floor {
                return self.read_cold(seq, cold.as_ref());
            }
        }
        // Genuinely absent: not yet written (open) or closed for good.
        if self.closed.load(Ordering::Acquire) {
            Err(format!("WAL stream {} closed at seq {seq}", self.stream_id))
        } else {
            Ok(None)
        }
    }

    /// Resolve a spilled seq from the cold tier: the one-segment cache, else look
    /// up the segment index, fetch the blob (local content store, else a peer
    /// fetch from its seal origin), extract the frame, and cache the blob for the
    /// next consecutive cold read. `Ok(None)` when no segment indexes the seq —
    /// it was trimmed by retention (the caller surfaces `Truncated`).
    fn read_cold(&self, seq: u64, cold: &dyn ColdSegmentStore) -> Result<Option<Vec<u8>>, String> {
        {
            let guard = self.seg_cache.lock();
            if let Some((base, end, blob)) = guard.as_ref() {
                if *base <= seq && seq < *end {
                    return extract_frame(blob.as_slice(), *base, seq).map(Some);
                }
            }
        }
        let seg = match self
            .store
            .find_stream_segment(&self.prefix, seq)
            .map_err(|e| format!("find_stream_segment({}, {seq}): {e:?}", self.prefix))?
        {
            Some(seg) => seg,
            None => return Ok(None), // trimmed by retention
        };
        let blob = Arc::new(cold.read_segment(&self.stream_id, &seg.content_id, &seg.origin)?);
        let out = extract_frame(blob.as_slice(), seg.base, seq)?;
        *self.seg_cache.lock() = Some((seg.base, seg.end, blob));
        Ok(Some(out))
    }

    /// Push-side seal gate. A cheap atomic check (`tail` vs. the last-known
    /// floor + window), then — at most one at a time — spawn a background thread
    /// to roll the hot tail into cold segments. Off the append hot path: the
    /// caller does not wait for the seal.
    fn maybe_trigger_seal(&self, tail: u64) {
        let Some(cold) = self.cold.as_ref() else {
            return;
        };
        if !self.policy.seals() {
            return;
        }
        let floor = self.known_floor.load(Ordering::Relaxed);
        let threshold = floor
            .saturating_add(self.policy.hot_window)
            .saturating_add(self.policy.seal_batch);
        if tail < threshold {
            return;
        }
        if self.seal_in_flight.swap(true, Ordering::AcqRel) {
            return; // a seal is already running for this stream
        }
        let store = Arc::clone(&self.store);
        let cold = Arc::clone(cold);
        let prefix = self.prefix.clone();
        let stream_id = self.stream_id.clone();
        let policy = self.policy;
        let in_flight = Arc::clone(&self.seal_in_flight);
        let known_floor = Arc::clone(&self.known_floor);
        let retention = self.retention;
        std::thread::spawn(move || {
            seal_loop(
                &store,
                cold.as_ref(),
                &prefix,
                &stream_id,
                policy,
                &known_floor,
                retention,
            );
            in_flight.store(false, Ordering::Release);
        });
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

/// Drain the hot tail down to the hot window, one contiguous `seal_batch` at a
/// time, on a background thread. Each pass reads the AUTHORITATIVE floor + tail
/// (never a stale local guess), stops once within the window, else serializes
/// `[base, base+seal_batch)` → writes the blob to the cold store → proposes
/// `SealStreamSegment`. Stops on the first non-progress — nothing to seal, a
/// racing peer seal (a read gap or a gate-rejected propose), or a cold-store /
/// leader error — so it can never spin, and the next append re-triggers it.
fn seal_loop(
    store: &Arc<dyn MetaStore>,
    cold: &dyn ColdSegmentStore,
    prefix: &str,
    stream_id: &str,
    policy: SealPolicy,
    known_floor: &AtomicU64,
    retention: u64,
) {
    loop {
        let floor = match store.stream_floor(prefix) {
            Ok(f) => f,
            Err(_) => return,
        };
        known_floor.store(floor, Ordering::Relaxed);
        let tail = match store.stream_tail(prefix) {
            Ok(t) => t,
            Err(_) => return,
        };
        let threshold = floor
            .saturating_add(policy.hot_window)
            .saturating_add(policy.seal_batch);
        if tail < threshold {
            return; // caught up to within the hot window
        }
        let base = floor;
        let end = base + policy.seal_batch;

        // Collect the frames to seal. A `None`/`Err` means a race (a peer sealed
        // this range, or the row isn't materialized here) — abort; re-triggered
        // on the next append.
        let mut frames = Vec::with_capacity(policy.seal_batch as usize);
        for seq in base..end {
            match store.get_stream_entry(&format!("{prefix}{seq}")) {
                Ok(Some(bytes)) => frames.push(bytes),
                _ => return,
            }
        }

        let blob = encode_segment(base, &frames);
        let content_id = match cold.write_segment(stream_id, base, &blob) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    stream_id,
                    error = %e,
                    "wal DT_STREAM cold segment write failed; retrying on next append"
                );
                return;
            }
        };
        let origin = cold.self_origin().unwrap_or_default();
        match store.seal_stream_segment(prefix, base, end, &content_id, &origin, blob.len() as u64)
        {
            Ok(()) => {
                tracing::info!(
                    stream_id,
                    base,
                    end,
                    bytes = blob.len(),
                    "wal DT_STREAM sealed cold segment"
                );
                known_floor.store(end, Ordering::Relaxed);
                // Retention: after adding cold bytes, drop the oldest segments
                // if the stream is over its cold-storage budget.
                if retention > 0 {
                    maybe_trim(store, prefix, stream_id, retention);
                }
                // Loop: seal the next batch if the tail is still past the window.
            }
            Err(e) => {
                // Gate rejection (a peer already sealed) or no reachable leader —
                // stop; the re-read floor next pass reflects reality.
                tracing::debug!(
                    stream_id,
                    error = ?e,
                    "wal DT_STREAM seal not applied; ending this pass"
                );
                return;
            }
        }
    }
}

/// Retention trim: if the stream's total cold-segment bytes exceed `retention`,
/// drop the oldest whole segments until it fits, then propose
/// `trim_stream_segments` (advances `earliest`, deletes the index entries, and
/// carries the dropped blobs' refs so each node's trim-GC observer reclaims the
/// blobs it owns). The trimmer only proposes — it does NOT delete blobs itself,
/// so single- and multi-origin streams reclaim uniformly via the observers.
fn maybe_trim(store: &Arc<dyn MetaStore>, prefix: &str, stream_id: &str, retention: u64) {
    let segs = match store.list_stream_segments(prefix) {
        Ok(s) => s,
        Err(_) => return,
    };
    let total: u64 = segs.iter().map(|s| s.size).sum();
    if total <= retention {
        return;
    }
    // Drop oldest-first until the remaining cold bytes fit the budget.
    let mut remaining = total;
    let mut up_to = 0u64;
    let mut trimmed: Vec<(String, String)> = Vec::new();
    for seg in &segs {
        if remaining <= retention {
            break;
        }
        remaining -= seg.size;
        up_to = seg.end;
        trimmed.push((seg.origin.clone(), seg.content_id.clone()));
    }
    if up_to == 0 {
        return; // nothing whole to drop
    }
    let dropped = trimmed.len();
    match store.trim_stream_segments(prefix, up_to, trimmed) {
        Ok(()) => tracing::info!(
            stream_id,
            up_to,
            dropped,
            kept_bytes = remaining,
            "wal DT_STREAM trimmed cold segments"
        ),
        Err(e) => tracing::debug!(
            stream_id,
            error = ?e,
            "wal DT_STREAM trim not applied (racing trim / no leader)"
        ),
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
        match self.write_sync(data) {
            Ok(seq) => {
                // The tail is now `seq + 1`. Consider rolling the hot tail into a
                // cold segment — off the hot path (this returns immediately; the
                // seal, if any, runs on a background thread).
                self.maybe_trigger_seal(seq + 1);
                // Stamp local wall-clock so sys_stat surfaces a live
                // last-append time; see the field doc for the
                // per-replica vs global caveat.  Uses the shared
                // fetch_max helper — write_sync is serialised at the
                // metastore layer per stream, but two write_syncs on
                // DIFFERENT streams could still race in stamping if
                // they hit the same `AtomicI64`; fetch_max keeps the
                // monotonic contract identical to shm/mem.
                crate::stream::stamp_now_monotonic(&self.last_append_ms);
                Ok(seq as usize)
            }
            Err(e) => {
                tracing::warn!(
                    stream_id = %self.stream_id,
                    error = %e,
                    "wal DT_STREAM push failed to replicate — write rejected (fail-loud)"
                );
                Err(StreamError::Closed(
                    "wal DT_STREAM push failed to replicate (no reachable leader?)",
                ))
            }
        }
    }

    fn read_at(&self, offset: usize) -> Result<(Vec<u8>, usize), StreamError> {
        match WalStreamCore::read_at(self, offset as u64) {
            Ok(Some(data)) => Ok((data, offset + 1)),
            // A miss is either "not written yet" (park a tail reader) or
            // "retention-trimmed" (below `earliest`). Only a trimming cold tier
            // can produce the latter, so consult `earliest` to distinguish and
            // surface a clean Truncated (OffsetOutOfRange) instead of Empty.
            Ok(None) => {
                let earliest = self.earliest_offset();
                if self.cold.is_some() && offset < earliest {
                    Err(StreamError::Truncated(earliest, offset))
                } else {
                    Err(StreamError::Empty)
                }
            }
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

    fn last_append_ms(&self) -> Option<i64> {
        // `0` sentinel = never appended on this replica.  A follower
        // replaying raft-committed frames does NOT bump this — the
        // stamp reflects a locally-accepted push, per the field doc.
        match self.last_append_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        }
    }

    fn earliest_offset(&self) -> usize {
        // Only a trimming cold tier has an earliest > 0; otherwise 0 (unchanged).
        if self.cold.is_none() {
            return 0;
        }
        self.store.stream_earliest(&self.prefix).unwrap_or(0) as usize
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
    use crate::abc::meta_store::{FileMetadata, MetaStoreError, StreamSegment};
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Mutex;
    use std::time::Duration;

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

    /// Faithful in-memory mirror of the raft SM's stream side-table: a flat
    /// entry map (key `{prefix}{seq}`) plus per-prefix tail / floor cursors and a
    /// segment index — so append assigns the offset, seal deletes the sealed
    /// rows + advances the floor under the same base==floor gate, and cold reads
    /// resolve through `find_stream_segment`, exactly as `FullStateMachine` does.
    #[derive(Default)]
    struct StreamKv {
        entries: BTreeMap<String, Vec<u8>>,
        tails: BTreeMap<String, u64>,
        floors: BTreeMap<String, u64>,
        earliests: BTreeMap<String, u64>,
        segments: BTreeMap<(String, u64), StreamSegment>,
    }

    struct MemKvStore {
        inner: Mutex<StreamKv>,
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
        // The STORE assigns the offset from the tail cursor under a lock, so
        // concurrent writers — one core or several over the same store — never
        // collide.
        fn append_stream_entry(
            &self,
            stream_prefix: &str,
            data: &[u8],
        ) -> Result<u64, MetaStoreError> {
            let mut i = self.inner.lock().unwrap();
            let seq = *i.tails.get(stream_prefix).unwrap_or(&0);
            i.entries
                .insert(format!("{stream_prefix}{seq}"), data.to_vec());
            i.tails.insert(stream_prefix.to_string(), seq + 1);
            Ok(seq)
        }
        fn get_stream_entry(&self, key: &str) -> Result<Option<Vec<u8>>, MetaStoreError> {
            Ok(self.inner.lock().unwrap().entries.get(key).cloned())
        }
        fn stream_tail(&self, stream_prefix: &str) -> Result<u64, MetaStoreError> {
            Ok(*self
                .inner
                .lock()
                .unwrap()
                .tails
                .get(stream_prefix)
                .unwrap_or(&0))
        }
        fn stream_floor(&self, stream_prefix: &str) -> Result<u64, MetaStoreError> {
            Ok(*self
                .inner
                .lock()
                .unwrap()
                .floors
                .get(stream_prefix)
                .unwrap_or(&0))
        }
        fn seal_stream_segment(
            &self,
            stream_prefix: &str,
            base: u64,
            end: u64,
            content_id: &str,
            origin: &str,
            size: u64,
        ) -> Result<(), MetaStoreError> {
            let mut i = self.inner.lock().unwrap();
            let floor = *i.floors.get(stream_prefix).unwrap_or(&0);
            let tail = *i.tails.get(stream_prefix).unwrap_or(&0);
            if base != floor || end <= base || end > tail {
                return Err(MetaStoreError::IOError(format!(
                    "stale/invalid seal [{base},{end}) floor={floor} tail={tail}"
                )));
            }
            i.segments.insert(
                (stream_prefix.to_string(), base),
                StreamSegment {
                    base,
                    end,
                    content_id: content_id.to_string(),
                    origin: origin.to_string(),
                    size,
                },
            );
            for seq in base..end {
                i.entries.remove(&format!("{stream_prefix}{seq}"));
            }
            i.floors.insert(stream_prefix.to_string(), end);
            Ok(())
        }
        fn find_stream_segment(
            &self,
            stream_prefix: &str,
            seq: u64,
        ) -> Result<Option<StreamSegment>, MetaStoreError> {
            let i = self.inner.lock().unwrap();
            Ok(i.segments
                .iter()
                .filter(|((p, _), _)| p == stream_prefix)
                .map(|(_, seg)| seg)
                .find(|seg| seg.base <= seq && seq < seg.end)
                .cloned())
        }
        fn stream_earliest(&self, stream_prefix: &str) -> Result<u64, MetaStoreError> {
            Ok(*self
                .inner
                .lock()
                .unwrap()
                .earliests
                .get(stream_prefix)
                .unwrap_or(&0))
        }
        fn list_stream_segments(
            &self,
            stream_prefix: &str,
        ) -> Result<Vec<StreamSegment>, MetaStoreError> {
            let i = self.inner.lock().unwrap();
            Ok(i.segments
                .iter()
                .filter(|((p, _), _)| p == stream_prefix)
                .map(|(_, seg)| seg.clone())
                .collect())
        }
        fn trim_stream_segments(
            &self,
            stream_prefix: &str,
            up_to_seq: u64,
            _trimmed: Vec<(String, String)>,
        ) -> Result<(), MetaStoreError> {
            let mut i = self.inner.lock().unwrap();
            let earliest = *i.earliests.get(stream_prefix).unwrap_or(&0);
            let floor = *i.floors.get(stream_prefix).unwrap_or(&0);
            if up_to_seq <= earliest || up_to_seq > floor {
                return Err(MetaStoreError::IOError(format!(
                    "stale/invalid trim up_to={up_to_seq} earliest={earliest} floor={floor}"
                )));
            }
            i.segments
                .retain(|(p, _), seg| p != stream_prefix || seg.end > up_to_seq);
            i.earliests.insert(stream_prefix.to_string(), up_to_seq);
            Ok(())
        }
    }

    /// Content-addressed in-memory cold store: `write_segment` hashes the bytes
    /// (so identical blobs dedup), `read_segment` returns them; `origin` is fixed
    /// so tests can assert it round-trips. Local-only (no peer leg needed for
    /// unit tests — the cross-node fetch is covered by the live e2e).
    #[derive(Default)]
    struct MockCold {
        blobs: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        origin: Option<String>,
    }

    fn content_id_of(bytes: &[u8]) -> String {
        // Small FNV-1a — deterministic + content-derived, enough for test dedup.
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        format!("seg-{h:016x}")
    }

    impl ColdSegmentStore for MockCold {
        fn self_origin(&self) -> Option<String> {
            self.origin.clone()
        }
        fn write_segment(
            &self,
            _stream_id: &str,
            _base: u64,
            bytes: &[u8],
        ) -> Result<String, String> {
            let id = content_id_of(bytes);
            self.blobs
                .lock()
                .unwrap()
                .insert(id.clone(), bytes.to_vec());
            Ok(id)
        }
        fn read_segment(
            &self,
            _stream_id: &str,
            content_id: &str,
            _origin: &str,
        ) -> Result<Vec<u8>, String> {
            self.blobs
                .lock()
                .unwrap()
                .get(content_id)
                .cloned()
                .ok_or_else(|| format!("mock cold: no blob {content_id}"))
        }
    }

    fn store() -> Arc<dyn MetaStore> {
        Arc::new(MemKvStore {
            inner: Mutex::new(StreamKv::default()),
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

    /// WAL push via the `StreamBackend` trait MUST stamp
    /// `last_append_ms` so `sys_stat.modified_at_ms` surfaces a
    /// live per-replica wall-clock — the parity contract the mem +
    /// shm backends implement.  Pre-fix the trait's `push` inlined
    /// its own clock-fetch (DRY debt); the shared
    /// `stream::stamp_now_monotonic` now provides the fetch_max
    /// monotonic guarantee for all three backends.
    #[test]
    fn push_via_streambackend_stamps_last_append_ms() {
        use crate::stream::StreamBackend;
        let c = core();
        let backend: &dyn StreamBackend = &c;
        assert_eq!(
            backend.last_append_ms(),
            None,
            "never-appended WAL stream must surface None",
        );

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        backend.push(b"hello").expect("push via trait");
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let stamped = backend.last_append_ms().expect("stamp must be Some");
        assert!(
            before <= stamped && stamped <= after,
            "stamp {stamped} must lie in [{before}, {after}]",
        );
    }

    /// Pin the intentional "per-replica, non-durable" contract of
    /// WAL `last_append_ms`.  A fresh core over the SAME store (=
    /// simulated restart) sees no stamp — the wall-clock stamp is
    /// per-instance in-memory, so post-restart `sys_stat` surfaces
    /// `None` for `modified_at_ms` until the next local push
    /// stamps it again.  Persisting the stamp would require a WAL
    /// schema field (rejected — the same "last append" wall-clock
    /// diverges across replicas anyway, so a durable value would
    /// be misleading).
    #[test]
    fn last_append_ms_is_per_replica_and_does_not_survive_restart() {
        use crate::stream::StreamBackend;
        let store = store();
        {
            let c1 = WalStreamCore::new(Arc::clone(&store), "restart-test".into());
            let backend: &dyn StreamBackend = &c1;
            backend.push(b"first").expect("push");
            assert!(
                backend.last_append_ms().is_some(),
                "post-push stamp must be Some on the writing instance",
            );
        }
        // Fresh instance over the SAME durable store.
        let c2 = WalStreamCore::new(Arc::clone(&store), "restart-test".into());
        assert_eq!(
            c2.tail(),
            1,
            "durable entries survive restart (contract from cursor_is_store_owned_across_restart)",
        );
        let backend2: &dyn StreamBackend = &c2;
        assert_eq!(
            backend2.last_append_ms(),
            None,
            "wall-clock stamp is per-replica in-memory; must reset to None on fresh instance",
        );
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
        assert_eq!(
            seqs.len(),
            8,
            "every concurrent write gets a distinct offset"
        );
        assert_eq!(c.tail(), 8);
        for seq in 0..8u64 {
            assert!(c.read_at(seq).unwrap().is_some());
        }
    }

    // ── Cold tier (tiered storage) ──────────────────────────────────────

    /// Segment framing round-trips every frame by absolute seq, and fails LOUD
    /// (never returns wrong bytes) on a bad magic, a base mismatch, or an
    /// out-of-range seq.
    #[test]
    fn segment_encode_extract_roundtrip_and_fails_loud() {
        let frames = vec![
            b"a".to_vec(),
            b"bb".to_vec(),
            Vec::new(), // empty payload is a valid frame
            b"cccc".to_vec(),
        ];
        let blob = encode_segment(10, &frames);
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(extract_frame(&blob, 10, 10 + i as u64).unwrap(), *f);
        }
        // Fail-loud: below base, past the range, wrong base, corrupt magic.
        assert!(extract_frame(&blob, 10, 9).is_err());
        assert!(extract_frame(&blob, 10, 14).is_err());
        assert!(extract_frame(&blob, 11, 11).is_err());
        let mut bad = blob.clone();
        bad[0] = b'X';
        assert!(extract_frame(&bad, 10, 10).is_err());
    }

    /// The whole P1 contract through the WAL core: append past the window, seal
    /// (deterministically via `seal_loop`), and read the ENTIRE log back
    /// byte-exact — early seqs transparently from cold segments, recent ones
    /// hot — while the hot side-table is bounded to the window.
    #[test]
    fn seal_spills_and_cold_read_reconstructs_the_full_log() {
        let store = store();
        let cold: Arc<dyn ColdSegmentStore> = Arc::new(MockCold {
            origin: Some("node-a".into()),
            ..Default::default()
        });
        let policy = SealPolicy {
            hot_window: 3,
            seal_batch: 3,
        };
        let c = WalStreamCore::with_cold_tier(
            Arc::clone(&store),
            "coldtest".into(),
            Arc::clone(&cold),
            policy,
            0, // keep-forever (no trim)
        );
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}coldtest/");

        // 10 durable appends (via write_sync — no background trigger, so the
        // seal below is deterministic).
        for i in 0..10u64 {
            assert_eq!(c.write_sync(format!("m{i}").as_bytes()).unwrap(), i);
        }

        // Seal synchronously: drains [0,3) then [3,6); [6,10) stays hot
        // (10 - 6 = 4 < hot_window + seal_batch = 6).
        let kf = AtomicU64::new(0);
        seal_loop(&store, cold.as_ref(), &prefix, "coldtest", policy, &kf, 0);
        assert_eq!(store.stream_floor(&prefix).unwrap(), 6, "floor after seal");
        assert_eq!(kf.load(Ordering::Relaxed), 6);

        // SM state is bounded: sealed rows are gone, hot rows remain.
        for seq in 0..6u64 {
            assert_eq!(
                store.get_stream_entry(&format!("{prefix}{seq}")).unwrap(),
                None,
                "sealed row {seq} must be deleted"
            );
        }
        for seq in 6..10u64 {
            assert!(store
                .get_stream_entry(&format!("{prefix}{seq}"))
                .unwrap()
                .is_some());
        }

        // The full logical log reads back byte-exact through the core — cold
        // seqs resolve via the segment index + blob, hot seqs from the rows.
        for i in 0..10u64 {
            assert_eq!(
                c.read_at(i).unwrap(),
                Some(format!("m{i}").into_bytes()),
                "seq {i} must round-trip (cold or hot)"
            );
        }
        // Global tail (sys_stat.size SSOT) is the full length, not the hot count.
        assert_eq!(c.tail(), 10);
        // seq 0 is specifically cold (below floor) and exact.
        assert_eq!(c.read_at(0).unwrap(), Some(b"m0".to_vec()));
    }

    /// Integrity: if a cold blob is corrupted, the cold read fails LOUD rather
    /// than returning garbage — the segment magic/base guard catches it.
    #[test]
    fn corrupt_cold_blob_fails_loud() {
        let store = store();
        let cold_impl = Arc::new(MockCold {
            origin: Some("n".into()),
            ..Default::default()
        });
        let cold: Arc<dyn ColdSegmentStore> = cold_impl.clone();
        let policy = SealPolicy {
            hot_window: 1,
            seal_batch: 2,
        };
        let c = WalStreamCore::with_cold_tier(
            Arc::clone(&store),
            "corrupt".into(),
            Arc::clone(&cold),
            policy,
            0, // keep-forever (no trim)
        );
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}corrupt/");
        for i in 0..4u64 {
            c.write_sync(format!("v{i}").as_bytes()).unwrap();
        }
        let kf = AtomicU64::new(0);
        seal_loop(&store, cold.as_ref(), &prefix, "corrupt", policy, &kf, 0);
        assert!(store.stream_floor(&prefix).unwrap() >= 2);
        // Corrupt every stored blob.
        for v in cold_impl.blobs.lock().unwrap().values_mut() {
            v[0] ^= 0xff;
        }
        assert!(c.read_at(0).is_err(), "a corrupt cold blob must fail loud");
    }

    /// The push path itself triggers the background seal (proving the trigger is
    /// wired, not just `seal_loop` in isolation): after enough pushes the floor
    /// advances to the expected steady state and the whole log stays readable.
    #[test]
    fn push_triggers_background_seal_and_bounds_hot_rows() {
        let store = store();
        let cold: Arc<dyn ColdSegmentStore> = Arc::new(MockCold {
            origin: Some("n".into()),
            ..Default::default()
        });
        let c = Arc::new(WalStreamCore::with_cold_tier(
            Arc::clone(&store),
            "trig".into(),
            Arc::clone(&cold),
            SealPolicy {
                hot_window: 4,
                seal_batch: 4,
            },
            0, // keep-forever (no trim)
        ));
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}trig/");
        for i in 0..20u64 {
            StreamBackend::push(&*c, format!("m{i}").as_bytes()).unwrap();
        }
        // Background seal drains until tail - floor < hot_window + seal_batch (8):
        // 20 → floor converges to 16 (16 sealed, 4 hot). Poll (in-memory mock is
        // sub-ms; the bound is a generous backstop, never the expected wait).
        let mut floor = 0;
        for _ in 0..400 {
            floor = store.stream_floor(&prefix).unwrap();
            if floor == 16 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            floor, 16,
            "push-triggered seal must drain to the hot window"
        );
        // Hot rows bounded to the window (seqs 16..20).
        for seq in 0..16u64 {
            assert_eq!(
                store.get_stream_entry(&format!("{prefix}{seq}")).unwrap(),
                None
            );
        }
        // The full log is still readable end-to-end.
        for i in 0..20u64 {
            assert_eq!(c.read_at(i).unwrap(), Some(format!("m{i}").into_bytes()));
        }
    }

    /// A hot-only core (no cold tier) never seals and never consults the cold
    /// path — the pre-P1 behaviour is preserved exactly.
    #[test]
    fn hot_only_core_never_seals() {
        let store = store();
        let c = WalStreamCore::new(Arc::clone(&store), "hotonly".into());
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}hotonly/");
        for i in 0..50u64 {
            StreamBackend::push(&c, format!("m{i}").as_bytes()).unwrap();
        }
        // No seal ever happens: floor stays 0 and every row is still hot.
        assert_eq!(store.stream_floor(&prefix).unwrap(), 0);
        for i in 0..50u64 {
            assert!(store
                .get_stream_entry(&format!("{prefix}{i}"))
                .unwrap()
                .is_some());
        }
    }

    /// Retention trim: once sealed cold storage exceeds the byte budget, the
    /// oldest segments are dropped and `earliest` advances. A read below
    /// `earliest` is `Truncated` (OffsetOutOfRange); reads at/above it still
    /// resolve; `earliest_offset` and the kept cold-byte budget hold.
    #[test]
    fn trim_advances_earliest_and_reads_below_are_truncated() {
        let store = store();
        let cold: Arc<dyn ColdSegmentStore> = Arc::new(MockCold {
            origin: Some("n".into()),
            ..Default::default()
        });
        let policy = SealPolicy {
            hot_window: 2,
            seal_batch: 2,
        };
        let retention = 40u64; // ~one two-frame segment
        let c = WalStreamCore::with_cold_tier(
            Arc::clone(&store),
            "trim".into(),
            Arc::clone(&cold),
            policy,
            retention,
        );
        let prefix = format!("{WAL_STREAM_KEY_PREFIX}trim/");
        for i in 0..10u64 {
            c.write_sync(format!("v{i:03}").as_bytes()).unwrap();
        }
        // Seal (+trim) synchronously for determinism.
        let kf = AtomicU64::new(0);
        seal_loop(
            &store,
            cold.as_ref(),
            &prefix,
            "trim",
            policy,
            &kf,
            retention,
        );

        let earliest = store.stream_earliest(&prefix).unwrap();
        assert!(
            earliest > 0,
            "retention must have trimmed the oldest cold segments"
        );
        let tail = c.tail();

        // Below earliest → Truncated at the backend (Kafka OffsetOutOfRange).
        for seq in 0..earliest {
            match StreamBackend::read_at(&c, seq as usize) {
                Err(StreamError::Truncated(e, req)) => {
                    assert_eq!(e, earliest as usize);
                    assert_eq!(req, seq as usize);
                }
                other => panic!("seq {seq} below earliest must be Truncated, got {other:?}"),
            }
        }
        // At/above earliest → still resolves (cold or hot), byte-exact next offset.
        for seq in earliest..tail {
            assert!(c.read_at(seq).unwrap().is_some(), "seq {seq} must resolve");
            match StreamBackend::read_at(&c, seq as usize) {
                Ok((_, next)) => assert_eq!(next, seq as usize + 1),
                other => panic!("seq {seq} must read, got {other:?}"),
            }
        }
        assert_eq!(c.earliest_offset(), earliest as usize);
        let cold_bytes: u64 = store
            .list_stream_segments(&prefix)
            .unwrap()
            .iter()
            .map(|s| s.size)
            .sum();
        assert!(
            cold_bytes <= retention,
            "kept cold storage {cold_bytes} must fit retention {retention}"
        );
    }
}
