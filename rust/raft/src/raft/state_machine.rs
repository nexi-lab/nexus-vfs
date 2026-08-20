//! State machine trait for Raft consensus.
//!
//! The state machine defines what operations can be applied through Raft.
//! For STRONG_HA zones, this includes metadata and lock operations
//! (NOT file data - that stays in CAS/S3).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::storage::{RedbStore, RedbTree};

// Advisory lock types are the shared SSOT, defined in `contracts::lock_state`.
// Re-exported here so callers can `use raft::{LockInfo, ...}` directly.
pub use contracts::lock_state::{HolderInfo, LockAcquireResult, LockEntry, LockInfo, LockState};

use super::Result;

/// Command to be replicated through Raft.
///
/// Commands are serialized and stored in the Raft log, then applied
/// to the state machine when committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Set a key-value pair in metadata.
    SetMetadata {
        /// The key (typically a file path).
        key: String,
        /// The value (serialized metadata).
        value: Vec<u8>,
    },

    /// Delete a metadata entry.
    DeleteMetadata {
        /// The key to delete.
        key: String,
    },

    /// Acquire a distributed lock (exclusive or shared).
    ///
    /// Two orthogonal dimensions:
    ///
    /// * `max_holders` — capacity. `1` = mutex, `>1` = semaphore /
    ///   reader-writer. Also used as the computed "mode" display
    ///   label in Python (`"mutex"` vs. `"semaphore"`), which stays
    ///   computed — never stored.
    /// * `mode` — conflict rule for *this acquire*. `Exclusive`
    ///   requires the caller to be the sole holder; `Shared` may
    ///   coexist with other `Shared` holders up to `max_holders` but
    ///   is blocked by any `Exclusive` holder. `max_holders=1 +
    ///   Exclusive` is a classic mutex; `max_holders>1 + Shared` is a
    ///   reader-writer lock with N concurrent readers.
    AcquireLock {
        /// Resource path being locked.
        path: String,
        /// Unique lock ID for this holder (UUID).
        lock_id: String,
        /// Maximum number of concurrent holders (1 = mutex, >1 = semaphore).
        max_holders: u32,
        /// Lock expiration in seconds.
        ttl_secs: u32,
        /// Information about the holder (e.g., "agent:xxx").
        holder_info: String,
        /// Wall-clock timestamp captured at proposal time (Unix secs).
        /// All replicas use this value instead of local clocks to ensure
        /// deterministic state machine application.
        now_secs: u64,
    },

    /// Release a distributed lock.
    ReleaseLock {
        /// Resource path.
        path: String,
        /// Lock ID of the holder releasing.
        lock_id: String,
    },

    /// Extend lock TTL.
    ExtendLock {
        /// Resource path.
        path: String,
        /// Lock ID of the holder.
        lock_id: String,
        /// New TTL in seconds (from now).
        new_ttl_secs: u32,
        /// Wall-clock timestamp captured at proposal time (Unix secs).
        /// All replicas use this value instead of local clocks to ensure
        /// deterministic state machine application (Issue #3029 / Bug 1).
        now_secs: u64,
    },

    /// Compare-and-swap metadata: write only if current version matches.
    CasSetMetadata {
        /// The key (typically a file path).
        key: String,
        /// The value (serialized metadata).
        value: Vec<u8>,
        /// Expected version (0 = create-only).
        expected_version: u32,
    },

    /// Atomically adjust a metadata counter by a signed delta.
    ///
    /// Read-modify-write happens in `apply()` — serial by Raft guarantee.
    /// The value is stored as `i64` big-endian in the metadata tree.
    /// Result is clamped to `>= 0`.
    AdjustCounter {
        /// The metadata key (e.g., `"__i_links_count__"`).
        key: String,
        /// Signed delta to add (positive = increment, negative = decrement).
        delta: i64,
    },

    /// Force-release ALL holders on a lock (admin override).
    ForceReleaseLock {
        /// Resource path.
        path: String,
    },

    /// Append a raw-byte entry to a dedicated stream table (R19.1b').
    ///
    /// Used by the kernel's WAL stream backend to persist ordered
    /// stream entries without shoehorning the payload through the
    /// ``FileMetadata`` proto. Stored in ``TREE_STREAM_ENTRIES``
    /// (distinct from ``TREE_METADATA``) so list scans and snapshot
    /// walkers do not confuse stream payload with file metadata.
    AppendStreamEntry {
        /// Stream key PREFIX (``/__wal_stream__/<id>/`` or
        /// ``/__wal_pipe__/<id>/``). The caller does NOT choose the offset —
        /// the state machine assigns it at apply (see `execute_metadata_in_txn`)
        /// in raft-committed order, so a total order holds even across
        /// concurrent writers and two writers can never collide on a seq.
        stream_prefix: String,
        /// Raw payload bytes — no encoding applied.
        data: Vec<u8>,
    },

    /// No-op command (used for leader election confirmation).
    Noop,

    // ── Auth-key store ───────────────────────────────────────────────
    //
    // Kept AFTER `Noop` on purpose: bincode encodes an enum variant by
    // its declaration index, and the raft log is persisted + replicated
    // with that encoding. Appending here preserves every existing
    // variant's index, so logs written before these commands existed
    // still decode. New variants must always be appended, never
    // inserted mid-enum.
    /// Upsert an opaque value into the replicated cluster-control store under
    /// `(namespace, key)` — the ONE key space carrying all cluster-control state
    /// (auth-key/agent records under [`contracts::CONTROL_NS_AUTH`], cross-org
    /// trust anchors under [`contracts::CONTROL_NS_FOREIGN_CA`], …). The "locks"
    /// pattern: a kernel-internal primitive, not a file. `value` is opaque bytes
    /// the state machine never interprets; each namespace owner owns its schema.
    /// Kept in a dedicated tree so `ZoneMetaStore`/snapshot walkers (which assume
    /// every metadata value is a `FileMetadata` proto) never see it. Raft-
    /// replicated ⇒ writes + revocations propagate to every replica.
    ///
    /// `if_absent` makes this a CAS put-if-absent: apply returns
    /// [`CommandResult::Error`] if `(namespace, key)` already exists, giving a
    /// log-ordered uniqueness gate (agent-name dedup, foreign-CA anchor re-pin
    /// rejection) that a client read-then-write cannot (TOCTOU). `false` = plain
    /// upsert (rotation).
    ///
    /// Replaces the former `PutAuthKey`/`DeleteAuthKey` (generalised, not kept as
    /// a compat shim). The `Command` wire encoding is bincode-by-index and this
    /// occupies the same tail index; a pre-existing log with the old variant is
    /// not decoded across this change — the cluster is wiped on version bump (no
    /// backward compat), so no in-place old log is ever read by this build.
    PutControlState {
        /// Owner namespace (`contracts::CONTROL_NS_*`).
        namespace: String,
        /// Lookup key within the namespace (not a secret).
        key: String,
        /// Opaque serialized value; the state machine never parses it.
        value: Vec<u8>,
        /// CAS: reject if `(namespace, key)` already exists.
        if_absent: bool,
    },

    /// Remove `(namespace, key)` from the cluster-control store (revocation /
    /// un-pin). Idempotent.
    DeleteControlState {
        /// Owner namespace (`contracts::CONTROL_NS_*`).
        namespace: String,
        /// Lookup key within the namespace.
        key: String,
    },

    /// Seal a contiguous `[base, end)` seq range of a WAL DT_STREAM into an
    /// immutable cold segment (Kafka tiered-storage roll → upload → delete).
    ///
    /// Kept AFTER `DeleteControlState` for the same bincode-index reason those
    /// variants document: a new variant is appended, never inserted mid-enum,
    /// so every existing variant keeps its encoded index.
    ///
    /// The segment BYTES were already written to the content pillar (CAS /
    /// federation cache) by the proposer BEFORE this command — `content_id` is
    /// the id that store returned and `origin` is the proposer's advertise
    /// address, so a cold read on any node resolves the blob (local content
    /// store, else a `ReadBlob` peer fetch from `origin`) exactly the way a
    /// DT_REG file's federated content read does. This command is the METADATA
    /// half: it is deterministic and redb-only (no CAS I/O at apply), so every
    /// replica converges. Applied via `execute_metadata_in_txn` so the index
    /// mutation and `last_applied` land in one txn.
    ///
    /// Apply gates on `base == floor` (seal contiguously from the front) so a
    /// duplicate or racing proposal for an already-sealed range is a no-op
    /// error, and content-addressing dedups the blob — the pair makes concurrent
    /// proposers on different nodes converge without gap, dup, or offset skew.
    SealStreamSegment {
        /// Stream key PREFIX (`/__wal_stream__/<id>/`), same identity the
        /// matching `AppendStreamEntry` uses.
        stream_prefix: String,
        /// First seq in the sealed range (must equal the stream's current
        /// cold-tier floor at apply, else the seal is rejected as stale).
        base: u64,
        /// One past the last sealed seq. Rows `[base, end)` are deleted from
        /// the hot tree and the floor advances to `end`.
        end: u64,
        /// Content-store id of the sealed segment blob (BLAKE3 for a CAS
        /// backend; the storage path for the path-addressed federation cache).
        content_id: String,
        /// Advertise address of the node that wrote the segment blob — the
        /// `ReadBlob` fetch origin for replicas that lack it locally.
        origin: String,
        /// Segment blob size in bytes (observability + future trim accounting).
        size: u64,
    },

    /// Trim a WAL DT_STREAM's cold tier: drop every sealed segment fully below
    /// `up_to_seq` and advance the stream's `earliest` seq to it — Kafka log
    /// retention. A read below `earliest` is `Truncated` (OffsetOutOfRange).
    ///
    /// Appended at the enum tail for the same bincode-index reason the other
    /// variants document. Deterministic + redb-only at apply (index delete +
    /// `earliest` bump in one txn) — the blob GC is a side effect the kernel's
    /// trim-GC apply-observer performs on each blob's origin node, driven by the
    /// `trimmed` list carried here (the index entries are gone by observer time,
    /// so the refs must travel with the command). Gated `earliest < up_to <=
    /// floor` so it only ever drops sealed data and only advances.
    TrimStreamSegment {
        /// Stream key PREFIX (`/__wal_stream__/<id>/`).
        stream_prefix: String,
        /// New `earliest` seq — one past the last trimmed seq. Every segment
        /// whose `end <= up_to_seq` is dropped from the index.
        up_to_seq: u64,
        /// `(origin, content_id)` of each dropped segment's blob, so the trim-GC
        /// observer on each node can delete the blobs it owns (`origin == self`).
        trimmed: Vec<(String, String)>,
    },
}

/// Result of applying a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandResult {
    /// Command succeeded.
    Success,

    /// Command succeeded with a value.
    Value(Vec<u8>),

    /// Lock acquisition result.
    LockResult(LockAcquireResult),

    /// Compare-and-swap result.
    CasResult {
        /// Whether the swap succeeded.
        success: bool,
        /// Current version after the operation.
        current_version: u32,
    },

    /// Command failed.
    Error(String),
}

// Advisory lock types — `HolderInfo`, `LockInfo`, `LockAcquireResult`,
// `LockEntry`, `LockState` — live in `contracts::lock_state` and are
// re-exported at the top of this file. All state-transition logic
// lives on `LockState` (the shared BTreeMap-based SSOT) so the local
// `LockManager` path and the raft apply path go through the same
// primitives under the same mutex.

/// State machine trait that must be implemented by applications.
///
/// The state machine processes committed Raft log entries and maintains
/// the application state. For Nexus STRONG_HA zones, this handles:
///
/// - File metadata (path -> hash, size, mtime, permissions)
/// - Distributed locks (semaphore-style with owner tracking)
///
/// File content is NOT stored in the state machine - it remains in
/// the content-addressable storage (CAS) backend (S3, GCS, local).
pub trait StateMachine: Send + Sync {
    /// Apply a committed command to the state machine.
    ///
    /// This is called when a log entry is committed (replicated to a quorum).
    /// The implementation must be deterministic - given the same sequence of
    /// commands, all nodes must reach the same state.
    ///
    /// # Arguments
    /// * `index` - Log index of the entry being applied
    /// * `command` - The command to apply
    ///
    /// # Returns
    /// Result of applying the command
    fn apply(&mut self, index: u64, command: &Command) -> Result<CommandResult>;

    /// Create a snapshot of the current state.
    ///
    /// Snapshots are used to compact the Raft log and for catch-up of
    /// lagging followers. Returns serialized state that can be restored
    /// with `restore_snapshot`.
    ///
    /// For witness nodes, this returns an empty snapshot (they don't
    /// store state machine data).
    fn snapshot(&self) -> Result<Vec<u8>>;

    /// Restore state from a snapshot.
    ///
    /// Called when a node receives a snapshot from the leader (typically
    /// when the node is far behind or just joined the cluster).
    fn restore_snapshot(&mut self, data: &[u8]) -> Result<()>;

    /// Apply a command locally for EC (eventual consistency) writes.
    ///
    /// Unlike [`apply`], this bypasses Raft index tracking — the write
    /// is not associated with any Raft log entry. Only metadata operations
    /// (SetMetadata, DeleteMetadata) are supported; lock operations require
    /// linearizability and must use SC (Raft consensus).
    ///
    /// Default implementation returns an error (not all state machines
    /// support local writes — e.g., witness nodes).
    fn apply_local(&mut self, _command: &Command) -> Result<CommandResult> {
        Err(super::RaftError::InvalidState(
            "Local EC writes not supported on this state machine".into(),
        ))
    }

    /// Apply an EC command with LWW (Last Writer Wins) conflict resolution.
    ///
    /// Used by the peer-receive path to reject stale writes. Compares the
    /// incoming entry's timestamp against the existing metadata's `modified_at`.
    ///
    /// Default: delegates to [`apply_local`] (no LWW check). Override in
    /// state machines that store FileMetadata (i.e., [`FullStateMachine`]).
    fn apply_ec_with_lww(
        &mut self,
        command: &Command,
        _entry_timestamp: u64,
    ) -> Result<CommandResult> {
        self.apply_local(command)
    }

    /// Snapshot the current EC-replicable state as idempotent commands.
    ///
    /// Used by the EC anti-entropy path (`SnapshotEcState`): a peer that fell
    /// behind the compacted WAL region can't be caught up incrementally, so
    /// the sender re-materializes THIS state as idempotent `SetMetadata`
    /// commands and ships it. Order is irrelevant: the receiver applies each
    /// LWW-idempotently.
    ///
    /// EC state is metadata registers only — DT_STREAM entries are strong
    /// consistency (raft-committed, replicated via the log itself), never the
    /// EC plane, so they are not part of this snapshot.
    ///
    /// Default: empty (a state machine that holds no EC state — e.g. a
    /// witness — has nothing to transfer). Override in [`FullStateMachine`].
    fn ec_state_snapshot(&self) -> Vec<Command> {
        Vec::new()
    }

    /// Get the last applied log index.
    ///
    /// Used to determine which log entries need to be applied after restart.
    fn last_applied_index(&self) -> u64;

    /// Return a shared atomic counter reflecting ``last_applied_index``.
    ///
    /// Implementors that need to expose applied progress to sync readers
    /// outside the state-machine's async RwLock return an ``Arc`` clone
    /// of the atomic they own internally. Default is ``None`` — callers
    /// that need the signal must then fall back to ``last_applied_index``
    /// under the async lock.
    ///
    /// Only ``FullStateMachine`` implements this; witness / in-memory
    /// test state machines return ``None`` because nothing outside
    /// raft reads their applied progress.
    fn last_applied_shared(&self) -> Option<Arc<AtomicU64>> {
        None
    }

    /// Optional apply-side observer list.
    ///
    /// State machines that back apply-side coherence (notably
    /// ``FullStateMachine``) return their shared
    /// ``Arc<RwLock<Vec<Arc<Fn(&AppliedEntry)>>>>`` so multiple
    /// downstream consumers each ``push`` an observer fired on every
    /// committed metadata-path command. This is the single spine that
    /// federation-mount wiring, DCache invalidation, and (future) A2A /
    /// auth-cache eviction all subscribe to. State machines with no such
    /// coherence concern (witness, direct-drive test harnesses) return
    /// ``None`` via the default impl, and apply stays a pure no-op on
    /// that front.
    ///
    /// Each observer must match the command variants it cares about and
    /// ignore the rest — every registered observer is invoked for every
    /// committed metadata-path command (in registration order).
    fn apply_observers_slot(&self) -> Option<Arc<parking_lot::RwLock<Vec<ApplyObserver>>>> {
        None
    }

    /// Optional advisory-lock state handle.
    ///
    /// Returns a clone of the same ``Arc<Mutex<LockState>>`` the apply
    /// path mutates. ``ZoneConsensus::new`` captures this handle BEFORE
    /// wrapping the state machine in the async RwLock so sync callers
    /// (notably ``DistributedLocks::new`` invoked from inside the
    /// mount-apply callback that fires on a tokio worker thread) can
    /// obtain the SSOT advisory Arc without ``RwLock::blocking_read`` —
    /// which panics from inside a tokio runtime.
    ///
    /// The Arc identity is stable for the life of the state machine:
    /// snapshot restore mutates the inner ``LockState`` under the same
    /// parking_lot mutex (see ``FullStateMachine::restore_snapshot``).
    ///
    /// Only [`FullStateMachine`] returns ``Some``; witness / test
    /// state machines return ``None`` because they don't carry advisory
    /// locks.
    fn advisory_handle(&self) -> Option<Arc<Mutex<LockState>>> {
        None
    }
}

/// A committed log entry handed to every apply-side observer registered
/// on [`StateMachine::apply_observers_slot`].
///
/// Delivered AFTER the entry is durably applied. Observers are
/// side-effect-only, non-blocking, and must tolerate any command variant
/// (they match what they care about and ignore the rest). Every observer
/// sees identical data on every replica — no node-local truth.
pub struct AppliedEntry<'a> {
    /// Log index of the applied entry.
    pub index: u64,
    /// The committed command.
    pub command: &'a Command,
    /// Key whose committed pre-image was a DT_MOUNT that this command
    /// removes / overwrites — captured before the write txn (the one
    /// fact not recomputable post-commit). ``None`` for everything else;
    /// only the mount observer reads it.
    pub removed_mount_key: Option<&'a str>,
}

/// A registered apply-side observer.
///
/// The optional `&'static str` is a dedup key that controls re-register
/// semantics on [`ZoneConsensus`]:
/// * `Some(key)` — **replace-by-key**: registering again with the same
///   key drops the prior observer. Used by federation-mount wiring,
///   which re-installs 7+ times per zone (boot resume / join / mount /
///   rewire) and must stay a singleton — the old code held it in a
///   single `Option` slot and overwrote.
/// * `None` — **anonymous accumulate**: every registration adds another
///   observer. Used by the DCache invalidator, where one observer per
///   `ZoneMetaStore` surface is correct and stale closures are harmless.
pub type ApplyObserver = (
    Option<&'static str>,
    Arc<dyn Fn(&AppliedEntry) + Send + Sync>,
);

/// A DT_MOUNT apply event — the mount observer's internal representation,
/// produced by [`FullStateMachine::mount_apply_event_from`].
///
/// All payload fields derive from replicated state (raft log `Command` +
/// state-machine `FileMetadata` proto), so every replica firing this
/// event observes identical data — no node-local truth is introduced.
///
/// The callback's parent ``zone_id`` is captured by the install site
/// (kernel's ``install_federation_mount_coherence(consensus)``) as a
/// closure binding, not carried on the event.
#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
pub enum MountApplyEvent {
    /// DT_MOUNT upsert. ``target_zone_id`` comes from the decoded
    /// ``FileMetadata`` proto written by this apply — snapshotted at
    /// fire time so a subsequent apply to the same key cannot race
    /// the callback into wiring the wrong target.
    ///
    /// The event carries only ``key`` and ``target_zone_id``.
    /// io_profile / readonly / admin_only and ``backend_name`` are
    /// not carried — the kernel-side wire path passes a constant
    /// label down to the router, and mount records' backend is
    /// supplied separately by the router's mount config.
    Set { key: String, target_zone_id: String },
    /// DT_MOUNT delete. No proto payload — the entry was removed inside
    /// the same apply txn, so callers look up the prior mount via their
    /// own reverse index (e.g. kernel ``cross_zone_mounts``) to drive
    /// cascade-unmount.
    Delete { key: String },
}

/// A no-op state machine for witness nodes (in-memory, for testing).
///
/// Witness nodes participate in Raft voting but don't apply state machine
/// commands. They only store the Raft log (for leader election and replication).
/// This makes them cheaper to run while still contributing to quorum.
#[derive(Debug, Default)]
pub struct WitnessStateMachineInMemory {
    last_applied: u64,
}

impl WitnessStateMachineInMemory {
    /// Create a new witness state machine.
    pub fn new() -> Self {
        Self { last_applied: 0 }
    }
}

impl StateMachine for WitnessStateMachineInMemory {
    fn apply(&mut self, index: u64, _command: &Command) -> Result<CommandResult> {
        self.last_applied = index;
        Ok(CommandResult::Success)
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn restore_snapshot(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn last_applied_index(&self) -> u64 {
        self.last_applied
    }
}

// Tree name for witness log storage
const TREE_WITNESS_LOG: &str = "witness_log";
const KEY_WITNESS_LAST_INDEX: &[u8] = b"__witness_last_index__";

/// Persistent witness state machine backed by redb.
///
/// Stores log entries for vote validation but doesn't apply commands.
/// This is used for production witness nodes.
pub struct WitnessStateMachine {
    log_tree: RedbTree,
    last_index: u64,
}

impl WitnessStateMachine {
    /// Create a new witness state machine with storage.
    ///
    /// Handles endianness migration: existing deployments stored `last_index`
    /// as little-endian, but the rest of the codebase uses big-endian. On load,
    /// we detect the format by checking which interpretation yields a valid
    /// Raft index (small positive number) and migrate to big-endian on next write.
    pub fn new(store: &RedbStore) -> Result<Self> {
        let log_tree = store.tree(TREE_WITNESS_LOG)?;

        // Load last index, auto-detecting LE vs BE encoding
        let last_index = log_tree
            .get(KEY_WITNESS_LAST_INDEX)?
            .map(|v| {
                if v.len() == 8 {
                    let bytes: [u8; 8] = [v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]];
                    let be_val = u64::from_be_bytes(bytes);
                    let le_val = u64::from_le_bytes(bytes);

                    // Heuristic: valid Raft indices are small positive numbers.
                    // If BE gives a huge number but LE gives a reasonable one,
                    // the data is in the old LE format.
                    if be_val > 1_000_000_000 && le_val <= 1_000_000_000 {
                        le_val // old LE format — will be re-written as BE on next store
                    } else {
                        be_val // new BE format (or both are reasonable — BE is preferred)
                    }
                } else {
                    0
                }
            })
            .unwrap_or(0);

        Ok(Self {
            log_tree,
            last_index,
        })
    }

    /// Store a log entry (for vote validation).
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    pub fn store_log_entry(&mut self, index: u64, data: &[u8]) -> Result<()> {
        let key = format!("log:{:020}", index);
        self.log_tree.set(key.as_bytes(), data)?;

        if index > self.last_index {
            self.last_index = index;
            // Always write big-endian (consistent with rest of codebase)
            self.log_tree
                .set(KEY_WITNESS_LAST_INDEX, &index.to_be_bytes())?;
        }
        Ok(())
    }

    /// Get a log entry by index.
    pub fn get_log_entry(&self, index: u64) -> Option<Vec<u8>> {
        let key = format!("log:{:020}", index);
        self.log_tree.get(key.as_bytes()).ok().flatten()
    }
}

impl StateMachine for WitnessStateMachine {
    fn apply(&mut self, index: u64, _command: &Command) -> Result<CommandResult> {
        // Witness nodes don't apply commands - they just track the index
        self.last_index = index;
        Ok(CommandResult::Success)
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        // Witness nodes return empty snapshots
        Ok(vec![])
    }

    fn restore_snapshot(&mut self, _data: &[u8]) -> Result<()> {
        // Witness nodes don't restore state
        Ok(())
    }

    fn last_applied_index(&self) -> u64 {
        self.last_index
    }
}

// Tree names for FullStateMachine
const TREE_METADATA: &str = "sm_metadata";
/// Dedicated redb tree for raw-byte stream entries (R19.1b').
///
/// Holds ``Command::AppendStreamEntry`` payloads separate from
/// ``TREE_METADATA`` so the WAL stream backend does not pollute file
/// metadata scans / snapshots with hex-encoded payload rows. Keys are
/// opaque strings (the kernel picks a ``/__wal_stream__/<id>/<seq>``
/// convention); values are raw bytes. One reserved sidecar key per stream —
/// [`stream_tail_key`] — holds that stream's next-offset cursor in the SAME
/// tree, so the cursor is atomic with the entries and rides the snapshot.
const TREE_STREAM_ENTRIES: &str = "sm_stream_entries";

/// Reserved key holding a stream's next-offset cursor, stored beside its
/// entries in [`TREE_STREAM_ENTRIES`]. The `__stream_tail__` namespace never
/// overlaps an entry key (`{stream_prefix}{seq}`, where `stream_prefix` begins
/// `/__wal_stream__/` or `/__wal_pipe__/`), so read/collect prefix scans skip
/// it while the state-machine snapshot (which walks the whole tree) carries it
/// for free. The `AppendStreamEntry` apply is the sole writer; SSOT for "how
/// many entries has this stream ever had".
fn stream_tail_key(stream_prefix: &str) -> String {
    format!("__stream_tail__{stream_prefix}")
}

/// Reserved key holding a stream's cold-tier FLOOR — the lowest seq still in the
/// hot tree (`earliest_hot`). `0` (absent) until the first seal. A cold read
/// (`get_stream_entry` miss with `seq < floor`) resolves through the segment
/// index; `SealStreamSegment` apply is the sole writer. Lives in the SAME tree
/// as the entries so it is atomic with them and rides the snapshot, exactly like
/// [`stream_tail_key`]. Its `__stream_floor__` namespace never overlaps an entry
/// key (`{stream_prefix}{seq}`) nor a segment key, so prefix scans skip it.
fn stream_floor_key(stream_prefix: &str) -> String {
    format!("__stream_floor__{stream_prefix}")
}

/// Reserved key holding a stream's `earliest` readable seq — the retention floor
/// advanced by `TrimStreamSegment`. `0` (absent) until the first trim. A read
/// below it is `Truncated` (Kafka OffsetOutOfRange). Same tree / snapshot
/// treatment and non-overlapping `__stream_earliest__` namespace as the tail /
/// floor sidecars.
fn stream_earliest_key(stream_prefix: &str) -> String {
    format!("__stream_earliest__{stream_prefix}")
}

/// Key prefix under which a stream's cold-segment index records live, one per
/// sealed range. Full key = `{prefix}{base:020}` (zero-padded so lexicographic
/// order == numeric base order, enabling the `find_segment` reverse-range
/// lookup). Distinct `__stream_seg__` namespace, so — like the tail/floor
/// sidecars — it never collides with an entry key and rides the snapshot with
/// the rest of the tree.
fn stream_segment_key_prefix(stream_prefix: &str) -> String {
    format!("__stream_seg__{stream_prefix}")
}

/// Full segment-index key for the segment based at `base`.
fn stream_segment_key(stream_prefix: &str, base: u64) -> String {
    format!("{}{base:020}", stream_segment_key_prefix(stream_prefix))
}

/// One decoded cold-segment index record (the `SealStreamSegment` payload minus
/// `base`, which the key carries). SSOT for the on-disk record layout, paired
/// with [`encode_segment_record`] / [`decode_segment_record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecord {
    /// One past the last seq in the segment.
    pub end: u64,
    /// Segment blob size in bytes.
    pub size: u64,
    /// Advertise address of the node that wrote the blob (`ReadBlob` origin).
    pub origin: String,
    /// Content-store id of the sealed blob.
    pub content_id: String,
}

/// Serialize a segment-index record to opaque redb bytes. Explicit fixed-layout
/// framing (not serde) so the format is stable across builds — these bytes ride
/// SM snapshots to every joining node. Layout (all big-endian):
/// `[end u64][size u64][origin_len u32][origin bytes][content_id bytes…]`.
fn encode_segment_record(end: u64, size: u64, origin: &str, content_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + origin.len() + content_id.len());
    out.extend_from_slice(&end.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&(origin.len() as u32).to_be_bytes());
    out.extend_from_slice(origin.as_bytes());
    out.extend_from_slice(content_id.as_bytes());
    out
}

/// Inverse of [`encode_segment_record`]. Returns `None` on a truncated / corrupt
/// record (treated as "no segment" by the caller — fail closed, never panic in
/// a state-machine read).
fn decode_segment_record(bytes: &[u8]) -> Option<SegmentRecord> {
    if bytes.len() < 20 {
        return None;
    }
    let end = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
    let size = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    let origin_len = u32::from_be_bytes(bytes[16..20].try_into().ok()?) as usize;
    let origin_end = 20usize.checked_add(origin_len)?;
    if bytes.len() < origin_end {
        return None;
    }
    let origin = String::from_utf8(bytes[20..origin_end].to_vec()).ok()?;
    let content_id = String::from_utf8(bytes[origin_end..].to_vec()).ok()?;
    Some(SegmentRecord {
        end,
        size,
        origin,
        content_id,
    })
}
/// Dedicated redb tree for the cluster-control store (auth records, cross-org
/// anchors, …).
///
/// Holds ``Command::PutControlState`` payloads, separate from ``TREE_METADATA``
/// for the same reason ``TREE_STREAM_ENTRIES`` is: the values are opaque bytes,
/// not ``FileMetadata`` protos, so keeping them out of the metadata tree stops
/// ``ZoneMetaStore``/snapshot walkers (which assume every value decodes as a
/// proto) from choking. Keys are ``namespace\0key`` (both NUL-free ASCII), so a
/// ``namespace\0`` prefix scan enumerates exactly one namespace; values are the
/// namespace owner's serialized record.
const TREE_CONTROL_STATE: &str = "sm_control_state";
const KEY_LAST_APPLIED: &[u8] = b"__last_applied__";

/// Composite storage key for [`TREE_CONTROL_STATE`]: ``namespace \0 key``.
/// Namespaces (`contracts::CONTROL_NS_*`) and keys (hex hashes, `agent:<name>`,
/// anchor hashes) are NUL-free ASCII, so the separator is unambiguous and a
/// ``namespace\0`` prefix scan enumerates exactly one namespace.
fn control_key(namespace: &str, key: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(namespace.len() + 1 + key.len());
    k.extend_from_slice(namespace.as_bytes());
    k.push(0);
    k.extend_from_slice(key.as_bytes());
    k
}

// R14: Advisory locks no longer have a redb tree. The BTreeMap in
// `Arc<Mutex<LockState>>` is the single source of truth; persistence
// happens via raft snapshots. This preserves raft's "apply = atomic
// commit point" contract — reads and writes observe the same state
// under the same mutex, and there is no two-phase window between a
// BTreeMap mirror and a redb row where a crash could leave them
// divergent. On startup the BTreeMap is rebuilt from a snapshot
// (`restore_snapshot`) plus log replay; see `FullStateMachine::apply`
// for the replay semantics.

// ---------------------------------------------------------------------------
// LWW (Last Writer Wins) helpers for EC conflict resolution
// ---------------------------------------------------------------------------

/// Decode a serialized FileMetadata protobuf and extract the `modified_at` field.
///
/// Used for LWW comparison on `SetMetadata`: both incoming and existing values
/// are decoded and their `modified_at` ISO 8601 strings compared lexicographically.
///
/// Returns empty string on decode failure (sorts before any real timestamp,
/// meaning corrupted data always gets overwritten).
#[cfg(feature = "grpc")]
fn decode_modified_at(bytes: &[u8]) -> String {
    use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
    use prost::Message as ProstMessage;

    ProtoFileMetadata::decode(bytes)
        .map(|fm| fm.modified_at)
        .unwrap_or_default()
}

/// Decode a serialized FileMetadata protobuf and parse `modified_at` to Unix seconds.
///
/// Used for LWW comparison on `DeleteMetadata`: the entry's u64 timestamp is
/// compared against the existing value's parsed `modified_at`.
///
/// Returns 0 on decode/parse failure (treat as infinitely old).
#[cfg(feature = "grpc")]
fn decode_modified_at_unix(bytes: &[u8]) -> u64 {
    use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
    use prost::Message as ProstMessage;

    ProtoFileMetadata::decode(bytes)
        .ok()
        .and_then(|fm| {
            time::OffsetDateTime::parse(
                &fm.modified_at,
                &time::format_description::well_known::Rfc3339,
            )
            .ok()
        })
        .map(|dt| dt.unix_timestamp() as u64)
        .unwrap_or(0)
}

/// Full state machine for STRONG_HA zones.
///
/// Metadata lives in redb for durability; advisory locks live in an
/// in-memory `Arc<Mutex<LockState>>` BTreeMap that is the single source
/// of truth shared with the kernel's `LockManager`. This matches the
/// raft invariant that apply is an atomic commit point — readers and
/// writers both hit the same mutex, so there is no divergence window.
///
/// # Storage Layout
///
/// ```text
/// redb database
/// └── sm_metadata/        # File metadata (key: path)
///     ├── "/zone/file1" -> FileMetadata (serialized)
///     ├── "/zone/file2" -> FileMetadata (serialized)
///     └── ...
///
/// in-memory
/// └── advisory: Arc<Mutex<LockState>> # Advisory locks (BTreeMap)
/// ```
///
/// Advisory-lock persistence happens through raft snapshots: `snapshot`
/// serializes the BTreeMap under the mutex; `restore_snapshot`
/// deserializes and replaces the BTreeMap under the same mutex. Between
/// snapshots, the raft log is the durable record — advisory state is
/// rebuilt by log replay on restart.
pub struct FullStateMachine {
    /// Metadata tree: path -> serialized FileMetadata.
    metadata: RedbTree,
    /// Raw-byte stream entries tree (R19.1b') — key -> opaque bytes.
    ///
    /// Distinct from ``metadata`` so WAL stream payloads never appear
    /// in file-listing scans / snapshots that walk ``sm_metadata``.
    stream_entries: RedbTree,
    /// Auth-key records tree — ``key_hash`` -> opaque record bytes.
    ///
    /// Distinct from ``metadata`` for the same reason as
    /// ``stream_entries``: the values are not ``FileMetadata`` protos,
    /// so they must stay off the file-metadata path. Written by
    /// ``Command::PutControlState`` / ``DeleteControlState``; read by
    /// [`Self::get_control_state`] / [`Self::list_control_state`]. Keyed by
    /// ``namespace\0key``.
    control_state: RedbTree,
    /// Advisory lock SSOT — shared with the kernel's `LockManager`.
    advisory: Arc<Mutex<LockState>>,
    /// Last applied metadata/Noop log index (persisted to redb).
    ///
    /// Gates metadata-command idempotency during log replay —
    /// `AdjustCounter` would double-count otherwise. Lock commands
    /// are idempotent under full replay (acquire/release cycles
    /// cancel out) so they ignore this guard and always apply.
    ///
    /// Held as ``Arc<AtomicU64>`` so the ZoneConsensus handle can
    /// publish its current value to sync Python readers (gate tests,
    /// monitoring) without acquiring the state-machine's async
    /// RwLock. The state machine is the SSOT; the Arc is how we
    /// surface it, not a shadow copy.
    last_applied: Arc<AtomicU64>,
    /// Unified apply-side observer list — shared ``Arc<RwLock<Vec<..>>>``
    /// so downstream owners can ``push`` observers *after* this state
    /// machine is moved into ``ZoneConsensus``.
    ///
    /// Fires once per committed metadata-path command (after the apply
    /// txn commits) with an [`AppliedEntry`]. This is the single spine
    /// that federation-mount wiring, DCache invalidation, and (future)
    /// A2A / auth-cache eviction all subscribe to — one mechanism
    /// instead of a bespoke slot per consumer. Each observer matches the
    /// command variants it cares about and ignores the rest.
    ///
    /// Empty when nothing is wired (tests, witness nodes) — the send
    /// site is gated on non-empty so apply stays a no-op. Every observer
    /// is invoked under ``catch_unwind`` so a panicking one can't poison
    /// apply per raft's "apply must not fail" rule.
    ///
    /// Elements are [`ApplyObserver`] — a `(dedup_key, cb)` pair so a
    /// keyed consumer (federation mount) replaces its prior registration
    /// on re-install while anonymous ones (DCache) accumulate.
    apply_observers: Arc<parking_lot::RwLock<Vec<ApplyObserver>>>,
}

impl FullStateMachine {
    /// Create a new full state machine with its own advisory-lock Arc.
    ///
    /// Callers that need to share the advisory map with a kernel
    /// `LockManager` should use [`FullStateMachine::with_advisory`]
    /// and pre-build the Arc there.
    pub fn new(store: &RedbStore) -> Result<Self> {
        Self::with_advisory(store, Arc::new(Mutex::new(LockState::new())))
    }

    /// Create a new full state machine that shares its advisory map
    /// with the provided `Arc<Mutex<LockState>>`. Used by the kernel's
    /// `LockManager::upgrade_to_distributed` path so local holders
    /// survive the upgrade and every reader on the node sees the same
    /// state.
    pub fn with_advisory(store: &RedbStore, advisory: Arc<Mutex<LockState>>) -> Result<Self> {
        let metadata = store.tree(TREE_METADATA)?;
        let stream_entries = store.tree(TREE_STREAM_ENTRIES)?;
        let control_state = store.tree(TREE_CONTROL_STATE)?;

        // Load last_applied from metadata tree.
        let last_applied = match metadata.get(KEY_LAST_APPLIED)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| super::RaftError::Storage("invalid last_applied".into()))?;
                u64::from_be_bytes(arr)
            }
            None => 0,
        };

        Ok(Self {
            metadata,
            stream_entries,
            control_state,
            advisory,
            last_applied: Arc::new(AtomicU64::new(last_applied)),
            apply_observers: Arc::new(parking_lot::RwLock::new(Vec::new())),
        })
    }

    /// Return a clone of the shared ``last_applied`` atomic so a caller
    /// outside the state-machine's RwLock can publish "state machine has
    /// this index" as an atomic read. The state machine remains the
    /// SSOT; this is how the value is surfaced, not a shadow.
    pub fn last_applied_shared_arc(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.last_applied)
    }

    /// Clone the shared advisory-lock handle. Used by the kernel's
    /// `LockManager::upgrade_to_distributed` to adopt the state
    /// machine's `Arc<Mutex<LockState>>` after the zone is set up.
    pub fn advisory_state(&self) -> Arc<Mutex<LockState>> {
        self.advisory.clone()
    }

    /// Get current Unix timestamp. Public so proposal sites can capture
    /// the timestamp before it enters the replicated command.
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Apply SetMetadata command.
    fn apply_set_metadata(&self, key: &str, value: &[u8]) -> Result<CommandResult> {
        self.metadata.set(key.as_bytes(), value)?;
        Ok(CommandResult::Success)
    }

    /// Peek at a key's current committed value and decide whether it's
    /// a DT_MOUNT entry. Used by ``apply`` as a pre-read before the
    /// write txn to capture the pre-delete payload-classification for
    /// ``DeleteMetadata`` commands.
    ///
    /// Apply is serial, so no concurrent writer can mutate ``key``
    /// between this pre-read and the write txn that performs the
    /// delete. The read happens in its own short read txn.
    ///
    /// Returns ``true`` iff the current value decodes as a
    /// ``FileMetadata`` with ``entry_type == DT_MOUNT``. Decode failure
    /// or missing key both return ``false`` — those cases aren't
    /// DT_MOUNT and don't need a Delete event.
    #[cfg(feature = "grpc")]
    fn peek_is_dt_mount(&self, key: &str) -> bool {
        use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
        use prost::Message as ProstMessage;

        const DT_MOUNT: i32 = 2;
        let Ok(Some(bytes)) = self.metadata.get(key.as_bytes()) else {
            return false;
        };
        match ProtoFileMetadata::decode(bytes.as_slice()) {
            Ok(p) => p.entry_type == DT_MOUNT,
            Err(_) => false,
        }
    }

    /// Translate a committed command into a [`MountApplyEvent`], or
    /// ``None`` if it isn't a DT_MOUNT set / remove. The mount observer
    /// calls this; the pre-image (``removed_mount_key``) is captured in
    /// ``apply`` before the write txn (the one fact not recomputable
    /// post-commit).
    ///
    /// - Set path: decode the ``SetMetadata`` value; if it's a DT_MOUNT
    ///   with non-empty ``target_zone_id`` → ``Set``. Otherwise, if this
    ///   overwrote a prior DT_MOUNT (``removed_mount_key == Some(key)``)
    ///   → ``Delete`` (e.g. federation_unmount writes DT_DIR at the mount
    ///   path). Else ``None``.
    /// - Delete path: ``Delete`` iff ``removed_mount_key == Some(key)``.
    /// - proto decode failure on Set → ``warn!`` + ``None`` (upstream
    ///   writer wrote garbage; apply can't reject committed entries).
    #[cfg(feature = "grpc")]
    pub(crate) fn mount_apply_event_from(
        command: &Command,
        removed_mount_key: Option<&str>,
    ) -> Option<MountApplyEvent> {
        use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
        use prost::Message as ProstMessage;

        match command {
            Command::SetMetadata { key, value } => {
                let proto = match ProtoFileMetadata::decode(value.as_slice()) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            path = %key,
                            error = %e,
                            "mount-apply: FileMetadata decode failed on apply (non-FileMetadata SetMetadata?)",
                        );
                        return None;
                    }
                };
                const DT_MOUNT: i32 = 2;
                if proto.entry_type == DT_MOUNT && !proto.target_zone_id.is_empty() {
                    Some(MountApplyEvent::Set {
                        key: key.clone(),
                        target_zone_id: proto.target_zone_id,
                    })
                } else if removed_mount_key == Some(key.as_str()) {
                    // Overwrite of prior DT_MOUNT with a non-mount entry
                    // (e.g. federation_unmount writes DT_DIR at the mount
                    // path). Fire Delete so wire_federation_mount_impl
                    // removes this mount from the local VFSRouter.
                    Some(MountApplyEvent::Delete { key: key.clone() })
                } else {
                    None
                }
            }
            Command::DeleteMetadata { key } if removed_mount_key == Some(key.as_str()) => {
                Some(MountApplyEvent::Delete { key: key.clone() })
            }
            _ => None,
        }
    }

    /// Fire the unified apply-side observers for a committed command.
    ///
    /// Called once per committed metadata-path command, AFTER the apply
    /// txn commits. Each registered observer is invoked with the same
    /// [`AppliedEntry`] and must match the variants it cares about
    /// (mount wiring: DT_MOUNT Set/Delete; DCache: Set/Cas/Delete; etc.)
    /// — ignoring the rest. Every observer runs under ``catch_unwind`` so
    /// a panicking one can't poison apply (raft's "apply must not fail").
    /// The no-observer path returns before building the entry.
    fn emit_apply_observers(&self, index: u64, command: &Command, removed_mount_key: Option<&str>) {
        // Snapshot the observer vec under the read lock, release before
        // invoking — observers must never reacquire this lock (a future
        // installer would deadlock) and must stay short to not stall the
        // apply loop.
        let observers = self.apply_observers.read().clone();
        if observers.is_empty() {
            return;
        }
        let entry = AppliedEntry {
            index,
            command,
            removed_mount_key,
        };
        for (_key, obs) in observers {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| obs(&entry)))
            {
                tracing::error!(
                    index,
                    payload = ?payload,
                    "apply-observer panicked; continuing apply — coherence may be incomplete for this entry",
                );
            }
        }
    }

    /// Apply AdjustCounter command — atomic read-modify-write in apply().
    ///
    /// Reads the current i64 value (0 if absent), adds delta, clamps to >= 0,
    /// writes back. All within the serial `apply()` — no race possible.
    /// Returns the new value as `Value(i64 big-endian bytes)`.
    fn apply_adjust_counter(&self, key: &str, delta: i64) -> Result<CommandResult> {
        let current = self
            .metadata
            .get(key.as_bytes())?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(i64::from_be_bytes)
            .unwrap_or(0);
        let new_val = (current + delta).max(0);
        self.metadata.set(key.as_bytes(), &new_val.to_be_bytes())?;
        Ok(CommandResult::Value(new_val.to_be_bytes().to_vec()))
    }

    /// Apply CasSetMetadata command — atomic compare-and-swap on version.
    ///
    /// Reads the current value and conditionally writes within a **single
    /// redb WriteTransaction**. This prevents TOCTOU races: no concurrent
    /// writer can observe the same version and succeed.
    fn apply_cas_set_metadata(
        &self,
        key: &str,
        value: &[u8],
        expected_version: u32,
    ) -> Result<CommandResult> {
        let db = self.metadata.raw_db();
        let table_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.metadata.name());
        let write_txn = db
            .begin_write()
            .map_err(|e| super::RaftError::Storage(e.to_string()))?;

        let result;
        {
            let mut table = write_txn
                .open_table(table_def)
                .map_err(|e| super::RaftError::Storage(e.to_string()))?;

            let current_version = match table
                .get(key.as_bytes())
                .map_err(|e: redb::StorageError| super::RaftError::Storage(e.to_string()))?
            {
                Some(guard) => Self::extract_version(guard.value()),
                None => 0,
            };

            if current_version != expected_version {
                result = CommandResult::CasResult {
                    success: false,
                    current_version,
                };
            } else {
                table
                    .insert(key.as_bytes(), value)
                    .map_err(|e| super::RaftError::Storage(e.to_string()))?;

                // The new version is embedded in `value` (serialized by Python).
                // Return expected_version + 1 as a hint, but the authoritative
                // version is in the serialized bytes.
                result = CommandResult::CasResult {
                    success: true,
                    current_version: expected_version + 1,
                };
            }
        }

        write_txn
            .commit()
            .map_err(|e| super::RaftError::Storage(e.to_string()))?;
        Ok(result)
    }

    /// Extract the version field from serialized FileMetadata.
    ///
    /// Supports both protobuf (field 9, varint) and JSON formats.
    /// Returns 0 if extraction fails (treat as "never written").
    fn extract_version(bytes: &[u8]) -> u32 {
        // Try protobuf first: field 9 = tag (9 << 3 | 0) = 72 = 0x48
        // Scan for tag byte 0x48 followed by a varint
        let mut i = 0;
        while i < bytes.len() {
            let tag_byte = bytes[i];
            let field_number = tag_byte >> 3;
            let wire_type = tag_byte & 0x07;

            if field_number == 9 && wire_type == 0 {
                // Found version field — decode varint
                i += 1;
                if i < bytes.len() {
                    return Self::decode_varint(&bytes[i..]) as u32;
                }
            }

            // Skip to next field based on wire type
            i += 1;
            match wire_type {
                0 => {
                    // Varint: skip bytes with MSB set
                    while i < bytes.len() && bytes[i] & 0x80 != 0 {
                        i += 1;
                    }
                    i += 1; // skip final byte
                }
                1 => i += 8, // 64-bit
                2 => {
                    // Length-delimited
                    let (len, consumed) = Self::decode_varint_with_len(&bytes[i..]);
                    i += consumed + len as usize;
                }
                5 => i += 4, // 32-bit
                _ => break,  // unknown wire type
            }
        }

        // Protobuf extraction failed — try JSON fallback
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Some(pos) = text.find("\"version\"") {
                // Simple JSON extraction: find "version": <number>
                let after = &text[pos + 9..];
                if let Some(colon) = after.find(':') {
                    let num_str = after[colon + 1..].trim_start();
                    let end = num_str
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(num_str.len());
                    if let Ok(v) = num_str[..end].parse::<u32>() {
                        return v;
                    }
                }
            }
        }

        0 // default: treat as never written
    }

    /// Decode a protobuf varint from bytes.
    fn decode_varint(bytes: &[u8]) -> u64 {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        for &byte in bytes {
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        result
    }

    /// Decode a protobuf varint and return (value, bytes_consumed).
    fn decode_varint_with_len(bytes: &[u8]) -> (u64, usize) {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        for (i, &byte) in bytes.iter().enumerate() {
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                return (result, i + 1);
            }
            shift += 7;
        }
        (result, bytes.len())
    }

    /// Apply DeleteMetadata command.
    fn apply_delete_metadata(&self, key: &str) -> Result<CommandResult> {
        self.metadata.delete(key.as_bytes())?;
        Ok(CommandResult::Success)
    }

    /// Apply AcquireLock — delegates to `LockState::apply_acquire` under
    /// the shared advisory mutex.
    ///
    /// `now` is the wall-clock timestamp captured at proposal time so
    /// all replicas reach identical state (#3029 / Bug 1).
    fn apply_acquire_lock(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u32,
        holder_info: &str,
        now: u64,
    ) -> Result<CommandResult> {
        let mut guard = self.advisory.lock();
        let result = guard.apply_acquire(path, lock_id, max_holders, ttl_secs, holder_info, now);
        Ok(CommandResult::LockResult(result))
    }

    /// Apply ReleaseLock — delegates to `LockState::apply_release`.
    fn apply_release_lock(&self, path: &str, lock_id: &str) -> Result<CommandResult> {
        let mut guard = self.advisory.lock();
        if guard.apply_release(path, lock_id) {
            Ok(CommandResult::Success)
        } else if guard.get_lock(path).is_none() {
            Ok(CommandResult::Error("Lock not found".to_string()))
        } else {
            Ok(CommandResult::Error("Lock holder not found".to_string()))
        }
    }

    /// Apply ForceReleaseLock — delegates to `LockState::apply_force_release`.
    fn apply_force_release_lock(&self, path: &str) -> Result<CommandResult> {
        let mut guard = self.advisory.lock();
        if guard.apply_force_release(path) {
            Ok(CommandResult::Success)
        } else {
            Ok(CommandResult::Error("Lock not found".to_string()))
        }
    }

    /// Apply ExtendLock — delegates to `LockState::apply_extend`.
    fn apply_extend_lock(
        &self,
        path: &str,
        lock_id: &str,
        new_ttl_secs: u32,
        now: u64,
    ) -> Result<CommandResult> {
        let mut guard = self.advisory.lock();
        if guard.apply_extend(path, lock_id, new_ttl_secs, now) {
            Ok(CommandResult::Success)
        } else if guard.get_lock(path).is_none() {
            Ok(CommandResult::Error("Lock not found".to_string()))
        } else {
            Ok(CommandResult::Error("Lock holder not found".to_string()))
        }
    }

    /// Get metadata by path.
    pub fn get_metadata(&self, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.metadata.get(path.as_bytes())?)
    }

    /// Get metadata for multiple paths in a single call.
    pub fn get_metadata_multi(&self, paths: &[String]) -> Result<Vec<(String, Option<Vec<u8>>)>> {
        paths
            .iter()
            .map(|path| self.get_metadata(path).map(|opt| (path.clone(), opt)))
            .collect()
    }

    /// List all metadata with prefix.
    pub fn list_metadata(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut result = Vec::new();
        for item in self.metadata.scan_prefix(prefix.as_bytes()) {
            let (key, value) = item?;
            if let Ok(path) = String::from_utf8(key) {
                // Skip internal keys
                if !path.starts_with("__") {
                    result.push((path, value));
                }
            }
        }
        Ok(result)
    }

    /// Iterate every DT_MOUNT entry in this state machine, returning
    /// ``(key, target_zone_id)`` pairs.
    ///
    /// Used by the kernel's startup replay to re-drive every historic
    /// federation mount through ``wire_federation_mount`` — apply-cb
    /// only fires on new applies, so restart-from-snapshot wouldn't
    /// otherwise wire the mounts already in state.
    ///
    /// Lenient: skips entries that fail to decode or aren't DT_MOUNT
    /// or have an empty target_zone_id.
    #[cfg(feature = "grpc")]
    pub fn iter_dt_mount_entries(&self) -> Result<Vec<(String, String)>> {
        use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
        use prost::Message as ProstMessage;

        let mut result = Vec::new();
        for (key, bytes) in self.list_metadata("/")? {
            let Ok(proto) = ProtoFileMetadata::decode(bytes.as_slice()) else {
                continue;
            };
            const DT_MOUNT: i32 = 2;
            if proto.entry_type == DT_MOUNT && !proto.target_zone_id.is_empty() {
                result.push((key, proto.target_zone_id));
            }
        }
        Ok(result)
    }

    /// Get a stream entry by key (R19.1b').
    ///
    /// Looks up the opaque bytes previously stored by
    /// ``Command::AppendStreamEntry``. Returns ``Ok(None)`` if absent.
    pub fn get_stream_entry(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.stream_entries.get(key.as_bytes())?)
    }

    /// Current next-offset cursor for a stream (``0`` if nothing written yet).
    ///
    /// Reads the `__stream_tail__` sidecar the `AppendStreamEntry` apply keeps
    /// beside the entries — the SSOT for how many entries the stream holds,
    /// correct across ALL writers because every append replicates + applies on
    /// every node in the same committed order.
    pub fn stream_tail(&self, stream_prefix: &str) -> Result<u64> {
        let key = stream_tail_key(stream_prefix);
        Ok(self
            .stream_entries
            .get(key.as_bytes())?
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0))
    }

    /// Current cold-tier floor (`earliest_hot`) for a stream — the lowest seq
    /// still in the hot tree. `0` until the first seal. A reader that misses a
    /// `get_stream_entry` and finds `seq < floor` knows the seq was spilled to a
    /// cold segment (vs. simply not written yet), and resolves it via
    /// [`Self::find_segment`].
    pub fn stream_floor(&self, stream_prefix: &str) -> Result<u64> {
        let key = stream_floor_key(stream_prefix);
        Ok(self
            .stream_entries
            .get(key.as_bytes())?
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0))
    }

    /// Find the sealed cold segment covering `seq` (`base <= seq < end`),
    /// returning `(base, record)`, or `None` if no segment holds it. Segments
    /// are contiguous and non-overlapping, so at most one matches. `base` (the
    /// key, not the value) is returned so a reader can compute the frame's
    /// position within the segment blob (`seq - base`).
    ///
    /// Uses a bounded reverse-range scan over this stream's `__stream_seg__`
    /// records (keys are zero-padded so lexicographic order == base order): the
    /// greatest `base <= seq`, then a `seq < end` check. O(log n) in the segment
    /// count — never a full-tree walk — so cold reads stay cheap.
    pub fn find_segment(
        &self,
        stream_prefix: &str,
        seq: u64,
    ) -> Result<Option<(u64, SegmentRecord)>> {
        let seg_prefix = stream_segment_key_prefix(stream_prefix);
        // Upper bound: the key a segment based exactly at `seq` would have. The
        // greatest key <= this whose base <= seq is the candidate.
        let upper = stream_segment_key(stream_prefix, seq);

        let db = self.stream_entries.raw_db();
        let read_txn = db
            .begin_read()
            .map_err(|e| super::RaftError::Storage(format!("find_segment begin_read: {e}")))?;
        let table_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.stream_entries.name());
        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => {
                return Err(super::RaftError::Storage(format!(
                    "find_segment open_table: {e}"
                )))
            }
        };
        // Inclusive range over THIS stream's segment keyspace, upper-bounded by
        // the `seq`-based key; `next_back()` = greatest base <= seq.
        let mut range = table
            .range(seg_prefix.as_bytes()..=upper.as_bytes())
            .map_err(|e| super::RaftError::Storage(format!("find_segment range: {e}")))?;
        match range.next_back() {
            Some(entry) => {
                let (k, v) = entry
                    .map_err(|e| super::RaftError::Storage(format!("find_segment iter: {e}")))?;
                // Recover base from the key suffix ({seg_prefix}{base:020}).
                let base = std::str::from_utf8(k.value())
                    .ok()
                    .and_then(|ks| ks.strip_prefix(seg_prefix.as_str()))
                    .and_then(|b| b.parse::<u64>().ok());
                match (base, decode_segment_record(v.value())) {
                    (Some(base), Some(rec)) if base <= seq && seq < rec.end => {
                        Ok(Some((base, rec)))
                    }
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Current `earliest` readable seq (retention floor) — `0` until the first
    /// trim. A read below it is truncated (dropped by retention).
    pub fn stream_earliest(&self, stream_prefix: &str) -> Result<u64> {
        let key = stream_earliest_key(stream_prefix);
        Ok(self
            .stream_entries
            .get(key.as_bytes())?
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0))
    }

    /// Every cold segment of a stream, as `(base, record)` ordered by base — the
    /// trimmer's view for summing cold bytes, choosing a trim boundary, and
    /// collecting the dropped blobs' refs. Segments are bounded metadata, so a
    /// forward range scan over this stream's `__stream_seg__` keyspace is cheap.
    pub fn list_segments(&self, stream_prefix: &str) -> Result<Vec<(u64, SegmentRecord)>> {
        let seg_prefix = stream_segment_key_prefix(stream_prefix);
        let mut upper = seg_prefix.clone().into_bytes();
        // Exclusive-ish upper bound covering all `{seg_prefix}{base:020}` keys.
        upper.push(0xff);

        let db = self.stream_entries.raw_db();
        let read_txn = db
            .begin_read()
            .map_err(|e| super::RaftError::Storage(format!("list_segments begin_read: {e}")))?;
        let table_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.stream_entries.name());
        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => {
                return Err(super::RaftError::Storage(format!(
                    "list_segments open_table: {e}"
                )))
            }
        };
        let range = table
            .range(seg_prefix.as_bytes()..=upper.as_slice())
            .map_err(|e| super::RaftError::Storage(format!("list_segments range: {e}")))?;
        let mut out = Vec::new();
        for entry in range {
            let (k, v) =
                entry.map_err(|e| super::RaftError::Storage(format!("list_segments iter: {e}")))?;
            let base = std::str::from_utf8(k.value())
                .ok()
                .and_then(|ks| ks.strip_prefix(seg_prefix.as_str()))
                .and_then(|b| b.parse::<u64>().ok());
            if let (Some(base), Some(rec)) = (base, decode_segment_record(v.value())) {
                out.push((base, rec));
            }
        }
        Ok(out)
    }

    /// Look up a cluster-control value by ``(namespace, key)``.
    ///
    /// Returns the opaque bytes stored by ``Command::PutControlState``
    /// (``Ok(None)`` if absent or revoked). Reads the locally-applied state
    /// machine — no consensus round-trip — so it is cheap enough for the auth
    /// provider's (and the cross-org verifier's) per-RPC lookup on a cache miss.
    pub fn get_control_state(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.control_state.get(&control_key(namespace, key))?)
    }

    /// Enumerate every value in one namespace as ``(key, value_bytes)``.
    ///
    /// A ``namespace\0`` prefix scan. Backs the admin-only
    /// ``/__sys__/auth/keys/`` procfs view + key-management tooling (via
    /// [`Self::list_auth_keys`]) and the cross-org anchor registry. Not a hot
    /// path — a full-tree scan filtered by prefix.
    pub fn list_control_state(&self, namespace: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut prefix = namespace.as_bytes().to_vec();
        prefix.push(0);
        let mut out = Vec::new();
        for item in self.control_state.iter() {
            let (k, value) = item?;
            if k.len() > prefix.len() && k[..prefix.len()] == prefix[..] {
                if let Ok(key) = String::from_utf8(k[prefix.len()..].to_vec()) {
                    out.push((key, value));
                }
            }
        }
        Ok(out)
    }

    /// Look up an API-key/agent record by its ``key_hash`` — the
    /// [`contracts::CONTROL_NS_AUTH`] view of [`Self::get_control_state`].
    pub fn get_auth_key(&self, key_hash: &str) -> Result<Option<Vec<u8>>> {
        self.get_control_state(contracts::CONTROL_NS_AUTH, key_hash)
    }

    /// Enumerate every auth record as ``(key_hash, record_bytes)`` — the
    /// [`contracts::CONTROL_NS_AUTH`] view of [`Self::list_control_state`].
    pub fn list_auth_keys(&self) -> Result<Vec<(String, Vec<u8>)>> {
        self.list_control_state(contracts::CONTROL_NS_AUTH)
    }

    /// Get lock info by path (reads the shared advisory map).
    pub fn get_lock(&self, path: &str) -> Result<Option<LockInfo>> {
        Ok(self.advisory.lock().get_lock(path))
    }

    /// List all locks matching a prefix (reads the shared advisory map).
    pub fn list_locks(&self, prefix: &str, limit: usize) -> Result<Vec<LockInfo>> {
        Ok(self.advisory.lock().list_locks(prefix, limit))
    }
}

/// Snapshot format for FullStateMachine.
///
/// ``stream_entries`` is serialized with a ``#[serde(default)]`` so
/// snapshots produced before R19.1b' (no stream table) still restore —
/// absent entries become an empty map on the target replica.
#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    /// All metadata entries.
    metadata: HashMap<String, Vec<u8>>,
    /// All stream entries (R19.1b').
    #[serde(default)]
    stream_entries: HashMap<String, Vec<u8>>,
    /// All cluster-control records, keyed by the composite ``namespace\0key``
    /// (NUL is valid UTF-8, so it round-trips through the `String` map).
    /// ``serde(default)`` so pre-control-store snapshots still restore (empty).
    #[serde(default)]
    control_state: HashMap<String, Vec<u8>>,
    /// Advisory lock SSOT at snapshot time (clone of the BTreeMap).
    advisory: LockState,
    /// Last applied index.
    last_applied: u64,
}

impl FullStateMachine {
    /// Shared command dispatch — the actual redb operations.
    ///
    /// Used by `apply_local()` (EC) and `apply_ec_with_lww()`. Each sub-method
    /// opens its own redb transaction internally.
    ///
    /// For the Raft `apply()` path, use `execute_in_txn()` instead — it runs
    /// inside a caller-provided transaction for atomicity with `last_applied`.
    fn execute(&self, command: &Command) -> Result<CommandResult> {
        match command {
            Command::SetMetadata { key, value } => self.apply_set_metadata(key, value),
            Command::CasSetMetadata {
                key,
                value,
                expected_version,
            } => self.apply_cas_set_metadata(key, value, *expected_version),
            Command::DeleteMetadata { key } => self.apply_delete_metadata(key),
            Command::AcquireLock {
                path,
                lock_id,
                max_holders,
                ttl_secs,
                holder_info,
                now_secs,
            } => self.apply_acquire_lock(
                path,
                lock_id,
                *max_holders,
                *ttl_secs,
                holder_info,
                *now_secs,
            ),
            Command::ReleaseLock { path, lock_id } => self.apply_release_lock(path, lock_id),
            Command::ForceReleaseLock { path } => self.apply_force_release_lock(path),
            Command::ExtendLock {
                path,
                lock_id,
                new_ttl_secs,
                now_secs,
            } => self.apply_extend_lock(path, lock_id, *new_ttl_secs, *now_secs),
            Command::AdjustCounter { key, delta } => self.apply_adjust_counter(key, *delta),
            Command::AppendStreamEntry { .. } => Err(super::RaftError::InvalidState(
                "AppendStreamEntry must apply via execute_metadata_in_txn (the offset is \
                 assigned atomically at raft apply); the non-txn path must never receive it"
                    .into(),
            )),
            Command::SealStreamSegment { .. } => Err(super::RaftError::InvalidState(
                "SealStreamSegment must apply via execute_metadata_in_txn (index write + hot-row \
                 delete + floor advance are one atomic txn); the non-txn path must never receive it"
                    .into(),
            )),
            Command::TrimStreamSegment { .. } => Err(super::RaftError::InvalidState(
                "TrimStreamSegment must apply via execute_metadata_in_txn (index delete + earliest \
                 advance are one atomic txn); the non-txn path must never receive it"
                    .into(),
            )),
            Command::PutControlState {
                namespace,
                key,
                value,
                if_absent,
            } => {
                let ckey = control_key(namespace, key);
                if *if_absent && self.control_state.get(&ckey)?.is_some() {
                    // CAS reject — applied (log entry consumed) but the write is
                    // refused; propose() surfaces this as an error.
                    return Ok(CommandResult::Error(format!(
                        "control state {namespace}/{key} already exists"
                    )));
                }
                self.control_state.set(&ckey, value)?;
                Ok(CommandResult::Success)
            }
            Command::DeleteControlState { namespace, key } => {
                self.control_state.delete(&control_key(namespace, key))?;
                Ok(CommandResult::Success)
            }
            Command::Noop => Ok(CommandResult::Success),
        }
    }

    /// Execute a metadata/Noop command inside a caller-provided redb write
    /// transaction. Lock commands don't flow through this path — they only
    /// mutate the in-memory advisory `LockState` and never touch redb.
    ///
    /// This is the transactional variant of `execute()`, used by `apply()` to
    /// ensure metadata mutations and the `last_applied` marker are persisted
    /// atomically in a single redb transaction (matching etcd/CockroachDB/TiKV
    /// practice). Without this, a crash between execute and save_last_applied
    /// could cause non-idempotent commands (e.g. AdjustCounter) to replay.
    fn execute_metadata_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        command: &Command,
    ) -> Result<CommandResult> {
        let meta_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.metadata.name());

        match command {
            Command::SetMetadata { key, value } => {
                let mut table = txn
                    .open_table(meta_def)
                    .map_err(|e| super::RaftError::Storage(format!("open metadata: {e}")))?;
                table
                    .insert(key.as_bytes(), value.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert metadata: {e}")))?;
                Ok(CommandResult::Success)
            }

            Command::CasSetMetadata {
                key,
                value,
                expected_version,
            } => {
                let mut table = txn
                    .open_table(meta_def)
                    .map_err(|e| super::RaftError::Storage(format!("open metadata: {e}")))?;
                let current = table
                    .get(key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get metadata: {e}")))?
                    .map(|v| v.value().to_vec());
                let current_version = match &current {
                    Some(bytes) => Self::extract_version(bytes),
                    None => 0,
                };
                if current_version != *expected_version {
                    return Ok(CommandResult::CasResult {
                        success: false,
                        current_version,
                    });
                }
                table
                    .insert(key.as_bytes(), value.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert metadata: {e}")))?;
                Ok(CommandResult::CasResult {
                    success: true,
                    current_version: expected_version + 1,
                })
            }

            Command::DeleteMetadata { key } => {
                let mut table = txn
                    .open_table(meta_def)
                    .map_err(|e| super::RaftError::Storage(format!("open metadata: {e}")))?;
                table
                    .remove(key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("remove metadata: {e}")))?;
                Ok(CommandResult::Success)
            }

            Command::AdjustCounter { key, delta } => {
                let mut table = txn
                    .open_table(meta_def)
                    .map_err(|e| super::RaftError::Storage(format!("open metadata: {e}")))?;
                let current = table
                    .get(key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get metadata: {e}")))?
                    .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                    .map(i64::from_be_bytes)
                    .unwrap_or(0);
                let new_val = (current + delta).max(0);
                table
                    .insert(key.as_bytes(), new_val.to_be_bytes().as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert counter: {e}")))?;
                Ok(CommandResult::Value(new_val.to_be_bytes().to_vec()))
            }

            Command::AppendStreamEntry {
                stream_prefix,
                data,
            } => {
                // Assign the offset HERE, at raft apply, in committed order — so
                // a total order holds even across concurrent writers (the log
                // serializes them). The next-offset cursor lives beside the
                // entries in the SAME tree + txn, so it can never diverge from
                // them and it rides the state-machine snapshot for free. This is
                // the linearizable-log contract: the caller never picks a seq,
                // so two writers cannot collide.
                let stream_def =
                    redb::TableDefinition::<&[u8], &[u8]>::new(self.stream_entries.name());
                let mut table = txn
                    .open_table(stream_def)
                    .map_err(|e| super::RaftError::Storage(format!("open stream_entries: {e}")))?;
                let tail_key = stream_tail_key(stream_prefix);
                let seq = table
                    .get(tail_key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get stream tail: {e}")))?
                    .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0);
                let entry_key = format!("{stream_prefix}{seq}");
                table
                    .insert(entry_key.as_bytes(), data.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert stream_entry: {e}")))?;
                table
                    .insert(tail_key.as_bytes(), (seq + 1).to_be_bytes().as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("bump stream tail: {e}")))?;
                Ok(CommandResult::Value(seq.to_be_bytes().to_vec()))
            }

            Command::SealStreamSegment {
                stream_prefix,
                base,
                end,
                content_id,
                origin,
                size,
            } => {
                // Deterministic, redb-only tiered-storage roll: write the cold
                // segment index record, delete the sealed hot rows, advance the
                // floor — all in this one apply txn, in committed order, so every
                // replica converges. The blob itself is NOT touched here (it was
                // written to the content pillar before this command); apply must
                // stay a pure, non-blocking redb mutation.
                let stream_def =
                    redb::TableDefinition::<&[u8], &[u8]>::new(self.stream_entries.name());
                let mut table = txn
                    .open_table(stream_def)
                    .map_err(|e| super::RaftError::Storage(format!("open stream_entries: {e}")))?;

                // Gate: seal contiguously from the current floor, within the
                // written range. A stale/racing proposal (base != floor) or an
                // over-reach (end > tail) is refused as a no-op error — the log
                // entry is consumed but nothing is mutated, and propose() surfaces
                // the error so the proposer retries next cycle with a fresh floor.
                let floor_key = stream_floor_key(stream_prefix);
                let floor = table
                    .get(floor_key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get stream floor: {e}")))?
                    .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0);
                let tail_key = stream_tail_key(stream_prefix);
                let tail = table
                    .get(tail_key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get stream tail: {e}")))?
                    .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0);
                if *base != floor || *end <= *base || *end > tail {
                    return Ok(CommandResult::Error(format!(
                        "stale/invalid seal {stream_prefix} [{base},{end}) \
                         (floor={floor}, tail={tail})"
                    )));
                }

                // 1. Segment index record.
                let seg_key = stream_segment_key(stream_prefix, *base);
                let rec = encode_segment_record(*end, *size, origin, content_id);
                table
                    .insert(seg_key.as_bytes(), rec.as_slice())
                    .map_err(|e| {
                        super::RaftError::Storage(format!("insert stream segment: {e}"))
                    })?;

                // 2. Delete the sealed hot rows [base, end) — this is what bounds
                //    the SM state + snapshot content.
                for seq in *base..*end {
                    let entry_key = format!("{stream_prefix}{seq}");
                    table.remove(entry_key.as_bytes()).map_err(|e| {
                        super::RaftError::Storage(format!("remove sealed stream_entry: {e}"))
                    })?;
                }

                // 3. Advance the floor.
                table
                    .insert(floor_key.as_bytes(), end.to_be_bytes().as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("advance stream floor: {e}")))?;

                Ok(CommandResult::Success)
            }

            Command::TrimStreamSegment {
                stream_prefix,
                up_to_seq,
                ..
            } => {
                // Deterministic, redb-only retention trim: drop the cold segment
                // index entries fully below up_to_seq and advance `earliest`. The
                // blob bytes are GC'd off-band by the kernel trim-GC observer
                // (driven by the command's `trimmed` list); apply stays pure redb.
                let stream_def =
                    redb::TableDefinition::<&[u8], &[u8]>::new(self.stream_entries.name());
                let mut table = txn
                    .open_table(stream_def)
                    .map_err(|e| super::RaftError::Storage(format!("open stream_entries: {e}")))?;

                let earliest_key = stream_earliest_key(stream_prefix);
                let earliest = table
                    .get(earliest_key.as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get stream earliest: {e}")))?
                    .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0);
                let floor = table
                    .get(stream_floor_key(stream_prefix).as_bytes())
                    .map_err(|e| super::RaftError::Storage(format!("get stream floor: {e}")))?
                    .and_then(|v| <[u8; 8]>::try_from(v.value()).ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0);
                // Gate: only advance, and only over sealed (cold) seqs — never
                // trim the hot tail. A stale / over-reaching trim is a no-op error.
                if *up_to_seq <= earliest || *up_to_seq > floor {
                    return Ok(CommandResult::Error(format!(
                        "stale/invalid trim {stream_prefix} up_to={up_to_seq} \
                         (earliest={earliest}, floor={floor})"
                    )));
                }

                // Collect the segment keys fully below up_to_seq (end <= up_to).
                // Collect first (owned) so the range borrow ends before we remove.
                let seg_prefix = stream_segment_key_prefix(stream_prefix);
                let mut upper = seg_prefix.clone().into_bytes();
                upper.push(0xff);
                let mut to_delete: Vec<Vec<u8>> = Vec::new();
                {
                    let range = table
                        .range(seg_prefix.as_bytes()..=upper.as_slice())
                        .map_err(|e| super::RaftError::Storage(format!("trim range: {e}")))?;
                    for entry in range {
                        let (k, v) = entry
                            .map_err(|e| super::RaftError::Storage(format!("trim iter: {e}")))?;
                        if let Some(rec) = decode_segment_record(v.value()) {
                            if rec.end <= *up_to_seq {
                                to_delete.push(k.value().to_vec());
                            }
                        }
                    }
                }
                for k in &to_delete {
                    table.remove(k.as_slice()).map_err(|e| {
                        super::RaftError::Storage(format!("trim remove segment: {e}"))
                    })?;
                }
                table
                    .insert(earliest_key.as_bytes(), up_to_seq.to_be_bytes().as_slice())
                    .map_err(|e| {
                        super::RaftError::Storage(format!("advance stream earliest: {e}"))
                    })?;

                Ok(CommandResult::Success)
            }

            Command::PutControlState {
                namespace,
                key,
                value,
                if_absent,
            } => {
                let def = redb::TableDefinition::<&[u8], &[u8]>::new(self.control_state.name());
                let mut table = txn
                    .open_table(def)
                    .map_err(|e| super::RaftError::Storage(format!("open control_state: {e}")))?;
                let ckey = control_key(namespace, key);
                if *if_absent {
                    let exists = table
                        .get(ckey.as_slice())
                        .map_err(|e| super::RaftError::Storage(format!("get control_state: {e}")))?
                        .is_some();
                    if exists {
                        // CAS reject — log-ordered uniqueness gate. The entry is
                        // applied (consumed) but the write is refused; the txn
                        // commits with nothing written for it and propose() maps
                        // CommandResult::Error to an error.
                        return Ok(CommandResult::Error(format!(
                            "control state {namespace}/{key} already exists"
                        )));
                    }
                }
                table
                    .insert(ckey.as_slice(), value.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert control_state: {e}")))?;
                Ok(CommandResult::Success)
            }

            Command::DeleteControlState { namespace, key } => {
                let def = redb::TableDefinition::<&[u8], &[u8]>::new(self.control_state.name());
                let mut table = txn
                    .open_table(def)
                    .map_err(|e| super::RaftError::Storage(format!("open control_state: {e}")))?;
                table
                    .remove(control_key(namespace, key).as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("remove control_state: {e}")))?;
                Ok(CommandResult::Success)
            }

            Command::Noop => Ok(CommandResult::Success),

            // Lock commands never flow here.
            Command::AcquireLock { .. }
            | Command::ReleaseLock { .. }
            | Command::ForceReleaseLock { .. }
            | Command::ExtendLock { .. } => Err(super::RaftError::InvalidState(
                "execute_metadata_in_txn called with a lock command".into(),
            )),
        }
    }

    fn is_lock_command(command: &Command) -> bool {
        matches!(
            command,
            Command::AcquireLock { .. }
                | Command::ReleaseLock { .. }
                | Command::ForceReleaseLock { .. }
                | Command::ExtendLock { .. }
        )
    }
}

impl StateMachine for FullStateMachine {
    fn apply_local(&mut self, command: &Command) -> Result<CommandResult> {
        match command {
            Command::SetMetadata { .. }
            | Command::CasSetMetadata { .. }
            | Command::DeleteMetadata { .. }
            | Command::PutControlState { .. }
            | Command::DeleteControlState { .. } => self.execute(command),
            _ => Err(super::RaftError::InvalidState(
                "Only metadata operations (set/delete) support EC local writes".into(),
            )),
        }
    }

    /// Apply a peer's EC (eventually-consistent) write with Last-Write-Wins
    /// conflict resolution, keyed per metadata key.
    ///
    /// ## Correctness contract — READ BEFORE RELYING ON THIS FOR CONFLICTS
    ///
    /// This LWW is only well-defined when writes are **owner-partitioned**:
    /// each key is written by exactly one node, so two nodes never write the
    /// SAME key concurrently and the conflict branch below never actually has
    /// to pick a winner. That invariant holds for every current EC caller —
    /// cc-tasks-share is owner-partitioned (each node owns its own task-list
    /// keys). Under it, the merge is trivially convergent.
    ///
    /// It is NOT a correct general multi-writer LWW, by design (deferred as
    /// YAGNI until a real concurrent-same-key workload exists):
    /// * No deterministic tie-break. `ReplicationEntry.node_id` is documented
    ///   as the tie-breaker but is not consulted here, and there is no stored
    ///   per-key writer id to compare against — so two nodes writing the same
    ///   key with equal timestamps can each accept the other's copy and
    ///   DIVERGE with no convergence.
    /// * Mixed clocks. `SetMetadata` compares the payload's `modified_at`
    ///   (client wall-clock) while `DeleteMetadata` compares `entry_timestamp`
    ///   (WAL append seconds) — cross-machine skew / precision can flip the
    ///   winner between a set and a delete.
    /// * Sentinel coercion. A missing/corrupt `modified_at` decodes to `""`
    ///   (Set, always loses) or `0` (Delete, always wins), silently forcing an
    ///   outcome.
    ///
    /// The correct fix is a stored per-key LWW version `(timestamp, node_id)`
    /// compared apples-to-apples — a metadata-format change. Build it when a
    /// workload writes the same key from two nodes concurrently; until then the
    /// owner-partition invariant above is the load-bearing guarantee.
    #[cfg(feature = "grpc")]
    fn apply_ec_with_lww(
        &mut self,
        command: &Command,
        entry_timestamp: u64,
    ) -> Result<CommandResult> {
        // Track whether an LWW check short-circuited as a stale no-op, so the
        // observer spine below doesn't fire side effects for a write we
        // deliberately dropped.
        let mut applied = true;
        let result = match command {
            Command::SetMetadata { key, value } => {
                // LWW: compare incoming vs existing modified_at (ISO 8601 lexicographic)
                if let Some(existing) = self.metadata.get(key.as_bytes())? {
                    let incoming_ts = decode_modified_at(value);
                    let existing_ts = decode_modified_at(&existing);
                    if incoming_ts < existing_ts {
                        tracing::trace!(
                            key,
                            incoming = incoming_ts.as_str(),
                            existing = existing_ts.as_str(),
                            "LWW: skipping stale SetMetadata from peer"
                        );
                        applied = false;
                        Ok(CommandResult::Success)
                    } else {
                        self.apply_set_metadata(key, value)
                    }
                } else {
                    self.apply_set_metadata(key, value)
                }
            }
            Command::DeleteMetadata { key } => {
                // LWW: compare entry timestamp (u64) vs existing modified_at (parsed to u64)
                if let Some(existing) = self.metadata.get(key.as_bytes())? {
                    let existing_unix = decode_modified_at_unix(&existing);
                    if entry_timestamp < existing_unix {
                        tracing::trace!(
                            key,
                            entry_ts = entry_timestamp,
                            existing_ts = existing_unix,
                            "LWW: skipping stale DeleteMetadata from peer"
                        );
                        applied = false;
                        Ok(CommandResult::Success)
                    } else {
                        self.apply_delete_metadata(key)
                    }
                } else {
                    self.apply_delete_metadata(key)
                }
            }
            _ => Err(super::RaftError::InvalidState(
                "Only metadata operations support EC writes".into(),
            )),
        };

        // Fire the apply-observer spine on the RECEIVER so an EC-replicated
        // write triggers the same side effects a raft-committed one does:
        // DCache invalidation (stale-read safety — the pre-existing gap where
        // EC applies skipped it) and the A2A stream-wakeup (a parked sys_watch
        // on this node wakes for a peer's AppendStreamEntry). The origin fired
        // these via its local write path; this node only ever sees the entry
        // via EC apply, so this is the sole + correct fire (no double-fire).
        // Skip on a stale-LWW no-op. EC applies carry no raft index — pass 0;
        // every registered observer keys on the command, not the index.
        if applied && result.is_ok() {
            self.emit_apply_observers(0, command, None);
        }
        result
    }

    fn ec_state_snapshot(&self) -> Vec<Command> {
        // EC anti-entropy snapshot = metadata registers only. `list_metadata`
        // skips internal `__` keys → SetMetadata. LWW-idempotent on the
        // receiver; Sc-plane keys are byte-identical there so they no-op, only
        // missed EC keys change. DT_STREAM entries are NOT here: streams are
        // strong consistency (raft-committed), replicated via the log itself,
        // never the EC plane.
        self.list_metadata("")
            .unwrap_or_default()
            .into_iter()
            .map(|(key, value)| Command::SetMetadata { key, value })
            .collect()
    }

    fn apply(&mut self, index: u64, command: &Command) -> Result<CommandResult> {
        // Lock commands: mutate the in-memory advisory map under its
        // own mutex. They are idempotent under full log replay
        // (acquire/release cycles cancel out, TTL expiry is
        // deterministic from now_secs in the command), so they skip
        // the `last_applied` idempotency guard. This is what lets a
        // follower rebuild its BTreeMap from the log on restart even
        // when `last_applied` has been persisted — the metadata side
        // still uses the guard, but the advisory side needs every
        // committed entry replayed.
        if Self::is_lock_command(command) {
            let result = match command {
                Command::AcquireLock {
                    path,
                    lock_id,
                    max_holders,
                    ttl_secs,
                    holder_info,
                    now_secs,
                } => self.apply_acquire_lock(
                    path,
                    lock_id,
                    *max_holders,
                    *ttl_secs,
                    holder_info,
                    *now_secs,
                )?,
                Command::ReleaseLock { path, lock_id } => self.apply_release_lock(path, lock_id)?,
                Command::ForceReleaseLock { path } => self.apply_force_release_lock(path)?,
                Command::ExtendLock {
                    path,
                    lock_id,
                    new_ttl_secs,
                    now_secs,
                } => self.apply_extend_lock(path, lock_id, *new_ttl_secs, *now_secs)?,
                _ => unreachable!("is_lock_command filtered non-lock variants"),
            };
            // Track high-water mark in memory for monitoring; we don't
            // persist it for lock-only entries because the idempotency
            // check doesn't apply to them and because their persistent
            // record lives in the raft log + snapshot, not redb.
            let cur = self.last_applied.load(Ordering::Relaxed);
            if index > cur {
                self.last_applied.store(index, Ordering::Release);
            }
            return Ok(result);
        }

        // Metadata path: skip if we've already applied this index.
        // Protects `AdjustCounter` and similar non-idempotent
        // commands from double-replay on restart.
        if index <= self.last_applied.load(Ordering::Relaxed) {
            return Ok(CommandResult::Success);
        }

        // Capture pre-delete DT_MOUNT classification BEFORE the
        // write txn removes the entry. Apply is serial, so no
        // concurrent writer can slip in between this read and the txn
        // that performs the delete. Only DeleteMetadata needs the
        // pre-capture — for SetMetadata the proto is on the command
        // itself, accessible from mount_apply_event_from. Threaded to
        // observers as AppliedEntry::removed_mount_key.
        //
        // federation_unmount also writes a DT_DIR at the mount path
        // to replace the DT_MOUNT entry — that's a SetMetadata, not a
        // DeleteMetadata. We detect "previous entry was DT_MOUNT but
        // the new one isn't" and fire a Delete event so
        // wire_federation_mount_impl removes the mount from
        // VFSRouter on every node.
        #[cfg(feature = "grpc")]
        let delete_mount_key: Option<String> = match command {
            Command::DeleteMetadata { key } if self.peek_is_dt_mount(key) => Some(key.clone()),
            Command::SetMetadata { key, value } if self.peek_is_dt_mount(key) => {
                use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
                use prost::Message as ProstMessage;
                const DT_MOUNT: i32 = 2;
                let overwrite_is_mount = match ProtoFileMetadata::decode(value.as_slice()) {
                    Ok(p) => p.entry_type == DT_MOUNT,
                    Err(_) => false,
                };
                if overwrite_is_mount {
                    None
                } else {
                    Some(key.clone())
                }
            }
            _ => None,
        };

        // Atomic apply: execute the metadata command AND persist
        // `last_applied` in a single redb write transaction. This
        // matches etcd (boltdb txn), CockroachDB (Pebble WriteBatch),
        // and TiKV (RocksDB WriteBatch). Without atomicity, a crash
        // between execute() and save_last_applied() would cause
        // non-idempotent commands to replay on restart, silently
        // diverging from other replicas.
        let db = self.metadata.raw_db();
        let meta_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.metadata.name());

        let write_txn = match db.begin_write() {
            Ok(txn) => txn,
            Err(e) => {
                panic!(
                    "Fatal: cannot begin write transaction for apply at index {}: {}. \
                     Node must be restored from snapshot to recover.",
                    index, e
                );
            }
        };

        // Execute the command within the transaction.
        // Storage errors during apply of committed entries are non-deterministic
        // and unrecoverable — if this replica fails but others succeed, state
        // has diverged. Following etcd/CockroachDB: panic to prevent silent
        // divergence (node must be restored from snapshot).
        let result = match self.execute_metadata_in_txn(&write_txn, command) {
            Ok(result) => result,
            Err(e) => {
                panic!(
                    "Fatal: storage error applying committed entry at index {}: {}. \
                     Node must be restored from snapshot to recover.",
                    index, e
                );
            }
        };

        // Persist last_applied in the SAME transaction — atomic with the
        // command mutation. On crash, either both are persisted or neither.
        match write_txn.open_table(meta_def) {
            Ok(mut table) => {
                if let Err(e) = table.insert(KEY_LAST_APPLIED, index.to_be_bytes().as_slice()) {
                    panic!(
                        "Fatal: failed to write last_applied in apply txn at index {}: {}. \
                         Node must be restored from snapshot to recover.",
                        index, e
                    );
                }
            }
            Err(e) => {
                panic!(
                    "Fatal: failed to open metadata table for last_applied at index {}: {}. \
                     Node must be restored from snapshot to recover.",
                    index, e
                );
            }
        }

        if let Err(e) = write_txn.commit() {
            panic!(
                "Fatal: failed to commit apply transaction at index {}: {}. \
                 Node must be restored from snapshot to recover.",
                index, e
            );
        }

        // Update in-memory state only after successful commit. Release
        // ordering pairs with Acquire loads in sync readers (e.g. the
        // gRPC gate helper) so a reader observing a new last_applied
        // value also sees the metadata write that preceded it.
        self.last_applied.store(index, Ordering::Release);

        // Fire the unified apply-side observers *after* commit — one
        // spine for federation-mount wiring, DCache invalidation, and
        // (future) A2A / auth-cache eviction. Every observer runs under
        // catch_unwind; returning Err from apply would poison the state
        // machine per raft's "apply must not fail" invariant, and the
        // observers are strictly side-effects. ``removed_mount_key`` is
        // the DT_MOUNT pre-image captured before the write txn (grpc
        // only — the pre-read is behind the same cfg).
        #[cfg(feature = "grpc")]
        let removed_mount_key = delete_mount_key.as_deref();
        #[cfg(not(feature = "grpc"))]
        let removed_mount_key: Option<&str> = None;
        self.emit_apply_observers(index, command, removed_mount_key);

        Ok(result)
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        let mut metadata = HashMap::new();
        for item in self.metadata.iter() {
            let (key, value) = item?;
            if let Ok(path) = String::from_utf8(key) {
                // Skip internal keys
                if !path.starts_with("__") {
                    metadata.insert(path, value);
                }
            }
        }

        // R19.1b': serialize stream_entries as its own map. Keys are
        // opaque so no ``__``-prefix filtering here; consumers rely on
        // the dedicated tree to keep them separate from file metadata.
        let mut stream_entries = HashMap::new();
        for item in self.stream_entries.iter() {
            let (key, value) = item?;
            if let Ok(k) = String::from_utf8(key) {
                stream_entries.insert(k, value);
            }
        }

        // Cluster-control records — same rationale as stream_entries: a
        // dedicated map so they travel in the snapshot without ever
        // touching the file-metadata map. Keys are the composite
        // ``namespace\0key`` verbatim.
        let mut control_state = HashMap::new();
        for item in self.control_state.iter() {
            let (key, value) = item?;
            if let Ok(k) = String::from_utf8(key) {
                control_state.insert(k, value);
            }
        }

        // Snapshot the advisory map under its own mutex. One clone of
        // the BTreeMap is cheap (shallow tree copy) and lets us drop
        // the mutex before bincoding.
        let advisory = self.advisory.lock().clone();

        let snapshot = Snapshot {
            metadata,
            stream_entries,
            control_state,
            advisory,
            last_applied: self.last_applied.load(Ordering::Relaxed),
        };

        Ok(bincode::serialize(&snapshot)?)
    }

    fn restore_snapshot(&mut self, data: &[u8]) -> Result<()> {
        let snapshot: Snapshot = bincode::deserialize(data)?;

        // Atomic restore for metadata: clear + repopulate in a single
        // redb transaction. Advisory locks are in-memory only — they
        // are replaced under their own mutex after the redb commit.
        let db = self.metadata.raw_db();
        let meta_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.metadata.name());

        let write_txn = db.begin_write().map_err(|e| {
            super::RaftError::Storage(format!("begin_write for snapshot restore: {e}"))
        })?;

        let stream_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.stream_entries.name());
        let control_def = redb::TableDefinition::<&[u8], &[u8]>::new(self.control_state.name());

        {
            write_txn
                .delete_table(meta_def)
                .map_err(|e| super::RaftError::Storage(format!("delete metadata table: {e}")))?;
            let mut meta_table = write_txn
                .open_table(meta_def)
                .map_err(|e| super::RaftError::Storage(format!("open metadata table: {e}")))?;
            for (path, value) in &snapshot.metadata {
                meta_table
                    .insert(path.as_bytes(), value.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert metadata: {e}")))?;
            }
            // Persist last_applied inside the same transaction
            meta_table
                .insert(
                    KEY_LAST_APPLIED,
                    snapshot.last_applied.to_be_bytes().as_slice(),
                )
                .map_err(|e| super::RaftError::Storage(format!("insert last_applied: {e}")))?;

            // R19.1b': same atomic transaction restores stream_entries.
            // ``delete_table`` wipes the previous state; then reinsert
            // the snapshot contents. Pre-R19.1b' snapshots carry an
            // empty map here (serde(default)), so the table ends up
            // empty — matching pre-R19.1b' behavior where it did not
            // exist.
            write_txn.delete_table(stream_def).map_err(|e| {
                super::RaftError::Storage(format!("delete stream_entries table: {e}"))
            })?;
            let mut stream_table = write_txn.open_table(stream_def).map_err(|e| {
                super::RaftError::Storage(format!("open stream_entries table: {e}"))
            })?;
            for (key, value) in &snapshot.stream_entries {
                stream_table
                    .insert(key.as_bytes(), value.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert stream_entry: {e}")))?;
            }

            // Cluster-control records — same clear-then-repopulate as
            // stream_entries. Pre-control-store snapshots carry an empty
            // map (serde(default)), so the table ends up empty.
            write_txn.delete_table(control_def).map_err(|e| {
                super::RaftError::Storage(format!("delete control_state table: {e}"))
            })?;
            let mut control_table = write_txn
                .open_table(control_def)
                .map_err(|e| super::RaftError::Storage(format!("open control_state table: {e}")))?;
            for (key, value) in &snapshot.control_state {
                control_table
                    .insert(key.as_bytes(), value.as_slice())
                    .map_err(|e| super::RaftError::Storage(format!("insert control_state: {e}")))?;
            }
        }

        write_txn
            .commit()
            .map_err(|e| super::RaftError::Storage(format!("commit snapshot restore: {e}")))?;

        // Replace advisory state under its mutex. Single acquisition
        // preserves the atomicity invariant: any concurrent reader
        // sees either the full pre-restore map or the full post-
        // restore map, never a torn in-between.
        {
            let mut guard = self.advisory.lock();
            *guard = snapshot.advisory;
        }

        // Update in-memory state only after both writes succeed.
        self.last_applied
            .store(snapshot.last_applied, Ordering::Release);

        Ok(())
    }

    fn last_applied_index(&self) -> u64 {
        self.last_applied.load(Ordering::Acquire)
    }

    fn last_applied_shared(&self) -> Option<Arc<AtomicU64>> {
        Some(self.last_applied_shared_arc())
    }

    /// Return the shared apply-side observer list so downstream holders
    /// (``ZoneConsensus``, kernel federation wiring, DCache) can register
    /// observers that fire on every committed metadata-path command.
    fn apply_observers_slot(&self) -> Option<Arc<parking_lot::RwLock<Vec<ApplyObserver>>>> {
        Some(Arc::clone(&self.apply_observers))
    }

    fn advisory_handle(&self) -> Option<Arc<Mutex<LockState>>> {
        Some(Arc::clone(&self.advisory))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_state_machine() {
        let mut sm = WitnessStateMachineInMemory::new();

        // Apply some commands
        let cmd = Command::SetMetadata {
            key: "test".into(),
            value: vec![1, 2, 3],
        };

        let result = sm.apply(1, &cmd).unwrap();
        assert!(matches!(result, CommandResult::Success));
        assert_eq!(sm.last_applied_index(), 1);

        let result = sm.apply(2, &Command::Noop).unwrap();
        assert!(matches!(result, CommandResult::Success));
        assert_eq!(sm.last_applied_index(), 2);

        // Snapshot should be empty
        let snapshot = sm.snapshot().unwrap();
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_command_serialization() {
        let cmd = Command::AcquireLock {
            path: "/data/test.txt".into(),
            lock_id: "uuid-123".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test".into(),
            now_secs: 1000,
        };

        let serialized = bincode::serialize(&cmd).unwrap();
        let deserialized: Command = bincode::deserialize(&serialized).unwrap();

        match deserialized {
            Command::AcquireLock {
                path,
                lock_id,
                max_holders,
                ttl_secs,
                holder_info,
                now_secs,
            } => {
                assert_eq!(path, "/data/test.txt");
                assert_eq!(lock_id, "uuid-123");
                assert_eq!(max_holders, 3);
                assert_eq!(ttl_secs, 30);
                assert_eq!(holder_info, "agent:test");
                assert_eq!(now_secs, 1000);
            }
            _ => panic!("wrong command type"),
        }
    }

    /// Apply-side DT_MOUNT callback — one flow covering every branch:
    /// DT_MOUNT Set with an installed callback fires exactly one Set
    /// event with the right payload; DT_DIR Set never fires;
    /// DT_MOUNT Delete fires a Delete event; DT_REG Delete never fires;
    /// a state machine with no callback applies normally (callback is
    /// pure side-effect — apply must be unaffected).
    #[cfg(feature = "grpc")]
    #[test]
    fn apply_mount_apply_cb_fires_only_on_dt_mount() {
        use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
        use prost::Message as ProstMessage;
        use std::sync::Mutex as StdMutex;

        fn encode(entry_type: i32, zone: &str, target: &str) -> Vec<u8> {
            ProtoFileMetadata {
                entry_type,
                zone_id: zone.to_string(),
                target_zone_id: target.to_string(),
                ..Default::default()
            }
            .encode_to_vec()
        }

        // Callback installed: DT_MOUNT Set emits a Set event with the
        // decoded target + backend snapshot.
        let store = RedbStore::open_temporary().unwrap();
        let sm = FullStateMachine::new(&store).unwrap();
        let events: Arc<StdMutex<Vec<MountApplyEvent>>> = Arc::new(StdMutex::new(Vec::new()));
        let slot = sm
            .apply_observers_slot()
            .expect("FullStateMachine exposes an apply-observers slot");
        let events_cb = Arc::clone(&events);
        // Mirror the real mount installer: translate the applied entry
        // to a MountApplyEvent and record it.
        slot.write().push((
            None,
            Arc::new(move |entry: &AppliedEntry| {
                if let Some(e) =
                    FullStateMachine::mount_apply_event_from(entry.command, entry.removed_mount_key)
                {
                    events_cb.lock().unwrap().push(e);
                }
            }),
        ));
        let mut sm = sm;

        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/mnt/peer".into(),
                value: encode(2, "zone-a", "zone-b"), // DT_MOUNT
            },
        )
        .unwrap();
        {
            let log = events.lock().unwrap();
            assert_eq!(log.len(), 1, "DT_MOUNT Set must fire exactly once");
            match &log[0] {
                MountApplyEvent::Set {
                    key,
                    target_zone_id,
                } => {
                    assert_eq!(key, "/mnt/peer");
                    assert_eq!(target_zone_id, "zone-b");
                }
                other => panic!("expected Set event, got {other:?}"),
            }
        }

        // DT_DIR Set → no event.
        sm.apply(
            2,
            &Command::SetMetadata {
                key: "/docs".into(),
                value: encode(1, "zone-a", ""), // DT_DIR
            },
        )
        .unwrap();
        assert_eq!(
            events.lock().unwrap().len(),
            1,
            "DT_DIR must not fire a mount-apply event"
        );

        // DT_MOUNT Delete → fires one Delete event with the key.
        sm.apply(
            3,
            &Command::DeleteMetadata {
                key: "/mnt/peer".into(),
            },
        )
        .unwrap();
        {
            let log = events.lock().unwrap();
            assert_eq!(log.len(), 2, "DT_MOUNT Delete must fire once");
            match &log[1] {
                MountApplyEvent::Delete { key } => assert_eq!(key, "/mnt/peer"),
                other => panic!("expected Delete event, got {other:?}"),
            }
        }

        // DT_REG Set + Delete → no events (DT_REG is not DT_MOUNT).
        sm.apply(
            4,
            &Command::SetMetadata {
                key: "/file.txt".into(),
                value: encode(0, "zone-a", ""), // DT_REG
            },
        )
        .unwrap();
        sm.apply(
            5,
            &Command::DeleteMetadata {
                key: "/file.txt".into(),
            },
        )
        .unwrap();
        assert_eq!(
            events.lock().unwrap().len(),
            2,
            "DT_REG set/delete must not fire"
        );

        // No callback installed: DT_MOUNT applies normally, no panic.
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        let res = sm2
            .apply(
                1,
                &Command::SetMetadata {
                    key: "/mnt/peer".into(),
                    value: encode(2, "zone-a", "zone-b"),
                },
            )
            .unwrap();
        assert!(matches!(res, CommandResult::Success));
        assert_eq!(sm2.last_applied_index(), 1, "apply unaffected without cb");
    }

    /// Apply-side mount callback panics must not poison apply.
    #[cfg(feature = "grpc")]
    #[test]
    fn apply_mount_apply_cb_panic_does_not_poison_apply() {
        use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
        use prost::Message as ProstMessage;

        let store = RedbStore::open_temporary().unwrap();
        let sm = FullStateMachine::new(&store).unwrap();
        let slot = sm.apply_observers_slot().unwrap();
        slot.write().push((
            None,
            Arc::new(|entry: &AppliedEntry| {
                // Only panic once the entry translates to a real mount
                // event — mirrors the installer, which does nothing for
                // non-mount commands.
                if FullStateMachine::mount_apply_event_from(entry.command, entry.removed_mount_key)
                    .is_some()
                {
                    panic!("intentional test panic");
                }
            }),
        ));
        let mut sm = sm;

        let value = ProtoFileMetadata {
            entry_type: 2,
            target_zone_id: "zone-b".into(),
            ..Default::default()
        }
        .encode_to_vec();

        let res = sm.apply(
            1,
            &Command::SetMetadata {
                key: "/mnt/peer".into(),
                value,
            },
        );
        assert!(res.is_ok(), "callback panic must not fail apply");
        assert_eq!(sm.last_applied_index(), 1);
    }

    /// Apply-side invalidation callback — fires once per committed
    /// metadata mutation, skips non-mutating variants, survives
    /// callback panics without poisoning apply.
    #[test]
    fn apply_invalidate_callback_fires_on_metadata_mutations_only() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc as StdArc;

        let store = RedbStore::open_temporary().unwrap();
        let sm = FullStateMachine::new(&store).unwrap();
        let calls = StdArc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let slot = sm
            .apply_observers_slot()
            .expect("FullStateMachine exposes a slot");
        let calls_cb = StdArc::clone(&calls);
        // Mirror the ZoneMetaStore dcache observer: fire only for the
        // three key-mutating variants, recording the mutated key.
        slot.write().push((
            None,
            Arc::new(move |entry: &AppliedEntry| {
                let key = match entry.command {
                    Command::SetMetadata { key, .. }
                    | Command::CasSetMetadata { key, .. }
                    | Command::DeleteMetadata { key } => key.as_str(),
                    _ => return,
                };
                calls_cb.lock().unwrap().push(key.to_string());
            }),
        ));
        let mut sm = sm;

        // SetMetadata → fires with the mutated key.
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/a".into(),
                value: vec![0u8; 4],
            },
        )
        .unwrap();
        sm.apply(2, &Command::DeleteMetadata { key: "/b".into() })
            .unwrap();
        sm.apply(
            3,
            &Command::CasSetMetadata {
                key: "/c".into(),
                value: vec![0u8; 4],
                expected_version: 0,
            },
        )
        .unwrap();
        sm.apply(
            4,
            &Command::AdjustCounter {
                key: "__i_links_count__".into(),
                delta: 1,
            },
        )
        .unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["/a".to_string(), "/b".to_string(), "/c".to_string()],
            "callback must fire on Set/Cas/Delete, not on AdjustCounter"
        );

        // Panicking callback does not poison the state machine.
        let panic_count = StdArc::new(AtomicUsize::new(0));
        let panic_count_cb = StdArc::clone(&panic_count);
        // Replace the existing accumulator-cb with the panicking cb so
        // we exercise the panic-survives path in isolation.
        *slot.write() = vec![(
            None,
            Arc::new(move |_entry: &AppliedEntry| {
                panic_count_cb.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                panic!("intentional observer panic");
            }),
        )];
        let res = sm.apply(
            5,
            &Command::SetMetadata {
                key: "/d".into(),
                value: vec![0u8; 4],
            },
        );
        assert!(res.is_ok(), "apply must not propagate callback panic");
        assert_eq!(
            panic_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "panicking callback still ran once"
        );
        assert_eq!(sm.last_applied_index(), 5);

        // Slot cleared → no more invocations on subsequent applies.
        slot.write().clear();
        sm.apply(
            6,
            &Command::SetMetadata {
                key: "/e".into(),
                value: vec![0u8; 4],
            },
        )
        .unwrap();
        // calls vec is frozen at length 3 — /d / /e did not append because
        // the panicking cb was replaced before /d succeeded-without-append,
        // and /e ran with slot = None.
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    /// Registration semantics of the unified observer slot:
    /// - a **keyed** observer re-registered under the same key REPLACES
    ///   the prior one (federation mount installs 7+ times per zone and
    ///   must stay a singleton — this is the regression the keyed API
    ///   fixes);
    /// - an **anonymous** observer accumulates (DCache: one per surface).
    #[cfg(feature = "grpc")]
    #[test]
    fn keyed_observer_replaces_anonymous_accumulates() {
        use crate::transport::proto::nexus::core::FileMetadata as ProtoFileMetadata;
        use prost::Message as ProstMessage;
        use std::sync::atomic::{AtomicUsize, Ordering as AtOrd};
        use std::sync::Arc as StdArc;

        // Register the same key twice: only the second survives, so a
        // single DT_MOUNT apply fires it exactly once.
        let store = RedbStore::open_temporary().unwrap();
        let sm = FullStateMachine::new(&store).unwrap();
        let slot = sm.apply_observers_slot().unwrap();
        let keyed_fires = StdArc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            // Emulate ZoneConsensus::register_keyed_apply_observer's
            // retain-then-push (the state machine test has no consensus
            // handle, so exercise the Vec semantics directly).
            let c = StdArc::clone(&keyed_fires);
            let mut g = slot.write();
            g.retain(|(k, _)| *k != Some("federation_mount"));
            g.push((
                Some("federation_mount"),
                Arc::new(move |entry: &AppliedEntry| {
                    if FullStateMachine::mount_apply_event_from(
                        entry.command,
                        entry.removed_mount_key,
                    )
                    .is_some()
                    {
                        c.fetch_add(1, AtOrd::SeqCst);
                    }
                }),
            ));
        }
        assert_eq!(slot.read().len(), 1, "keyed re-register must replace");
        let mut sm = sm;
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/mnt/peer".into(),
                value: ProtoFileMetadata {
                    entry_type: 2, // DT_MOUNT
                    target_zone_id: "zone-b".into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            },
        )
        .unwrap();
        assert_eq!(
            keyed_fires.load(AtOrd::SeqCst),
            1,
            "keyed observer must fire exactly once (replace, not accumulate)"
        );

        // Two anonymous observers both survive and both fire.
        let store2 = RedbStore::open_temporary().unwrap();
        let sm2 = FullStateMachine::new(&store2).unwrap();
        let slot2 = sm2.apply_observers_slot().unwrap();
        let anon_fires = StdArc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let c = StdArc::clone(&anon_fires);
            slot2.write().push((
                None,
                Arc::new(move |_e: &AppliedEntry| {
                    c.fetch_add(1, AtOrd::SeqCst);
                }),
            ));
        }
        assert_eq!(slot2.read().len(), 2, "anonymous must accumulate");
        let mut sm2 = sm2;
        sm2.apply(
            1,
            &Command::SetMetadata {
                key: "/a".into(),
                value: vec![0u8; 4],
            },
        )
        .unwrap();
        assert_eq!(
            anon_fires.load(AtOrd::SeqCst),
            2,
            "both anonymous observers must fire"
        );
    }

    /// Determinism regression test (Issue #3029 / Bug 1):
    /// Two state machines applying the same commands must produce byte-identical snapshots.

    #[test]
    fn test_state_machine_determinism() {
        let store1 = RedbStore::open_temporary().unwrap();
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm1 = FullStateMachine::new(&store1).unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();

        // Build a sequence of commands with explicit timestamps
        let commands: Vec<(u64, Command)> = vec![
            (
                1,
                Command::SetMetadata {
                    key: "/file1".into(),
                    value: b"data1".to_vec(),
                },
            ),
            (
                2,
                Command::AcquireLock {
                    path: "/file1".into(),
                    lock_id: "lock-1".into(),
                    max_holders: 1,
                    ttl_secs: 60,
                    holder_info: "agent:a".into(),
                    now_secs: 1000,
                },
            ),
            (
                3,
                Command::AcquireLock {
                    path: "/file2".into(),
                    lock_id: "lock-2".into(),
                    max_holders: 3,
                    ttl_secs: 30,
                    holder_info: "agent:b".into(),
                    now_secs: 1001,
                },
            ),
            (
                4,
                Command::ExtendLock {
                    path: "/file1".into(),
                    lock_id: "lock-1".into(),
                    new_ttl_secs: 120,
                    now_secs: 1010,
                },
            ),
            (
                5,
                Command::ReleaseLock {
                    path: "/file2".into(),
                    lock_id: "lock-2".into(),
                },
            ),
            // Acquire after TTL-based expiry cleanup
            (
                6,
                Command::AcquireLock {
                    path: "/file2".into(),
                    lock_id: "lock-3".into(),
                    max_holders: 1,
                    ttl_secs: 60,
                    holder_info: "agent:c".into(),
                    now_secs: 2000, // well past lock-2's 30s TTL
                },
            ),
        ];

        // Apply identical commands to both state machines
        for (idx, cmd) in &commands {
            sm1.apply(*idx, cmd).unwrap();
            sm2.apply(*idx, cmd).unwrap();
        }

        // Snapshots must be logically identical (HashMap serialization order may vary).
        let snap1 = sm1.snapshot().unwrap();
        let snap2 = sm2.snapshot().unwrap();
        let decoded1: Snapshot = bincode::deserialize(&snap1).unwrap();
        let decoded2: Snapshot = bincode::deserialize(&snap2).unwrap();
        assert_eq!(decoded1.metadata, decoded2.metadata, "Metadata diverged");
        assert_eq!(
            decoded1.advisory.locks, decoded2.advisory.locks,
            "Locks diverged"
        );
        assert_eq!(
            decoded1.last_applied, decoded2.last_applied,
            "last_applied diverged"
        );
    }

    #[test]
    fn test_full_state_machine_metadata() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Set metadata
        let cmd = Command::SetMetadata {
            key: "/test/file.txt".into(),
            value: b"metadata".to_vec(),
        };
        let result = sm.apply(1, &cmd).unwrap();
        assert!(matches!(result, CommandResult::Success));

        // Get metadata
        let value = sm.get_metadata("/test/file.txt").unwrap();
        assert_eq!(value, Some(b"metadata".to_vec()));

        // Delete metadata
        let cmd = Command::DeleteMetadata {
            key: "/test/file.txt".into(),
        };
        let result = sm.apply(2, &cmd).unwrap();
        assert!(matches!(result, CommandResult::Success));

        let value = sm.get_metadata("/test/file.txt").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_full_state_machine_mutex_lock() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire mutex (max_holders = 1)
        let cmd = Command::AcquireLock {
            path: "/test/file.txt".into(),
            lock_id: "holder-1".into(),
            max_holders: 1,
            ttl_secs: 30,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        let result = sm.apply(1, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.current_holders, 1);
        } else {
            panic!("Expected LockResult");
        }

        // Try to acquire same mutex with different holder - should fail
        let cmd = Command::AcquireLock {
            path: "/test/file.txt".into(),
            lock_id: "holder-2".into(),
            max_holders: 1,
            ttl_secs: 30,
            holder_info: "agent:test2".into(),
            now_secs: 1000,
        };
        let result = sm.apply(2, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(!state.acquired);
            assert_eq!(state.current_holders, 1);
        } else {
            panic!("Expected LockResult");
        }

        // Release lock
        let cmd = Command::ReleaseLock {
            path: "/test/file.txt".into(),
            lock_id: "holder-1".into(),
        };
        let result = sm.apply(3, &cmd).unwrap();
        assert!(matches!(result, CommandResult::Success));

        // Now holder-2 can acquire
        let cmd = Command::AcquireLock {
            path: "/test/file.txt".into(),
            lock_id: "holder-2".into(),
            max_holders: 1,
            ttl_secs: 30,
            holder_info: "agent:test2".into(),
            now_secs: 1000,
        };
        let result = sm.apply(4, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
        } else {
            panic!("Expected LockResult");
        }
    }

    #[test]
    fn test_full_state_machine_semaphore_lock() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire semaphore with max_holders = 3
        let cmd = Command::AcquireLock {
            path: "/test/resource".into(),
            lock_id: "holder-1".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        let result = sm.apply(1, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.current_holders, 1);
            assert_eq!(state.max_holders, 3);
        } else {
            panic!("Expected LockResult");
        }

        // Second holder can also acquire
        let cmd = Command::AcquireLock {
            path: "/test/resource".into(),
            lock_id: "holder-2".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test2".into(),
            now_secs: 1000,
        };
        let result = sm.apply(2, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.current_holders, 2);
        } else {
            panic!("Expected LockResult");
        }

        // Third holder can also acquire
        let cmd = Command::AcquireLock {
            path: "/test/resource".into(),
            lock_id: "holder-3".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test3".into(),
            now_secs: 1000,
        };
        let result = sm.apply(3, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.current_holders, 3);
        } else {
            panic!("Expected LockResult");
        }

        // Fourth holder should fail - at capacity
        let cmd = Command::AcquireLock {
            path: "/test/resource".into(),
            lock_id: "holder-4".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test4".into(),
            now_secs: 1000,
        };
        let result = sm.apply(4, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(!state.acquired);
            assert_eq!(state.current_holders, 3);
        } else {
            panic!("Expected LockResult");
        }

        // Release one slot
        let cmd = Command::ReleaseLock {
            path: "/test/resource".into(),
            lock_id: "holder-2".into(),
        };
        sm.apply(5, &cmd).unwrap();

        // Now fourth holder can acquire
        let cmd = Command::AcquireLock {
            path: "/test/resource".into(),
            lock_id: "holder-4".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test4".into(),
            now_secs: 1000,
        };
        let result = sm.apply(6, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.current_holders, 3);
        } else {
            panic!("Expected LockResult");
        }
    }

    #[test]
    fn test_full_state_machine_snapshot_restore() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Add some data
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/file1".into(),
                value: b"data1".to_vec(),
            },
        )
        .unwrap();
        sm.apply(
            2,
            &Command::SetMetadata {
                key: "/file2".into(),
                value: b"data2".to_vec(),
            },
        )
        .unwrap();
        sm.apply(
            3,
            &Command::AcquireLock {
                path: "/file1".into(),
                lock_id: "lock-1".into(),
                max_holders: 1,
                ttl_secs: 3600,
                holder_info: "agent:test".into(),
                now_secs: 1000,
            },
        )
        .unwrap();

        // Take snapshot
        let snapshot_data = sm.snapshot().unwrap();

        // Create new state machine and restore
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.restore_snapshot(&snapshot_data).unwrap();

        // Verify data
        assert_eq!(sm2.get_metadata("/file1").unwrap(), Some(b"data1".to_vec()));
        assert_eq!(sm2.get_metadata("/file2").unwrap(), Some(b"data2".to_vec()));
        assert!(sm2.get_lock("/file1").unwrap().is_some());
        assert_eq!(sm2.last_applied_index(), 3);
    }

    #[test]
    fn test_lock_idempotent_acquire() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire lock
        let cmd = Command::AcquireLock {
            path: "/test/file.txt".into(),
            lock_id: "holder-1".into(),
            max_holders: 1,
            ttl_secs: 30,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        sm.apply(1, &cmd).unwrap();

        // Acquire again with same lock_id - should succeed (idempotent)
        let result = sm.apply(2, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.current_holders, 1); // Still 1, not 2
        } else {
            panic!("Expected LockResult");
        }
    }

    /// Test that expired holders are cleaned up during acquire.
    #[test]
    fn test_lock_ttl_expiry_during_acquire() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire a lock with 1-second TTL at time 1000
        let cmd = Command::AcquireLock {
            path: "/test/expire".into(),
            lock_id: "holder-1".into(),
            max_holders: 1,
            ttl_secs: 1,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        let result = sm.apply(1, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
        } else {
            panic!("Expected LockResult");
        }

        // Another holder acquires at time 1002 (after the 1s TTL expired)
        // No sleep needed — deterministic timestamps from the command.
        let cmd2 = Command::AcquireLock {
            path: "/test/expire".into(),
            lock_id: "holder-2".into(),
            max_holders: 1,
            ttl_secs: 30,
            holder_info: "agent:test2".into(),
            now_secs: 1002,
        };
        let result = sm.apply(2, &cmd2).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired, "Should acquire after expiry");
            assert_eq!(state.current_holders, 1);
            // Verify it's holder-2, not holder-1
            assert_eq!(state.holders[0].lock_id, "holder-2");
        } else {
            panic!("Expected LockResult");
        }
    }

    /// Test that mixing mutex and semaphore max_holders is rejected.
    #[test]
    fn test_lock_type_mismatch() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire a semaphore lock (max_holders = 3)
        let cmd = Command::AcquireLock {
            path: "/test/mismatch".into(),
            lock_id: "holder-1".into(),
            max_holders: 3,
            ttl_secs: 30,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        let result = sm.apply(1, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
        } else {
            panic!("Expected LockResult");
        }

        // Try to acquire as mutex (max_holders = 1) — should be rejected
        let cmd2 = Command::AcquireLock {
            path: "/test/mismatch".into(),
            lock_id: "holder-2".into(),
            max_holders: 1, // Mismatch: 1 != 3
            ttl_secs: 30,
            holder_info: "agent:test2".into(),
            now_secs: 1000,
        };
        let result = sm.apply(2, &cmd2).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(!state.acquired, "Should reject mismatched max_holders");
        } else {
            panic!("Expected LockResult");
        }
    }

    /// Test that snapshots include expired holders (they're cleaned on acquire, not snapshot).
    #[test]
    fn test_expired_holders_in_snapshot() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire a lock with 1-second TTL at time 1000 (expires at 1001)
        let cmd = Command::AcquireLock {
            path: "/test/snap-expire".into(),
            lock_id: "holder-1".into(),
            max_holders: 1,
            ttl_secs: 1,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        sm.apply(1, &cmd).unwrap();

        // Take snapshot — should still include the expired holder
        // (cleanup happens during acquire, not snapshot; the lock expired at 1001)
        let snapshot_data = sm.snapshot().unwrap();

        // Restore to a new state machine
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.restore_snapshot(&snapshot_data).unwrap();

        // The expired lock should be present in the restored state
        let lock = sm2.get_lock("/test/snap-expire").unwrap();
        assert!(lock.is_some(), "Expired lock should persist in snapshot");
        let lock_info = lock.unwrap();
        assert_eq!(lock_info.holders.len(), 1);
        assert_eq!(lock_info.holders[0].lock_id, "holder-1");
    }

    /// Test edge cases with max_holders boundary values.
    #[test]
    fn test_lock_max_holders_boundary() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Acquire with max_holders = u32::MAX (should work)
        let cmd = Command::AcquireLock {
            path: "/test/boundary".into(),
            lock_id: "holder-1".into(),
            max_holders: u32::MAX,
            ttl_secs: 30,
            holder_info: "agent:test1".into(),
            now_secs: 1000,
        };
        let result = sm.apply(1, &cmd).unwrap();
        if let CommandResult::LockResult(state) = result {
            assert!(state.acquired);
            assert_eq!(state.max_holders, u32::MAX);
        } else {
            panic!("Expected LockResult");
        }

        // Noop should be handled cleanly
        let result = sm.apply(2, &Command::Noop).unwrap();
        assert!(matches!(result, CommandResult::Success));

        // Re-applying an already applied index should be idempotent
        let cmd2 = Command::SetMetadata {
            key: "/test/dup".into(),
            value: b"data".to_vec(),
        };
        let result = sm.apply(1, &cmd2).unwrap(); // index 1 already applied
        assert!(
            matches!(result, CommandResult::Success),
            "Re-applying old index should succeed (no-op)"
        );
        // The metadata should NOT be set (skipped due to idempotency)
        assert!(sm.get_metadata("/test/dup").unwrap().is_none());
    }

    // ───────────────────────────────────────────────────────────────
    // Advisory lock semantics — `max_holders` parametrizes the shape
    // (mutex = 1, counting semaphore > 1).
    // ───────────────────────────────────────────────────────────────

    /// Helper: build an AcquireLock command. `max_holders == 1` is a
    /// mutex; `max_holders > 1` is a counting semaphore.
    fn acquire_cmd(path: &str, lock_id: &str, max_holders: u32, now_secs: u64) -> Command {
        Command::AcquireLock {
            path: path.into(),
            lock_id: lock_id.into(),
            max_holders,
            ttl_secs: 60,
            holder_info: format!("agent:{lock_id}"),
            now_secs,
        }
    }

    #[test]
    fn test_f4_mutex_blocks_second_acquire() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        let c1 = acquire_cmd("/rw/a", "h1", 1, 1000);
        let c2 = acquire_cmd("/rw/a", "h2", 1, 1000);

        match sm.apply(1, &c1).unwrap() {
            CommandResult::LockResult(s) => assert!(s.acquired),
            _ => panic!("LockResult"),
        }
        match sm.apply(2, &c2).unwrap() {
            CommandResult::LockResult(s) => assert!(!s.acquired),
            _ => panic!("LockResult"),
        }
    }

    #[test]
    fn test_f4_semaphore_coexists_up_to_max() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // max_holders=3, three holders all acquire.
        for (idx, id) in ["r1", "r2", "r3"].iter().enumerate() {
            let cmd = acquire_cmd("/rw/b", id, 3, 1000);
            match sm.apply((idx + 1) as u64, &cmd).unwrap() {
                CommandResult::LockResult(s) => assert!(s.acquired, "{} should acquire", id),
                _ => panic!("LockResult"),
            }
        }

        // Fourth holder fails — at capacity.
        let c4 = acquire_cmd("/rw/b", "r4", 3, 1000);
        match sm.apply(4, &c4).unwrap() {
            CommandResult::LockResult(s) => assert!(!s.acquired),
            _ => panic!("LockResult"),
        }
    }

    #[test]
    fn test_f4_max_holders_mismatch_rejects() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        let first = acquire_cmd("/rw/c", "r1", 3, 1000);
        let mismatch = acquire_cmd("/rw/c", "w1", 1, 1000);

        match sm.apply(1, &first).unwrap() {
            CommandResult::LockResult(s) => assert!(s.acquired),
            _ => panic!("LockResult"),
        }
        // Second acquire with different max_holders is rejected.
        match sm.apply(2, &mismatch).unwrap() {
            CommandResult::LockResult(s) => assert!(!s.acquired),
            _ => panic!("LockResult"),
        }
    }

    #[test]
    fn test_f4_snapshot_roundtrip() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        sm.apply(7, &acquire_cmd("/rw/f", "r1", 3, 1000)).unwrap();

        let snap = sm.snapshot().unwrap();
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.restore_snapshot(&snap).unwrap();

        let lock = sm2.get_lock("/rw/f").unwrap().unwrap();
        assert_eq!(lock.holders[0].lock_id, "r1");
        assert_eq!(lock.max_holders, 3);
    }

    #[test]
    fn test_cas_set_metadata_create_new() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // CAS create: expected_version=0, key does not exist → success
        let cmd = Command::CasSetMetadata {
            key: "/cas/new.txt".into(),
            value: b"data-v1".to_vec(),
            expected_version: 0,
        };
        let result = sm.apply(1, &cmd).unwrap();
        if let CommandResult::CasResult {
            success,
            current_version,
        } = result
        {
            assert!(success, "CAS create should succeed");
            assert_eq!(current_version, 1);
        } else {
            panic!("Expected CasResult");
        }

        // Verify data was written
        assert_eq!(
            sm.get_metadata("/cas/new.txt").unwrap(),
            Some(b"data-v1".to_vec())
        );
    }

    #[test]
    fn test_cas_set_metadata_version_mismatch() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Write initial data
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/cas/file.txt".into(),
                value: b"initial".to_vec(),
            },
        )
        .unwrap();

        // CAS with wrong expected_version → failure
        let cmd = Command::CasSetMetadata {
            key: "/cas/file.txt".into(),
            value: b"updated".to_vec(),
            expected_version: 5, // wrong version
        };
        let result = sm.apply(2, &cmd).unwrap();
        if let CommandResult::CasResult {
            success,
            current_version,
        } = result
        {
            assert!(!success, "CAS should fail on version mismatch");
            // current_version depends on what extract_version returns for raw bytes
            assert_eq!(current_version, 0); // raw bytes without protobuf → 0
        } else {
            panic!("Expected CasResult");
        }

        // Verify data was NOT overwritten
        assert_eq!(
            sm.get_metadata("/cas/file.txt").unwrap(),
            Some(b"initial".to_vec())
        );
    }

    #[test]
    fn test_cas_set_metadata_create_exists() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Write initial data with a version field (JSON format, version=1)
        let json_data = br#"{"path":"/cas/exists.txt","version":1,"size":6}"#;
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/cas/exists.txt".into(),
                value: json_data.to_vec(),
            },
        )
        .unwrap();

        // CAS create (expected_version=0) when file already exists with version=1 → failure
        let cmd = Command::CasSetMetadata {
            key: "/cas/exists.txt".into(),
            value: b"new-data".to_vec(),
            expected_version: 0,
        };
        let result = sm.apply(2, &cmd).unwrap();
        if let CommandResult::CasResult {
            success,
            current_version,
        } = result
        {
            assert!(!success, "CAS create should fail when file exists");
            assert_eq!(current_version, 1);
        } else {
            panic!("Expected CasResult");
        }

        // Verify data was NOT overwritten
        assert_eq!(
            sm.get_metadata("/cas/exists.txt").unwrap(),
            Some(json_data.to_vec())
        );
    }

    #[test]
    fn test_cas_set_metadata_json_version_extraction() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Write JSON metadata with version field
        let json_data = br#"{"path":"/test","version":3,"size":100}"#;
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/cas/json.txt".into(),
                value: json_data.to_vec(),
            },
        )
        .unwrap();

        // CAS with correct version → success
        let cmd = Command::CasSetMetadata {
            key: "/cas/json.txt".into(),
            value: br#"{"path":"/test","version":4,"size":200}"#.to_vec(),
            expected_version: 3,
        };
        let result = sm.apply(2, &cmd).unwrap();
        if let CommandResult::CasResult { success, .. } = result {
            assert!(success, "CAS should succeed with correct JSON version");
        } else {
            panic!("Expected CasResult");
        }

        // CAS with wrong version → failure
        let cmd2 = Command::CasSetMetadata {
            key: "/cas/json.txt".into(),
            value: br#"{"path":"/test","version":5,"size":300}"#.to_vec(),
            expected_version: 3, // stale — actual is 4 now
        };
        let result = sm.apply(3, &cmd2).unwrap();
        if let CommandResult::CasResult {
            success,
            current_version,
        } = result
        {
            assert!(!success, "CAS should fail with stale version");
            assert_eq!(current_version, 4);
        } else {
            panic!("Expected CasResult");
        }
    }

    #[test]
    fn test_adjust_counter() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        // Increment from zero
        let result = sm
            .apply(
                1,
                &Command::AdjustCounter {
                    key: "__i_links_count__".into(),
                    delta: 1,
                },
            )
            .unwrap();
        if let CommandResult::Value(bytes) = result {
            let val = i64::from_be_bytes(bytes.try_into().unwrap());
            assert_eq!(val, 1);
        } else {
            panic!("Expected Value result");
        }

        // Increment again
        let result = sm
            .apply(
                2,
                &Command::AdjustCounter {
                    key: "__i_links_count__".into(),
                    delta: 1,
                },
            )
            .unwrap();
        if let CommandResult::Value(bytes) = result {
            let val = i64::from_be_bytes(bytes.try_into().unwrap());
            assert_eq!(val, 2);
        } else {
            panic!("Expected Value result");
        }

        // Decrement
        let result = sm
            .apply(
                3,
                &Command::AdjustCounter {
                    key: "__i_links_count__".into(),
                    delta: -1,
                },
            )
            .unwrap();
        if let CommandResult::Value(bytes) = result {
            let val = i64::from_be_bytes(bytes.try_into().unwrap());
            assert_eq!(val, 1);
        } else {
            panic!("Expected Value result");
        }

        // Decrement below zero should clamp to 0
        let result = sm
            .apply(
                4,
                &Command::AdjustCounter {
                    key: "__i_links_count__".into(),
                    delta: -100,
                },
            )
            .unwrap();
        if let CommandResult::Value(bytes) = result {
            let val = i64::from_be_bytes(bytes.try_into().unwrap());
            assert_eq!(val, 0);
        } else {
            panic!("Expected Value result");
        }
    }

    #[test]
    fn test_apply_idempotency_guard() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let cmd = Command::SetMetadata {
            key: "/test".into(),
            value: b"data".to_vec(),
        };
        sm.apply(1, &cmd).unwrap();
        assert_eq!(sm.last_applied_index(), 1);
        let result = sm
            .apply(
                1,
                &Command::DeleteMetadata {
                    key: "/test".into(),
                },
            )
            .unwrap();
        assert!(matches!(result, CommandResult::Success));
        assert_eq!(sm.get_metadata("/test").unwrap(), Some(b"data".to_vec()));
        assert_eq!(sm.last_applied_index(), 1);
        let result = sm.apply(0, &Command::Noop).unwrap();
        assert!(matches!(result, CommandResult::Success));
        assert_eq!(sm.last_applied_index(), 1);
    }

    #[test]
    fn test_apply_advances_last_applied_sequentially() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        for i in 1..=5 {
            sm.apply(i, &Command::Noop).unwrap();
            assert_eq!(sm.last_applied_index(), i);
        }
        let sm2 = FullStateMachine::new(&store).unwrap();
        assert_eq!(sm2.last_applied_index(), 5);
    }

    #[test]
    fn test_apply_skips_gaps_correctly() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        sm.apply(1, &Command::Noop).unwrap();
        sm.apply(
            5,
            &Command::SetMetadata {
                key: "/test".into(),
                value: b"data".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(sm.last_applied_index(), 5);
        assert_eq!(sm.get_metadata("/test").unwrap(), Some(b"data".to_vec()));
    }

    #[test]
    fn test_restore_snapshot_corrupt_data_preserves_state() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/existing".into(),
                value: b"original".to_vec(),
            },
        )
        .unwrap();
        assert_eq!(sm.last_applied_index(), 1);
        let result = sm.restore_snapshot(b"this is not valid bincode");
        assert!(result.is_err(), "corrupt snapshot should return error");
        assert_eq!(
            sm.get_metadata("/existing").unwrap(),
            Some(b"original".to_vec())
        );
        assert_eq!(sm.last_applied_index(), 1);
    }

    #[test]
    fn test_restore_snapshot_empty_data() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let result = sm.restore_snapshot(b"");
        assert!(result.is_err(), "empty snapshot should return error");
    }

    #[test]
    fn test_restore_snapshot_overwrites_existing_data() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/old_file".into(),
                value: b"old_data".to_vec(),
            },
        )
        .unwrap();
        sm.apply(
            2,
            &Command::AcquireLock {
                path: "/old_file".into(),
                lock_id: "lock-old".into(),
                max_holders: 1,
                ttl_secs: 3600,
                holder_info: "agent:old".into(),
                now_secs: 1000,
            },
        )
        .unwrap();
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.apply(
            1,
            &Command::SetMetadata {
                key: "/new_file".into(),
                value: b"new_data".to_vec(),
            },
        )
        .unwrap();
        let snapshot_data = sm2.snapshot().unwrap();
        sm.restore_snapshot(&snapshot_data).unwrap();
        assert!(sm.get_metadata("/old_file").unwrap().is_none());
        assert!(sm.get_lock("/old_file").unwrap().is_none());
        assert_eq!(
            sm.get_metadata("/new_file").unwrap(),
            Some(b"new_data".to_vec())
        );
        assert_eq!(sm.last_applied_index(), 1);
    }

    #[test]
    fn test_restore_snapshot_persists_atomically() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.apply(
            1,
            &Command::SetMetadata {
                key: "/persisted".into(),
                value: b"value".to_vec(),
            },
        )
        .unwrap();
        sm2.apply(
            2,
            &Command::AcquireLock {
                path: "/persisted".into(),
                lock_id: "lock-1".into(),
                max_holders: 1,
                ttl_secs: 3600,
                holder_info: "agent:test".into(),
                now_secs: 1000,
            },
        )
        .unwrap();
        let snapshot_data = sm2.snapshot().unwrap();
        sm.restore_snapshot(&snapshot_data).unwrap();

        // Metadata persists across reopens (redb-backed).
        let sm3 = FullStateMachine::new(&store).unwrap();
        assert_eq!(
            sm3.get_metadata("/persisted").unwrap(),
            Some(b"value".to_vec())
        );
        assert_eq!(sm3.last_applied_index(), 2);

        // Advisory locks are in-memory only after R14 — reopening
        // constructs a fresh empty `Arc<Mutex<LockState>>`. Rebuilding
        // the BTreeMap is the job of the raft replay + snapshot restore
        // path on startup, not this plain `new(&store)` constructor.
        assert!(sm3.get_lock("/persisted").unwrap().is_none());

        // The same-instance sm (the one that received restore_snapshot)
        // does hold the advisory state — the mutex was repopulated in
        // place.
        assert!(sm.get_lock("/persisted").unwrap().is_some());
    }

    // ═══════════════════════════════════════════════════════════════
    // R14 — SSOT invariants: shared Arc, atomicity, rehydration
    // ═══════════════════════════════════════════════════════════════

    /// The `advisory_state()` handle is a clone of the Arc the apply
    /// path writes into — mutations made via `sm.apply(AcquireLock)`
    /// must be visible to any external holder of the same Arc without
    /// taking a second snapshot or restart.
    #[test]
    fn r14_apply_is_visible_through_shared_arc() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let shared = sm.advisory_state();

        sm.apply(
            1,
            &Command::AcquireLock {
                path: "/r14/a".into(),
                lock_id: "h1".into(),
                max_holders: 1,
                ttl_secs: 60,
                holder_info: "agent".into(),
                now_secs: 1000,
            },
        )
        .unwrap();

        // The external Arc sees the committed state immediately — no
        // ReadIndex, no redb round-trip.
        let guard = shared.lock();
        let entry = guard.get_lock("/r14/a").expect("lock should exist");
        assert_eq!(entry.holders.len(), 1);
        assert_eq!(entry.holders[0].lock_id, "h1");
    }

    /// Pre-populating the advisory Arc **before** constructing the
    /// state machine must survive: the state machine's apply path
    /// operates on that same Arc (no copy / replace on construction).
    /// This models the kernel's upgrade path where LockManager hands
    /// its Arc into FullStateMachine::with_advisory.
    #[test]
    fn r14_with_advisory_preserves_preexisting_holders() {
        use std::sync::Arc;

        let store = RedbStore::open_temporary().unwrap();
        let advisory = Arc::new(Mutex::new(LockState::new()));

        // Simulate local-mode kernel holders that existed pre-upgrade.
        {
            let mut guard = advisory.lock();
            guard.apply_acquire("/r14/pre", "local-h1", 1, 60, "agent", 1000);
        }

        let sm = FullStateMachine::with_advisory(&store, advisory.clone()).unwrap();

        // The state machine sees the pre-existing holder via shared Arc.
        assert!(sm.get_lock("/r14/pre").unwrap().is_some());
    }

    /// Snapshot serialization of the advisory BTreeMap is lossless —
    /// snapshot → fresh state machine → restore_snapshot produces an
    /// identical map.
    #[test]
    fn r14_snapshot_roundtrip_advisory_only() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        for (idx, (path, id)) in [("/r14/a", "h1"), ("/r14/b", "r1"), ("/r14/b", "r2")]
            .iter()
            .enumerate()
        {
            sm.apply(
                (idx + 1) as u64,
                &Command::AcquireLock {
                    path: path.to_string(),
                    lock_id: id.to_string(),
                    max_holders: 3,
                    ttl_secs: 60,
                    holder_info: "agent".into(),
                    now_secs: 1000,
                },
            )
            .unwrap();
        }

        let snap = sm.snapshot().unwrap();

        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.restore_snapshot(&snap).unwrap();

        let a = sm2.get_lock("/r14/a").unwrap().unwrap();
        assert_eq!(a.holders.len(), 1);
        assert_eq!(a.holders[0].lock_id, "h1");

        let b = sm2.get_lock("/r14/b").unwrap().unwrap();
        assert_eq!(b.holders.len(), 2);
        assert_eq!(b.max_holders, 3);
    }

    /// Lock commands are idempotent under full log replay — applying
    /// the same committed entry a second time (simulating a post-
    /// restart replay) produces the same final state, not a double-
    /// apply. This is the invariant that lets the apply() lock-path
    /// skip the `index <= last_applied` guard without corrupting state.
    #[test]
    fn r14_lock_replay_is_idempotent() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        let cmd = Command::AcquireLock {
            path: "/r14/replay".into(),
            lock_id: "h1".into(),
            max_holders: 1,
            ttl_secs: 60,
            holder_info: "agent".into(),
            now_secs: 1000,
        };
        sm.apply(1, &cmd).unwrap();
        // Replay: raft-rs may re-emit the same committed entry on
        // restart if our reported applied lags. Apply must be a no-op.
        sm.apply(1, &cmd).unwrap();

        let info = sm.get_lock("/r14/replay").unwrap().unwrap();
        assert_eq!(info.holders.len(), 1);
    }

    /// Apply and external reads share a single mutex. A reader can
    /// never observe a half-applied lock (an entry where max_holders
    /// was updated but the new holder hasn't been appended yet)
    /// because `LockState::apply_acquire` runs as a single
    /// mutate-under-guard step. Stress this with N writers + M
    /// readers; every read snapshot must reflect a complete,
    /// consistent state.
    #[test]
    fn r14_apply_and_read_are_atomic_under_contention() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let store = RedbStore::open_temporary().unwrap();
        let sm = Arc::new(std::sync::Mutex::new(
            FullStateMachine::new(&store).unwrap(),
        ));
        let shared = sm.lock().unwrap().advisory_state();

        let next_idx = Arc::new(AtomicU64::new(1));
        let writer_count = 32;
        let reader_count = 32;

        let mut handles = Vec::new();

        for i in 0..writer_count {
            let sm = sm.clone();
            let next_idx = next_idx.clone();
            handles.push(std::thread::spawn(move || {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                let path = format!("/r14/stress/{}", i % 8);
                let id = format!("h{}", i);
                sm.lock()
                    .unwrap()
                    .apply(
                        idx,
                        &Command::AcquireLock {
                            path,
                            lock_id: id,
                            max_holders: 32,
                            ttl_secs: 60,
                            holder_info: "agent".into(),
                            now_secs: 1000,
                        },
                    )
                    .unwrap();
            }));
        }

        for _ in 0..reader_count {
            let shared = shared.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let guard = shared.lock();
                    // Invariant: for every entry with holders,
                    // `max_holders` is non-zero (seeded atomically
                    // with the first push).
                    for entry in guard.locks.values() {
                        if !entry.holders.is_empty() {
                            assert!(
                                entry.max_holders > 0,
                                "observed entry with holders but max_holders=0",
                            );
                        }
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let guard = shared.lock();
        let total_holders: usize = guard.locks.values().map(|e| e.holders.len()).sum();
        assert!(total_holders > 0);
        assert!(total_holders <= writer_count as usize);
    }

    /// Snapshot taken while apply is in-flight captures a
    /// point-in-time state — no torn reads of the BTreeMap. The
    /// snapshot's BTreeMap clone happens under the advisory mutex
    /// (same as apply), so either the apply completed before the
    /// clone (snapshot sees it) or after (snapshot doesn't). Never
    /// neither / both.
    #[test]
    fn r14_snapshot_under_concurrent_apply_is_consistent() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let store = RedbStore::open_temporary().unwrap();
        let sm = Arc::new(std::sync::Mutex::new(
            FullStateMachine::new(&store).unwrap(),
        ));
        let next_idx = Arc::new(AtomicU64::new(1));
        let snapshots = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));

        let sm_w = sm.clone();
        let next_idx_w = next_idx.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..50 {
                let idx = next_idx_w.fetch_add(1, Ordering::Relaxed);
                sm_w.lock()
                    .unwrap()
                    .apply(
                        idx,
                        &Command::AcquireLock {
                            path: format!("/r14/sn/{}", i),
                            lock_id: format!("h{}", i),
                            max_holders: 1,
                            ttl_secs: 60,
                            holder_info: "agent".into(),
                            now_secs: 1000,
                        },
                    )
                    .unwrap();
            }
        });

        let sm_s = sm.clone();
        let snapshots_s = snapshots.clone();
        let snapper = std::thread::spawn(move || {
            for _ in 0..5 {
                let bytes = sm_s.lock().unwrap().snapshot().unwrap();
                snapshots_s.lock().unwrap().push(bytes);
            }
        });

        writer.join().unwrap();
        snapper.join().unwrap();

        // Every captured snapshot must deserialize and reproduce a
        // self-consistent map — holders only on entries whose
        // `max_holders > 0`.
        for bytes in snapshots.lock().unwrap().iter() {
            let snap: Snapshot = bincode::deserialize(bytes).unwrap();
            for entry in snap.advisory.locks.values() {
                if !entry.holders.is_empty() {
                    assert!(entry.max_holders > 0);
                }
            }
        }
    }

    /// The state machine assigns each entry's offset at apply (the caller
    /// passes only the stream PREFIX): the first append lands at seq 0, the
    /// next at seq 1, `get_stream_entry` reads the raw bytes back at the
    /// assigned key, and the returned `CommandResult::Value` carries the seq.
    #[test]
    fn stream_entry_sm_assigns_offset_at_apply() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let prefix = "/__wal_stream__/s/";

        let payload: Vec<u8> = (0u8..=255).collect();
        let r0 = sm
            .apply(
                1,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: payload.clone(),
                },
            )
            .unwrap();
        // The apply RETURNS the assigned offset (0) so the writer learns it.
        assert!(matches!(r0, CommandResult::Value(ref v) if v.as_slice() == 0u64.to_be_bytes()));

        let r1 = sm
            .apply(
                2,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: b"second".to_vec(),
                },
            )
            .unwrap();
        assert!(matches!(r1, CommandResult::Value(ref v) if v.as_slice() == 1u64.to_be_bytes()));

        // Entries land at the SM-assigned keys {prefix}{seq}, read back raw.
        assert_eq!(
            sm.get_stream_entry("/__wal_stream__/s/0").unwrap(),
            Some(payload)
        );
        assert_eq!(
            sm.get_stream_entry("/__wal_stream__/s/1").unwrap(),
            Some(b"second".to_vec())
        );
        // The cursor advanced to 2; the `__stream_tail__` sidecar is the SSOT.
        assert_eq!(sm.stream_tail(prefix).unwrap(), 2);
        // Stream entries (and the sidecar) do NOT appear in list_metadata —
        // different redb tree. Confirms no pollution of file-metadata scans.
        assert!(sm.list_metadata("/__wal_stream__/").unwrap().is_empty());
    }

    /// Multi-writer safety: several appends to the SAME stream (as arrive on
    /// one node from concurrent writers, serialized by the raft log) each get a
    /// DISTINCT, gap-free offset — none overwrites another. This is the exact
    /// loss the old client-side `next_seq` produced when two nodes both picked
    /// the same seq; assigning at apply makes it impossible.
    #[test]
    fn stream_entry_concurrent_writers_never_collide() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let prefix = "/__wal_stream__/shared/";

        for (i, body) in ["from-a", "from-b", "from-a-again"].iter().enumerate() {
            let r = sm
                .apply(
                    (i + 1) as u64,
                    &Command::AppendStreamEntry {
                        stream_prefix: prefix.into(),
                        data: body.as_bytes().to_vec(),
                    },
                )
                .unwrap();
            assert!(
                matches!(r, CommandResult::Value(ref v) if v.as_slice() == (i as u64).to_be_bytes()),
                "append {i} must be assigned offset {i}"
            );
        }
        // All three survive at distinct offsets — nothing overwritten.
        assert_eq!(
            sm.get_stream_entry("/__wal_stream__/shared/0").unwrap(),
            Some(b"from-a".to_vec())
        );
        assert_eq!(
            sm.get_stream_entry("/__wal_stream__/shared/1").unwrap(),
            Some(b"from-b".to_vec())
        );
        assert_eq!(
            sm.get_stream_entry("/__wal_stream__/shared/2").unwrap(),
            Some(b"from-a-again".to_vec())
        );
        assert_eq!(sm.stream_tail(prefix).unwrap(), 3);
    }

    /// Seal a range: the index record is written, the hot rows are deleted
    /// (bounding SM state), the floor advances, the global tail is unchanged, and
    /// cold reads resolve through `find_segment` while hot reads still hit the
    /// entry rows. This is the whole P1 tiered-storage contract in one apply.
    #[test]
    fn seal_spills_hot_rows_to_the_segment_index() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let prefix = "/__wal_stream__/seal/";

        // Six entries, seq 0..6.
        for i in 0..6u64 {
            sm.apply(
                i + 1,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: format!("m{i}").into_bytes(),
                },
            )
            .unwrap();
        }
        assert_eq!(sm.stream_tail(prefix).unwrap(), 6);
        assert_eq!(
            sm.stream_floor(prefix).unwrap(),
            0,
            "no floor before any seal"
        );

        // Seal [0,4) — the first four rows spill to a cold segment.
        let r = sm
            .apply(
                7,
                &Command::SealStreamSegment {
                    stream_prefix: prefix.into(),
                    base: 0,
                    end: 4,
                    content_id: "blake3-abc".into(),
                    origin: "127.0.0.1:9000".into(),
                    size: 1234,
                },
            )
            .unwrap();
        assert!(matches!(r, CommandResult::Success));

        // Hot rows [0,4) are gone; [4,6) remain — SM state is bounded to the hot
        // window.
        for seq in 0..4u64 {
            assert_eq!(
                sm.get_stream_entry(&format!("{prefix}{seq}")).unwrap(),
                None,
                "sealed row {seq} must be deleted from the hot tree"
            );
        }
        assert_eq!(
            sm.get_stream_entry(&format!("{prefix}4")).unwrap(),
            Some(b"m4".to_vec())
        );
        assert_eq!(
            sm.get_stream_entry(&format!("{prefix}5")).unwrap(),
            Some(b"m5".to_vec())
        );

        // Floor advanced; global tail (sys_stat.size SSOT) unchanged.
        assert_eq!(sm.stream_floor(prefix).unwrap(), 4);
        assert_eq!(sm.stream_tail(prefix).unwrap(), 6);

        // Cold seqs resolve through the segment index; hot/unwritten seqs do not.
        for seq in 0..4u64 {
            let (base, seg) = sm
                .find_segment(prefix, seq)
                .unwrap()
                .expect("cold seq resolves");
            assert_eq!(base, 0);
            assert_eq!(seg.end, 4);
            assert_eq!(seg.content_id, "blake3-abc");
            assert_eq!(seg.origin, "127.0.0.1:9000");
            assert_eq!(seg.size, 1234);
        }
        assert!(
            sm.find_segment(prefix, 4).unwrap().is_none(),
            "hot seq not in a segment"
        );
        assert!(sm.find_segment(prefix, 5).unwrap().is_none());

        // Segment index/floor/tail sidecars never leak into file-metadata scans.
        assert!(sm.list_metadata("/__wal_stream__/").unwrap().is_empty());
    }

    /// The `base == floor` gate makes a stale/duplicate/over-reaching seal a
    /// no-op error, and a second contiguous seal advances further — the pair that
    /// keeps concurrent proposers convergent (no gap, no dup, no offset skew).
    #[test]
    fn seal_gate_rejects_stale_and_chains_contiguously() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let prefix = "/__wal_stream__/gate/";
        for i in 0..6u64 {
            sm.apply(
                i + 1,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: format!("m{i}").into_bytes(),
                },
            )
            .unwrap();
        }
        // Seal [0,4).
        sm.apply(
            7,
            &Command::SealStreamSegment {
                stream_prefix: prefix.into(),
                base: 0,
                end: 4,
                content_id: "seg0".into(),
                origin: "a".into(),
                size: 4,
            },
        )
        .unwrap();

        // Stale duplicate (base=0, floor=4) → Error no-op.
        let dup = sm
            .apply(
                8,
                &Command::SealStreamSegment {
                    stream_prefix: prefix.into(),
                    base: 0,
                    end: 4,
                    content_id: "seg0".into(),
                    origin: "a".into(),
                    size: 4,
                },
            )
            .unwrap();
        assert!(
            matches!(dup, CommandResult::Error(_)),
            "stale seal must be a no-op error"
        );
        assert_eq!(
            sm.stream_floor(prefix).unwrap(),
            4,
            "floor unchanged after stale seal"
        );

        // Over-reach (end past tail) → Error no-op.
        let over = sm
            .apply(
                9,
                &Command::SealStreamSegment {
                    stream_prefix: prefix.into(),
                    base: 4,
                    end: 99,
                    content_id: "x".into(),
                    origin: "a".into(),
                    size: 1,
                },
            )
            .unwrap();
        assert!(matches!(over, CommandResult::Error(_)));
        assert_eq!(sm.stream_floor(prefix).unwrap(), 4);

        // Contiguous next seal [4,6) → Success, floor advances, second segment
        // resolves independently of the first.
        sm.apply(
            10,
            &Command::SealStreamSegment {
                stream_prefix: prefix.into(),
                base: 4,
                end: 6,
                content_id: "seg1".into(),
                origin: "b".into(),
                size: 2,
            },
        )
        .unwrap();
        assert_eq!(sm.stream_floor(prefix).unwrap(), 6);
        assert_eq!(
            sm.find_segment(prefix, 1).unwrap().unwrap().1.content_id,
            "seg0"
        );
        assert_eq!(
            sm.find_segment(prefix, 5).unwrap().unwrap().1.content_id,
            "seg1"
        );
        assert!(sm.find_segment(prefix, 6).unwrap().is_none());
    }

    /// Determinism / convergence: the SAME append+seal command sequence applied
    /// to two independent state machines yields byte-identical observable state
    /// (floor, tail, segment records). This is the raft invariant the seal design
    /// rests on — every replica applies the deterministic command and converges.
    #[test]
    fn seal_is_deterministic_across_replicas() {
        let cmds = [
            Command::AppendStreamEntry {
                stream_prefix: "/__wal_stream__/d/".into(),
                data: b"a".to_vec(),
            },
            Command::AppendStreamEntry {
                stream_prefix: "/__wal_stream__/d/".into(),
                data: b"b".to_vec(),
            },
            Command::AppendStreamEntry {
                stream_prefix: "/__wal_stream__/d/".into(),
                data: b"c".to_vec(),
            },
            Command::SealStreamSegment {
                stream_prefix: "/__wal_stream__/d/".into(),
                base: 0,
                end: 2,
                content_id: "seg".into(),
                origin: "node-a".into(),
                size: 2,
            },
        ];
        let build = || {
            let store = RedbStore::open_temporary().unwrap();
            let mut sm = FullStateMachine::new(&store).unwrap();
            for (i, c) in cmds.iter().enumerate() {
                sm.apply((i + 1) as u64, c).unwrap();
            }
            (
                sm.stream_floor("/__wal_stream__/d/").unwrap(),
                sm.stream_tail("/__wal_stream__/d/").unwrap(),
                sm.find_segment("/__wal_stream__/d/", 0).unwrap(),
                sm.get_stream_entry("/__wal_stream__/d/2").unwrap(),
            )
        };
        assert_eq!(
            build(),
            build(),
            "two replicas must converge to identical state"
        );
    }

    /// The bounded post-seal SM state — the hot tail + the segment index + the
    /// floor — rides the SM snapshot, and the sealed rows do NOT. This is the P1
    /// boundedness claim at the snapshot boundary: a joiner that installs the
    /// snapshot gets the small index, not every historical entry.
    #[test]
    fn sealed_segments_survive_snapshot_restore() {
        let prefix = "/__wal_stream__/snap/";
        let src = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&src).unwrap();
        for i in 0..6u64 {
            sm.apply(
                i + 1,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: format!("m{i}").into_bytes(),
                },
            )
            .unwrap();
        }
        sm.apply(
            7,
            &Command::SealStreamSegment {
                stream_prefix: prefix.into(),
                base: 0,
                end: 4,
                content_id: "snap-seg".into(),
                origin: "node-x".into(),
                size: 42,
            },
        )
        .unwrap();
        let snap = sm.snapshot().unwrap();

        // Restore into a FRESH state machine — the joiner's install path.
        let dst = RedbStore::open_temporary().unwrap();
        let mut restored = FullStateMachine::new(&dst).unwrap();
        restored.restore_snapshot(&snap).unwrap();

        // Bounded state survived: floor, tail, the segment index, and the hot
        // rows — but NOT the sealed rows.
        assert_eq!(restored.stream_floor(prefix).unwrap(), 4);
        assert_eq!(restored.stream_tail(prefix).unwrap(), 6);
        let (base, seg) = restored
            .find_segment(prefix, 0)
            .unwrap()
            .expect("segment rides snapshot");
        assert_eq!(base, 0);
        assert_eq!(seg.end, 4);
        assert_eq!(seg.content_id, "snap-seg");
        assert_eq!(seg.origin, "node-x");
        for seq in 0..4u64 {
            assert_eq!(
                restored
                    .get_stream_entry(&format!("{prefix}{seq}"))
                    .unwrap(),
                None,
                "sealed row {seq} must NOT be in the snapshot"
            );
        }
        for seq in 4..6u64 {
            assert!(restored
                .get_stream_entry(&format!("{prefix}{seq}"))
                .unwrap()
                .is_some());
        }
    }

    /// Trim drops the cold segments fully below `up_to`, advances `earliest`, and
    /// gates against stale / over-reaching (into the hot tail) requests. The
    /// remaining segments still resolve; the trimmed seqs no longer do.
    #[test]
    fn trim_drops_cold_segments_and_advances_earliest() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let prefix = "/__wal_stream__/trim/";
        for i in 0..12u64 {
            sm.apply(
                i + 1,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: format!("m{i}").into_bytes(),
                },
            )
            .unwrap();
        }
        for (idx, (base, end, cid)) in [(0u64, 4u64, "c0"), (4, 8, "c1")].iter().enumerate() {
            sm.apply(
                13 + idx as u64,
                &Command::SealStreamSegment {
                    stream_prefix: prefix.into(),
                    base: *base,
                    end: *end,
                    content_id: (*cid).into(),
                    origin: "a".into(),
                    size: 10,
                },
            )
            .unwrap();
        }
        assert_eq!(sm.list_segments(prefix).unwrap().len(), 2);
        assert_eq!(sm.stream_earliest(prefix).unwrap(), 0);

        // Trim up_to=4 → drops segment [0,4), earliest=4.
        let r = sm
            .apply(
                15,
                &Command::TrimStreamSegment {
                    stream_prefix: prefix.into(),
                    up_to_seq: 4,
                    trimmed: vec![("a".into(), "c0".into())],
                },
            )
            .unwrap();
        assert!(matches!(r, CommandResult::Success));
        assert_eq!(sm.stream_earliest(prefix).unwrap(), 4);
        let segs = sm.list_segments(prefix).unwrap();
        assert_eq!(segs.len(), 1, "only the [4,8) segment remains");
        assert_eq!(segs[0].0, 4);
        assert!(
            sm.find_segment(prefix, 0).unwrap().is_none(),
            "trimmed seq gone"
        );
        assert!(
            sm.find_segment(prefix, 5).unwrap().is_some(),
            "kept seq resolves"
        );

        // Gate: stale (up_to <= earliest) and over-reach (up_to > floor=8) are
        // no-op errors; earliest is unchanged.
        assert!(matches!(
            sm.apply(
                16,
                &Command::TrimStreamSegment {
                    stream_prefix: prefix.into(),
                    up_to_seq: 4,
                    trimmed: vec![],
                },
            )
            .unwrap(),
            CommandResult::Error(_)
        ));
        assert!(matches!(
            sm.apply(
                17,
                &Command::TrimStreamSegment {
                    stream_prefix: prefix.into(),
                    up_to_seq: 99,
                    trimmed: vec![],
                },
            )
            .unwrap(),
            CommandResult::Error(_)
        ));
        assert_eq!(sm.stream_earliest(prefix).unwrap(), 4);
    }

    /// Build a `PutControlState` for the `auth` namespace (an upsert), the shape
    /// the auth store emits. Keeps the auth tests reading through the
    /// `get_auth_key`/`list_auth_keys` (namespace `auth`) wrappers.
    fn put_auth(key_hash: &str, record: Vec<u8>) -> Command {
        Command::PutControlState {
            namespace: contracts::CONTROL_NS_AUTH.to_string(),
            key: key_hash.to_string(),
            value: record,
            if_absent: false,
        }
    }

    /// ``PutControlState`` stores opaque record bytes; ``get_auth_key`` reads
    /// them back untouched — and the record NEVER appears in the
    /// file-metadata tree (different redb tree), which is the whole
    /// point of the dedicated store. This is the invariant the "auth
    /// records are not files" decision rests on.
    #[test]
    fn auth_key_roundtrip_and_isolated_from_metadata() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();

        let hash = "abc123deadbeef";
        let record: Vec<u8> = (0u8..=255).collect(); // opaque, non-proto bytes
        sm.apply(1, &put_auth(hash, record.clone())).unwrap();

        assert_eq!(sm.get_auth_key(hash).unwrap(), Some(record));
        // Not reachable through the file-metadata path: neither a
        // point read nor a full-tree list surfaces it. If this ever
        // fails, auth records have leaked into the sys_read/readdir
        // surface.
        assert!(sm.get_metadata(hash).unwrap().is_none());
        assert!(sm.list_metadata("").unwrap().is_empty());
    }

    /// ``DeleteControlState`` (revocation) removes the record.
    #[test]
    fn auth_key_delete_revokes() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        sm.apply(1, &put_auth("h", b"rec".to_vec())).unwrap();
        assert!(sm.get_auth_key("h").unwrap().is_some());
        sm.apply(
            2,
            &Command::DeleteControlState {
                namespace: contracts::CONTROL_NS_AUTH.to_string(),
                key: "h".to_string(),
            },
        )
        .unwrap();
        assert!(sm.get_auth_key("h").unwrap().is_none());
    }

    /// A CAS `PutControlState { if_absent: true }` is a log-ordered uniqueness
    /// gate: the first write wins, a second under the same `(namespace, key)` is
    /// refused (`CommandResult::Error`) without clobbering, while `if_absent:
    /// false` upserts. Backs agent-name dedup + foreign-CA anchor re-pin
    /// rejection.
    #[test]
    fn control_state_cas_put_if_absent_rejects_duplicate() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let cas = |k: &str, v: &[u8]| Command::PutControlState {
            namespace: contracts::CONTROL_NS_FOREIGN_CA.to_string(),
            key: k.to_string(),
            value: v.to_vec(),
            if_absent: true,
        };

        // First pin wins.
        assert!(matches!(
            sm.apply(1, &cas("anchor-a", b"v1")).unwrap(),
            CommandResult::Success
        ));
        // Re-pin of the same key is refused, and the stored value is untouched.
        assert!(matches!(
            sm.apply(2, &cas("anchor-a", b"v2")).unwrap(),
            CommandResult::Error(_)
        ));
        assert_eq!(
            sm.get_control_state(contracts::CONTROL_NS_FOREIGN_CA, "anchor-a")
                .unwrap(),
            Some(b"v1".to_vec())
        );
        // A non-CAS upsert overwrites.
        sm.apply(
            3,
            &Command::PutControlState {
                namespace: contracts::CONTROL_NS_FOREIGN_CA.to_string(),
                key: "anchor-a".to_string(),
                value: b"v3".to_vec(),
                if_absent: false,
            },
        )
        .unwrap();
        assert_eq!(
            sm.get_control_state(contracts::CONTROL_NS_FOREIGN_CA, "anchor-a")
                .unwrap(),
            Some(b"v3".to_vec())
        );
    }

    /// ``list_auth_keys`` enumerates every stored record — backs the
    /// admin procfs view.
    #[test]
    fn auth_key_list_enumerates_all() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        for (i, h) in ["h1", "h2", "h3"].iter().enumerate() {
            sm.apply((i + 1) as u64, &put_auth(h, format!("r{i}").into_bytes()))
                .unwrap();
        }
        let mut listed: Vec<String> = sm
            .list_auth_keys()
            .unwrap()
            .into_iter()
            .map(|(h, _)| h)
            .collect();
        listed.sort();
        assert_eq!(listed, vec!["h1", "h2", "h3"]);
    }

    /// Auth records travel in the snapshot and restore intact on a
    /// fresh replica — the mechanism that lets a catching-up node serve
    /// authentication without replaying the whole log.
    #[test]
    fn auth_key_survives_snapshot_restore() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        sm.apply(1, &put_auth("snap", b"survives".to_vec()))
            .unwrap();
        let bytes = sm.snapshot().unwrap();

        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        assert!(sm2.get_auth_key("snap").unwrap().is_none());
        sm2.restore_snapshot(&bytes).unwrap();
        assert_eq!(
            sm2.get_auth_key("snap").unwrap(),
            Some(b"survives".to_vec())
        );
    }

    /// Snapshot + restore round-trips stream entries AND their offset cursor.
    /// The cursor (`__stream_tail__` sidecar) rides the same tree, so a
    /// snapshot-restored replica keeps counting from where the stream left off:
    /// a post-restore append lands at the NEXT offset, never overwriting a
    /// restored entry. (A separate cursor tree that missed the snapshot would
    /// reset to 0 and clobber — the P7 trap this design avoids.)
    #[test]
    fn stream_entry_and_cursor_survive_snapshot_restore() {
        let store = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&store).unwrap();
        let prefix = "/__wal_stream__/s/";
        sm.apply(
            1,
            &Command::AppendStreamEntry {
                stream_prefix: prefix.into(),
                data: vec![0xde, 0xad, 0xbe, 0xef],
            },
        )
        .unwrap();
        sm.apply(
            2,
            &Command::AppendStreamEntry {
                stream_prefix: prefix.into(),
                data: vec![0x00, 0xff],
            },
        )
        .unwrap();

        let snap_bytes = sm.snapshot().unwrap();

        let store2 = RedbStore::open_temporary().unwrap();
        let mut sm2 = FullStateMachine::new(&store2).unwrap();
        sm2.restore_snapshot(&snap_bytes).unwrap();

        // Entries restored intact at their assigned offsets.
        assert_eq!(
            sm2.get_stream_entry("/__wal_stream__/s/0").unwrap(),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(
            sm2.get_stream_entry("/__wal_stream__/s/1").unwrap(),
            Some(vec![0x00, 0xff])
        );
        // Cursor restored too: the next append lands at seq 2, not 0.
        assert_eq!(sm2.stream_tail(prefix).unwrap(), 2);
        let r = sm2
            .apply(
                3,
                &Command::AppendStreamEntry {
                    stream_prefix: prefix.into(),
                    data: b"post-restore".to_vec(),
                },
            )
            .unwrap();
        assert!(matches!(r, CommandResult::Value(ref v) if v.as_slice() == 2u64.to_be_bytes()));
        assert_eq!(
            sm2.get_stream_entry("/__wal_stream__/s/2").unwrap(),
            Some(b"post-restore".to_vec())
        );
        // The originals were NOT clobbered.
        assert_eq!(
            sm2.get_stream_entry("/__wal_stream__/s/0").unwrap(),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }
}
