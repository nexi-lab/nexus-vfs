//! Zone-mutation operation journal (R8) — the idempotency substrate behind
//! the typed ZoneRuntime surface.
//!
//! A caller whose `ZoneCreate` response was lost must be able to retry or
//! query WITHOUT creating a second zone. Every typed mutation therefore
//! opens with a journal `begin`: a `put_if_absent(PENDING)` on the
//! replicated control store, which is a **log-ordered uniqueness gate** —
//! raft serializes the command, so exactly one proposer of a given
//! `operation_id` wins the insert and becomes the executor; every other
//! attempt (concurrent or a later retry) reads back the winner's record.
//!
//! The record then walks `PENDING → COMPLETED` (or `REJECTED`) via a
//! read-judge-write. `ControlStateStore` has no CAS primitive, so this
//! walk is guarded by a single-executor design plus a takeover grace:
//!
//! * The winner of `begin`'s insert is the executor; a concurrent or
//!   immediate retry replays its record instead of executing.
//! * A PENDING record whose `updated_at_ms` is older than the takeover
//!   grace (see the zone runtime, which owns the constant) may be TAKEN
//!   OVER by a retryer with the same request hash — the crash-orphan
//!   recovery path. The taker re-stamps `updated_at_ms` (`refresh`) so
//!   ITS execution window is grace-protected too.
//! * Two writers can therefore overlap only in the crash-recovery corner
//!   (the original executor alive but stuck past the grace). The
//!   transition's read-judge-write re-reads before its unconditional
//!   `put`, so a late writer abandons rather than overwriting a record
//!   that went terminal mid-write; the residual window is the
//!   microseconds between that re-read and the `put`.
//!
//! Storage rides the control zone via `Command::PutControlState` — opaque
//! bytes the state machine never parses, zero new raft `Command` variants
//! (D7/D8: zone-level mutations only; journal availability = control-zone
//! availability, accepted). Values are serde-encoded [`JournalRecord`]s;
//! the embedded receipt is the prost-encoded `ZoneReceipt` wire message,
//! opaque to the journal itself.

use contracts::CONTROL_NS_ZONE_OPS;
use serde::{Deserialize, Serialize};

use crate::control_state_store::ControlStateStore;
use crate::raft::{FullStateMachine, ZoneConsensus};

/// Record status — a one-way walk. `PENDING` means the executor is
/// mid-flight OR died mid-flight (the caller retries with a new
/// `operation_id`, or keeps polling `GetZoneOperation`).
pub(crate) const STATUS_PENDING: &str = "PENDING";
pub(crate) const STATUS_COMPLETED: &str = "COMPLETED";
pub(crate) const STATUS_REJECTED: &str = "REJECTED";

/// One journal entry under `zone-ops/{operation_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    pub operation_id: String,
    pub request_hash: u64,
    /// create | join | mount | unmount | remove_replica | deprovision.
    pub kind: String,
    pub zone_id: String,
    /// [`STATUS_PENDING`] | [`STATUS_COMPLETED`] | [`STATUS_REJECTED`].
    pub status: String,
    /// Prost-encoded `ZoneReceipt` — present iff status == COMPLETED.
    pub receipt: Option<Vec<u8>>,
    /// Human-readable refusal reason — present iff status == REJECTED.
    pub error: Option<String>,
    pub updated_at_ms: i64,
}

/// What `begin` found for an `operation_id`.
pub enum BeginOutcome {
    /// No prior record — this caller is the single executor. A PENDING
    /// record is durably in place; proceed with the mutation.
    Begin,
    /// The operation already ran (or is running) under this exact
    /// `operation_id` + `request_hash`. Carries the record so the caller
    /// can answer with `replayed = true` (COMPLETED) or "still PENDING".
    AlreadyInProgress(JournalRecord),
}

/// The zone-mutation journal: a namespaced view on the control store.
pub struct ZoneOpJournal {
    store: ControlStateStore,
}

impl ZoneOpJournal {
    /// Bind to the control zone's consensus (or the local root zone on an
    /// auth-off node — D8: both are "the store", availability follows it).
    pub fn new(node: ZoneConsensus<FullStateMachine>, runtime: tokio::runtime::Handle) -> Self {
        Self {
            store: ControlStateStore::new(node, runtime, CONTROL_NS_ZONE_OPS),
        }
    }

    /// Claim `operation_id` for execution, or discover it is already
    /// claimed. Same id + same `request_hash` ⇒ replay (idempotent retry);
    /// same id + DIFFERENT hash ⇒ refusal — a reused operation id must not
    /// silently merge a different request.
    pub fn begin(
        &self,
        operation_id: &str,
        request_hash: u64,
        kind: &str,
        zone_id: &str,
    ) -> Result<BeginOutcome, String> {
        let pending = JournalRecord {
            operation_id: operation_id.to_string(),
            request_hash,
            kind: kind.to_string(),
            zone_id: zone_id.to_string(),
            status: STATUS_PENDING.to_string(),
            receipt: None,
            error: None,
            updated_at_ms: now_ms(),
        };
        let bytes = serde_json::to_vec(&pending).map_err(|e| format!("journal encode: {e}"))?;
        if self.store.put_if_absent(operation_id, &bytes)? {
            return Ok(BeginOutcome::Begin);
        }
        // Already claimed. Hash match ⇒ replay; mismatch ⇒ refuse.
        let existing = self
            .get(operation_id)?
            .ok_or_else(|| format!("journal record '{operation_id}' vanished mid-begin"))?;
        if existing.request_hash != request_hash {
            return Err(format!(
                "operation_id '{operation_id}' already recorded with a different request \
                 (hash {} ≠ {}); mint a new operation_id for a new request",
                existing.request_hash, request_hash
            ));
        }
        Ok(BeginOutcome::AlreadyInProgress(existing))
    }

    /// Mark COMPLETED with the receipt (read-judge-write: only overwrites a
    /// record still PENDING — a stale concurrent writer cannot regress a
    /// finished record).
    pub fn complete(&self, operation_id: &str, receipt: &[u8]) -> Result<(), String> {
        self.transition(operation_id, "complete", |mut rec| {
            rec.status = STATUS_COMPLETED.to_string();
            rec.receipt = Some(receipt.to_vec());
            rec.error = None;
            rec.updated_at_ms = now_ms();
            rec
        })
    }

    /// Mark REJECTED with the refusal reason (same one-way guard).
    pub fn reject(&self, operation_id: &str, error: &str) -> Result<(), String> {
        self.transition(operation_id, "reject", |mut rec| {
            rec.status = STATUS_REJECTED.to_string();
            rec.error = Some(error.to_string());
            rec.updated_at_ms = now_ms();
            rec
        })
    }

    /// Re-stamp a PENDING record's `updated_at_ms` (no other field changes).
    /// Called by a takeover executor: the grace window restarts from the
    /// takeover point, so a later retryer cannot immediately take over the
    /// taker-over. No-op on a record that is terminal or absent.
    pub(crate) fn refresh(&self, operation_id: &str) -> Result<(), String> {
        self.transition(operation_id, "refresh", |mut rec| {
            rec.updated_at_ms = now_ms();
            rec
        })
    }

    /// Read one record (the `GetZoneOperation` backing store).
    pub fn get(&self, operation_id: &str) -> Result<Option<JournalRecord>, String> {
        match self.store.get(operation_id)? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("journal decode '{operation_id}': {e}")),
        }
    }

    /// Shared read-judge-write for the PENDING → terminal transition. A
    /// record already terminal (or absent) is left untouched. This is NOT
    /// a cross-writer CAS — the store's `put` is an unconditional upsert,
    /// so a writer that judged PENDING can still land after a concurrent
    /// terminal write; the pre-put re-read below narrows that overwrite
    /// window to the microseconds between the re-read and the `put` (the
    /// single-executor design plus the takeover grace make a genuine
    /// two-writer overlap a crash-recovery corner — see the module doc).
    fn transition(
        &self,
        operation_id: &str,
        intent: &str,
        f: impl FnOnce(JournalRecord) -> JournalRecord,
    ) -> Result<(), String> {
        let Some(current) = self.get(operation_id)? else {
            return Err(format!(
                "journal record '{operation_id}' vanished before transition"
            ));
        };
        if current.status != STATUS_PENDING {
            // Lost the race to a terminal state (or replayed an old call) —
            // the durable record already says something at least as final.
            tracing::warn!(
                operation_id,
                status = %current.status,
                "journal transition '{intent}' skipped: record already terminal"
            );
            return Ok(());
        }
        let next = f(current);
        // Pre-put re-read: write only while the record is STILL pending, so
        // a writer that judged PENDING earlier cannot overwrite a terminal
        // state that landed mid-write (nor can a takeover `refresh` revert
        // one).
        let Some(reread) = self.get(operation_id)? else {
            return Err(format!(
                "journal record '{operation_id}' vanished before transition"
            ));
        };
        if reread.status != STATUS_PENDING {
            tracing::warn!(
                operation_id,
                status = %reread.status,
                "journal transition '{intent}' abandoned: record went terminal mid-write"
            );
            return Ok(());
        }
        let bytes = serde_json::to_vec(&next).map_err(|e| format!("journal encode: {e}"))?;
        self.store.put(operation_id, &bytes)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
