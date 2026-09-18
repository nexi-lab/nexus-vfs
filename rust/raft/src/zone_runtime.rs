//! Typed Zone runtime backend (R7–R10) — the `ZoneRuntimeOps` implementor
//! behind the gRPC `ZoneRuntimeService`.
//!
//! Wraps the existing [`ZoneManager`] (create/join/mount/unmount/remove are
//! NOT re-implemented — the typed surface is an admission + receipt +
//! idempotency layer over them) plus the [`ZoneOpJournal`]. Every mutation:
//! admission-validates the zone id per use (`TenantZoneIdCreate` for create,
//! `RemoteLearned` for join), claims its `operation_id` in the journal
//! (single executor, replay-aware), executes via `ZoneManager`, then
//! READS BACK the physical facts (raft term/commit/voters, DT_MOUNT entry,
//! i_links) into a `ZoneReceipt` — no phantom success. Deprovision grows
//! its deletion-epoch leg in the zone-deletion phase; the journal +
//! remove + receipt skeleton lands here.

use std::sync::Arc;
use std::time::Duration;

use contracts::{validate_zone_id_for, ZoneIdUse};
use kernel::kernel::vfs_proto::{
    ClusterFacts, DeletionInfo, GetZoneOperationRequest, MountFacts, ZoneCreateRequest,
    ZoneDeprovisionRequest, ZoneJoinRequest, ZoneMountRequest, ZoneOperationRecord, ZoneReceipt,
    ZoneRemoveReplicaRequest, ZoneStatusRequest, ZoneStatusResponse, ZoneUnmountRequest,
};
use prost::Message;

use crate::raft::{wait_until_caught_up, RaftError};
use crate::zone_deletion_registry::ZoneDeletionRegistry;
use crate::zone_manager::{decode_file_metadata, ZoneManager, ZonePresence, DT_MOUNT};
use crate::zone_op_journal::{BeginOutcome, JournalRecord, ZoneOpJournal};

/// prost flattens the nested `ZoneStatusResponse.Presence` enum into a
/// sibling module — re-exported here so the ladder reads as one type.
use kernel::kernel::vfs_proto::zone_status_response::Presence;

/// Refusal taxonomy for the typed surface. The transport layer maps each
/// variant onto a tonic `Status` code; the journal stores the message.
#[derive(Debug)]
pub enum ZoneRuntimeError {
    /// Caller is not allowed to do this (admin gate, permission gate).
    PermissionDenied(String),
    /// Malformed request (bad zone id for the use, missing header).
    Invalid(String),
    /// The request conflicts with durable state (hash mismatch on a
    /// replayed operation id, different membership, reserved zone,
    /// deleted zone).
    Conflict(String),
    /// Journal lookup miss.
    NotFound(String),
    /// Execution failure underneath (raft, IO).
    Internal(String),
}

impl std::fmt::Display for ZoneRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneRuntimeError::PermissionDenied(m)
            | ZoneRuntimeError::Invalid(m)
            | ZoneRuntimeError::Conflict(m)
            | ZoneRuntimeError::NotFound(m)
            | ZoneRuntimeError::Internal(m) => f.write_str(m),
        }
    }
}

/// Receipt outcome strings (proto uses `string`, not enum, so the journal
/// stays opaque; these are the closed set the surface emits).
pub(crate) const OUTCOME_CREATED: &str = "CREATED";
pub(crate) const OUTCOME_ALREADY_PRESENT: &str = "ALREADY_PRESENT";
pub(crate) const OUTCOME_JOINED: &str = "JOINED";
pub(crate) const OUTCOME_MOUNTED: &str = "MOUNTED";
pub(crate) const OUTCOME_UNMOUNTED: &str = "UNMOUNTED";
pub(crate) const OUTCOME_REPLICA_REMOVED: &str = "REPLICA_REMOVED";
pub(crate) const OUTCOME_DEPROVISIONED: &str = "DEPROVISIONED";

/// How long a receipt read-back waits for the zone's apply loop to catch
/// up with its own log before snapshotting facts (same budget as the
/// coordinator's federation replay).
const CATCHUP_BUDGET: Duration = Duration::from_secs(10);

pub struct ZoneRuntimeBackend {
    zm: Arc<ZoneManager>,
    journal: ZoneOpJournal,
    deletions: Arc<ZoneDeletionRegistry>,
}

impl ZoneRuntimeBackend {
    pub fn new(
        zm: Arc<ZoneManager>,
        journal: ZoneOpJournal,
        deletions: Arc<ZoneDeletionRegistry>,
    ) -> Self {
        Self {
            zm,
            journal,
            deletions,
        }
    }

    /// R12: a deprovisioned zone stays gone — a create for a recorded-
    /// deleted zone id is refused (recreate is a later explicit work
    /// item, not a silent side effect of a stale retry).
    fn refuse_if_deleted(&self, zone_id: &str) -> Result<(), ZoneRuntimeError> {
        match self.deletions.deletion_epoch(zone_id) {
            Ok(Some(epoch)) => Err(ZoneRuntimeError::Conflict(format!(
                "zone '{zone_id}' was deprovisioned (deletion epoch {epoch}); creating it \
                 again requires an explicit recovery procedure"
            ))),
            Ok(None) => Ok(()),
            Err(e) => Err(ZoneRuntimeError::Internal(format!(
                "deletion registry unreadable for '{zone_id}': {e}"
            ))),
        }
    }

    /// Create a zone — tenant-create admission (full 3–63/charset/edge/
    /// reserved rules), single executor per operation id, physical
    /// read-back. `ZoneManager::create_zone` is itself idempotent per
    /// address book, so an operation retried under a NEW operation id
    /// after a crash mid-flight yields ALREADY_PRESENT, not a second zone.
    pub fn zone_create(&self, req: &ZoneCreateRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let header = require_header(req.mutation.as_ref())?;
        validate_zone_id_for(ZoneIdUse::TenantCreate, &req.zone_id)
            .map_err(|e| ZoneRuntimeError::Invalid(format!("zone_id: {e}")))?;
        self.refuse_if_deleted(&req.zone_id)?;
        let hash = request_hash(b"create", &[&req.zone_id, &join_sorted(&req.peers)]);

        if let Some(replay) =
            self.begin_or_replay(&header.operation_id, hash, "create", &req.zone_id)?
        {
            return Ok(replay);
        }

        let existed = self.zm.get_zone(&req.zone_id).is_some();
        if let Err(e) = self.zm.create_zone(&req.zone_id, req.peers.clone()) {
            return self.fail(
                &header.operation_id,
                map_raft_err(e),
                "create",
                &req.zone_id,
            );
        }
        let outcome = if existed {
            OUTCOME_ALREADY_PRESENT
        } else {
            OUTCOME_CREATED
        };
        let mut facts = self.cluster_facts_caught_up(&req.zone_id);
        facts.has_store = facts.has_store && self.zm.hosts_zone(&req.zone_id);
        let mut receipt = base_receipt(&header.operation_id, &req.zone_id, "create", outcome);
        receipt.cluster = Some(facts);
        receipt.evidence = vec![
            format!("zone_id passed TenantZoneIdCreate admission"),
            format!(
                "hosts_zone={} voters={} commit_index={}",
                self.zm.hosts_zone(&req.zone_id),
                receipt.cluster.as_ref().map_or(0, |c| c.voter_count),
                receipt.cluster.as_ref().map_or(0, |c| c.commit_index),
            ),
        ];
        self.complete(&header.operation_id, &req.zone_id, receipt)
    }

    /// Join an existing zone (R9/D2) — `ZoneManager::join_zone` only; there
    /// is NO founder fallback on this path. A join that cannot reach peers
    /// fails loudly; it can never degrade into a create.
    pub fn zone_join(&self, req: &ZoneJoinRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let header = require_header(req.mutation.as_ref())?;
        validate_zone_id_for(ZoneIdUse::RemoteLearned, &req.zone_id)
            .map_err(|e| ZoneRuntimeError::Invalid(format!("zone_id: {e}")))?;
        let hash = request_hash(
            b"join",
            &[
                &req.zone_id,
                &join_sorted(&req.peers),
                &req.learner.to_string(),
            ],
        );

        if let Some(replay) =
            self.begin_or_replay(&header.operation_id, hash, "join", &req.zone_id)?
        {
            return Ok(replay);
        }

        if let Err(e) = self
            .zm
            .join_zone(&req.zone_id, req.peers.clone(), req.learner)
        {
            return self.fail(&header.operation_id, map_raft_err(e), "join", &req.zone_id);
        }
        let mut facts = self.cluster_facts_caught_up(&req.zone_id);
        facts.has_store = facts.has_store && self.zm.hosts_zone(&req.zone_id);
        let mut receipt = base_receipt(&header.operation_id, &req.zone_id, "join", OUTCOME_JOINED);
        receipt.cluster = Some(facts);
        receipt.evidence = vec![
            format!(
                "join path only — no founder bootstrap fallback (learner={})",
                req.learner
            ),
            format!(
                "hosts_zone={} applied_index={}",
                self.zm.hosts_zone(&req.zone_id),
                receipt.cluster.as_ref().map_or(0, |c| c.applied_index),
            ),
        ];
        self.complete(&header.operation_id, &req.zone_id, receipt)
    }

    /// Presence ladder + raft facts (R10). Reading facts never materializes
    /// a cold zone — a `HOSTED_NOT_RESIDENT` answer must not drag the zone
    /// into residency just by being asked about it.
    pub fn zone_status(
        &self,
        req: &ZoneStatusRequest,
    ) -> Result<ZoneStatusResponse, ZoneRuntimeError> {
        validate_zone_id_for(ZoneIdUse::ExistingRef, &req.zone_id)
            .map_err(|e| ZoneRuntimeError::Invalid(format!("zone_id: {e}")))?;
        let mut resp = ZoneStatusResponse {
            zone_id: req.zone_id.clone(),
            ..Default::default()
        };
        // Deleted (R12) outranks the local ladder: a recorded replicated
        // deletion answers DELETED regardless of what local disk holds
        // (a stale replica that missed the fan-out still hosts the dir).
        if let Some(info) = self
            .deletions
            .deletion_info(&req.zone_id)
            .map_err(ZoneRuntimeError::Internal)?
        {
            resp.presence = Presence::Deleted.into();
            resp.deletion = Some(DeletionInfo {
                deletion_epoch: info.deletion_epoch,
                deleted_at_ms: info.deleted_at_ms as i64,
            });
            return Ok(resp);
        }
        match self.zm.zone_presence(&req.zone_id) {
            ZonePresence::LocalNotFound => {
                resp.presence = Presence::LocalNotFound.into();
            }
            ZonePresence::HostedNotResident => {
                resp.presence = Presence::HostedNotResident.into();
            }
            ZonePresence::Resident => {
                resp.presence = Presence::Resident.into();
                // Only a resident runtime has live facts; a cold zone keeps
                // its facts empty rather than being materialized for them.
                resp.cluster = Some(self.cluster_facts_caught_up(&req.zone_id));
            }
        }
        Ok(resp)
    }

    /// Mount target under parent (R11 zone-level layer) + DT_MOUNT
    /// read-back into MountFacts.
    pub fn zone_mount(&self, req: &ZoneMountRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let header = require_header(req.mutation.as_ref())?;
        for (label, id) in [
            ("parent_zone_id", &req.parent_zone_id),
            ("target_zone_id", &req.target_zone_id),
        ] {
            validate_zone_id_for(ZoneIdUse::ExistingRef, id)
                .map_err(|e| ZoneRuntimeError::Invalid(format!("{label}: {e}")))?;
        }
        let hash = request_hash(
            b"mount",
            &[&req.parent_zone_id, &req.mount_path, &req.target_zone_id],
        );

        if let Some(replay) =
            self.begin_or_replay(&header.operation_id, hash, "mount", &req.target_zone_id)?
        {
            return Ok(replay);
        }

        if let Err(e) = self.zm.mount(
            &req.parent_zone_id,
            &req.mount_path,
            &req.target_zone_id,
            true,
        ) {
            return self.fail(
                &header.operation_id,
                map_raft_err(e),
                "mount",
                &req.target_zone_id,
            );
        }
        // Physical read-back: the parent's state machine must now hold a
        // DT_MOUNT at mount_path pointing at the target, and the target's
        // i_links must have moved.
        let parent = self
            .zm
            .get_zone(&req.parent_zone_id)
            .ok_or_else(|| ZoneRuntimeError::Internal("parent zone vanished after mount".into()))?;
        let entry = parent
            .get_metadata(&req.mount_path)
            .map_err(|e| ZoneRuntimeError::Internal(format!("mount read-back: {e}")))?
            .and_then(|bytes| decode_file_metadata(&bytes).ok());
        let links = self.zm.get_links_count(&req.target_zone_id).unwrap_or(None);
        let mounted = entry.as_ref().is_some_and(|meta| {
            meta.entry_type == DT_MOUNT && meta.target_zone_id == req.target_zone_id
        });
        if !mounted {
            let e = ZoneRuntimeError::Internal(format!(
                "mount read-back: no DT_MOUNT → {} at '{}' in '{}'",
                req.target_zone_id, req.mount_path, req.parent_zone_id
            ));
            return self.fail(&header.operation_id, e, "mount", &req.target_zone_id);
        }
        let mut receipt = base_receipt(
            &header.operation_id,
            &req.target_zone_id,
            "mount",
            OUTCOME_MOUNTED,
        );
        receipt.mount = Some(MountFacts {
            mount_path: req.mount_path.clone(),
            target_zone_id: req.target_zone_id.clone(),
            i_links_count: links.unwrap_or(0),
        });
        receipt.evidence = vec![format!(
            "DT_MOUNT entry re-read from parent '{}' at '{}' → '{}'",
            req.parent_zone_id, req.mount_path, req.target_zone_id
        )];
        self.complete(&header.operation_id, &req.target_zone_id, receipt)
    }

    /// Unmount, restoring DT_DIR; MountFacts carries the post-unmount
    /// link count of the former target.
    pub fn zone_unmount(&self, req: &ZoneUnmountRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let header = require_header(req.mutation.as_ref())?;
        validate_zone_id_for(ZoneIdUse::ExistingRef, &req.parent_zone_id)
            .map_err(|e| ZoneRuntimeError::Invalid(format!("parent_zone_id: {e}")))?;
        let hash = request_hash(b"unmount", &[&req.parent_zone_id, &req.mount_path]);

        if let Some(replay) =
            self.begin_or_replay(&header.operation_id, hash, "unmount", &req.parent_zone_id)?
        {
            return Ok(replay);
        }

        let former_target = match self.zm.unmount(&req.parent_zone_id, &req.mount_path) {
            Ok(t) => t,
            Err(e) => {
                return self.fail(
                    &header.operation_id,
                    map_raft_err(e),
                    "unmount",
                    &req.parent_zone_id,
                )
            }
        };
        let links = former_target
            .as_deref()
            .and_then(|t| self.zm.get_links_count(t).unwrap_or(None));
        let mut receipt = base_receipt(
            &header.operation_id,
            &req.parent_zone_id,
            "unmount",
            OUTCOME_UNMOUNTED,
        );
        receipt.mount = Some(MountFacts {
            mount_path: req.mount_path.clone(),
            target_zone_id: former_target.clone().unwrap_or_default(),
            i_links_count: links.unwrap_or(0),
        });
        receipt.evidence = vec![format!(
            "mount point '{}' in '{}' restored to DT_DIR (former target: '{}')",
            req.mount_path,
            req.parent_zone_id,
            former_target.as_deref().unwrap_or("<none>")
        )];
        self.complete(&header.operation_id, &req.parent_zone_id, receipt)
    }

    /// Destroy this node's replica only — `ZoneManager::remove_zone`
    /// semantics (peer fan-out of the local-destroy DeleteZone RPC, POSIX
    /// i_links guard unless forced). No global Deleted state; that is
    /// [`Self::zone_deprovision`].
    pub fn zone_remove_replica(
        &self,
        req: &ZoneRemoveReplicaRequest,
    ) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let header = require_header(req.mutation.as_ref())?;
        validate_zone_id_for(ZoneIdUse::ExistingRef, &req.zone_id)
            .map_err(|e| ZoneRuntimeError::Invalid(format!("zone_id: {e}")))?;
        let hash = request_hash(
            b"remove_replica",
            &[&req.zone_id, &format!("force={}", req.force)],
        );

        if let Some(replay) =
            self.begin_or_replay(&header.operation_id, hash, "remove_replica", &req.zone_id)?
        {
            return Ok(replay);
        }

        if let Err(e) = self.zm.remove_zone(&req.zone_id, req.force) {
            return self.fail(
                &header.operation_id,
                map_raft_err(e),
                "remove_replica",
                &req.zone_id,
            );
        }
        let mut receipt = base_receipt(
            &header.operation_id,
            &req.zone_id,
            "remove_replica",
            OUTCOME_REPLICA_REMOVED,
        );
        receipt.evidence = vec![format!(
            "local replica destroyed (hosts_zone={} after removal)",
            self.zm.hosts_zone(&req.zone_id)
        )];
        self.complete(&header.operation_id, &req.zone_id, receipt)
    }

    /// Deprovision — the ONE entry point that writes global Deleted state
    /// (R12): journal idempotency → `mark_deleted` (epoch) → the existing
    /// `remove_zone` peer fan-out + reserved-guarded local teardown →
    /// receipt with the epoch as evidence. Replicas that miss the fan-out
    /// are suppressed at boot by the epoch-vs-creation check.
    pub fn zone_deprovision(
        &self,
        req: &ZoneDeprovisionRequest,
    ) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let header = require_header(req.mutation.as_ref())?;
        validate_zone_id_for(ZoneIdUse::ExistingRef, &req.zone_id)
            .map_err(|e| ZoneRuntimeError::Invalid(format!("zone_id: {e}")))?;
        if contracts::RESERVED_ZONE_IDS.contains(&req.zone_id.as_str()) {
            return Err(ZoneRuntimeError::Conflict(format!(
                "zone '{}' is reserved and cannot be deprovisioned",
                req.zone_id
            )));
        }
        let hash = request_hash(b"deprovision", &[&req.zone_id]);

        if let Some(replay) =
            self.begin_or_replay(&header.operation_id, hash, "deprovision", &req.zone_id)?
        {
            return Ok(replay);
        }

        // Record the deletion FIRST: the epoch must exist in the replicated
        // registry before any replica tears down, so a crash mid-fan-out
        // still leaves the anti-resurrection authority in place.
        let epoch = match self.deletions.mark_deleted(&req.zone_id) {
            Ok(epoch) => epoch,
            Err(e) => {
                return self.fail(
                    &header.operation_id,
                    ZoneRuntimeError::Internal(format!("mark_deleted: {e}")),
                    "deprovision",
                    &req.zone_id,
                )
            }
        };
        // Fast path: tell live peers to destroy their replicas now. A peer
        // that is DOWN is expected, not an error — the epoch is the
        // authority and its stale replica self-cleans at next boot.
        self.zm.fan_out_delete_best_effort(&req.zone_id, false);
        if let Err(e) = self.zm.remove_local_zone(&req.zone_id) {
            return self.fail(
                &header.operation_id,
                map_raft_err(e),
                "deprovision",
                &req.zone_id,
            );
        }
        let mut receipt = base_receipt(
            &header.operation_id,
            &req.zone_id,
            "deprovision",
            OUTCOME_DEPROVISIONED,
        );
        receipt.evidence = vec![
            format!("deletion epoch {epoch} recorded in the replicated registry"),
            format!(
                "local replica destroyed, live peers fanned out (hosts_zone={} after removal)",
                self.zm.hosts_zone(&req.zone_id)
            ),
        ];
        self.complete(&header.operation_id, &req.zone_id, receipt)
    }

    /// Journal lookup for a lost response (R8).
    pub fn get_zone_operation(
        &self,
        req: &GetZoneOperationRequest,
    ) -> Result<ZoneOperationRecord, ZoneRuntimeError> {
        let rec = self
            .journal
            .get(&req.operation_id)
            .map_err(ZoneRuntimeError::Internal)?
            .ok_or_else(|| {
                ZoneRuntimeError::NotFound(format!(
                    "no journal record for operation_id '{}'",
                    req.operation_id
                ))
            })?;
        Ok(record_from_journal(rec))
    }

    // ── internals ─────────────────────────────────────────────────────

    /// Journal `begin`, mapping the outcome: `Ok(None)` = we are the
    /// executor; `Ok(Some(receipt))` = replay answer for the caller.
    fn begin_or_replay(
        &self,
        operation_id: &str,
        hash: u64,
        kind: &str,
        zone_id: &str,
    ) -> Result<Option<ZoneReceipt>, ZoneRuntimeError> {
        match self.journal.begin(operation_id, hash, kind, zone_id) {
            Ok(BeginOutcome::Begin) => Ok(None),
            Ok(BeginOutcome::AlreadyInProgress(rec)) => match rec.status.as_str() {
                crate::zone_op_journal::STATUS_COMPLETED => {
                    let mut receipt = decode_receipt(&rec);
                    receipt.replayed = true;
                    Ok(Some(receipt))
                }
                crate::zone_op_journal::STATUS_REJECTED => {
                    Err(ZoneRuntimeError::Conflict(format!(
                        "operation_id '{}' was previously REJECTED: {}",
                        operation_id,
                        rec.error.as_deref().unwrap_or("<no reason recorded>")
                    )))
                }
                _ => Err(ZoneRuntimeError::Conflict(format!(
                    "operation_id '{}' is still PENDING — poll GetZoneOperation or retry \
                     with a fresh operation_id",
                    operation_id
                ))),
            },
            Err(e) => Err(ZoneRuntimeError::Conflict(e)),
        }
    }

    /// Persist a COMPLETED record and hand back the receipt.
    fn complete(
        &self,
        operation_id: &str,
        zone_id: &str,
        receipt: ZoneReceipt,
    ) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let mut bytes = Vec::new();
        receipt
            .encode(&mut bytes)
            .map_err(|e| ZoneRuntimeError::Internal(format!("receipt encode: {e}")))?;
        self.journal.complete(operation_id, &bytes).map_err(|e| {
            ZoneRuntimeError::Internal(format!("journal complete for '{zone_id}': {e}"))
        })?;
        Ok(receipt)
    }

    /// Persist a REJECTED record and surface the refusal.
    fn fail(
        &self,
        operation_id: &str,
        err: ZoneRuntimeError,
        kind: &str,
        zone_id: &str,
    ) -> Result<ZoneReceipt, ZoneRuntimeError> {
        let _ = self.journal.reject(operation_id, &err.to_string());
        tracing::error!(zone = %zone_id, kind = %kind, "zone runtime mutation refused: {err}");
        Err(err)
    }

    /// Raft facts after waiting for the zone's apply loop to catch up with
    /// its own log (the same guarantee the coordinator demands before
    /// reading a resumed zone).
    fn cluster_facts_caught_up(&self, zone_id: &str) -> ClusterFacts {
        if let Some(handle) = self.zm.get_zone(zone_id) {
            let node = handle.consensus_node();
            wait_until_caught_up(&node, zone_id, CATCHUP_BUDGET);
        }
        let status = self.zm.cluster_status(zone_id);
        ClusterFacts {
            has_store: status.has_store,
            term: status.term,
            commit_index: status.commit_index,
            applied_index: status.applied_index,
            leader_id: status.leader_id,
            voter_count: status.voter_count as u32,
            witness_count: status.witness_count as u32,
        }
    }
}

/// The mutation header is required on every mutation request; this is the
/// one shape check done backend-side (authz lives in the transport layer).
fn require_header(
    header: Option<&kernel::kernel::vfs_proto::ZoneMutationHeader>,
) -> Result<&kernel::kernel::vfs_proto::ZoneMutationHeader, ZoneRuntimeError> {
    let header =
        header.ok_or_else(|| ZoneRuntimeError::Invalid("missing ZoneMutationHeader".into()))?;
    if header.operation_id.is_empty() {
        return Err(ZoneRuntimeError::Invalid(
            "operation_id must not be empty".into(),
        ));
    }
    Ok(header)
}

fn base_receipt(operation_id: &str, zone_id: &str, kind: &str, outcome: &str) -> ZoneReceipt {
    ZoneReceipt {
        operation_id: operation_id.to_string(),
        zone_id: zone_id.to_string(),
        kind: kind.to_string(),
        outcome: outcome.to_string(),
        cluster: None,
        mount: None,
        evidence: Vec::new(),
        completed_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
        replayed: false,
    }
}

fn decode_receipt(rec: &JournalRecord) -> ZoneReceipt {
    rec.receipt
        .as_deref()
        .and_then(|bytes| ZoneReceipt::decode(bytes).ok())
        .unwrap_or_else(|| base_receipt(&rec.operation_id, &rec.zone_id, &rec.kind, ""))
}

fn record_from_journal(rec: JournalRecord) -> ZoneOperationRecord {
    let receipt = if rec.status == crate::zone_op_journal::STATUS_COMPLETED {
        Some(decode_receipt(&rec))
    } else {
        None
    };
    ZoneOperationRecord {
        operation_id: rec.operation_id,
        kind: rec.kind,
        zone_id: rec.zone_id,
        request_hash: rec.request_hash,
        status: rec.status,
        receipt,
        error: rec.error.unwrap_or_default(),
    }
}

fn map_raft_err(e: RaftError) -> ZoneRuntimeError {
    match e {
        RaftError::ZoneAlreadyExistsWithDifferentMembership { actual, requested } => {
            ZoneRuntimeError::Conflict(format!(
                "zone already exists with different membership: have {actual:?}, requested {requested:?}"
            ))
        }
        RaftError::InvalidState(m) => ZoneRuntimeError::Conflict(m),
        other => ZoneRuntimeError::Internal(format!("{other:?}")),
    }
}

/// Canonical request hash (blake3, low 64 bits) over the business fields
/// of a mutation — everything EXCEPT `auth_token` and the header itself.
/// Recomputed server-side; a replayed operation id whose hash disagrees
/// with the journal is refused.
fn request_hash(kind: &[u8], fields: &[&str]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind);
    for f in fields {
        hasher.update(&f.len().to_le_bytes());
        hasher.update(f.as_bytes());
    }
    u64::from_le_bytes(
        hasher.finalize().as_bytes()[..8]
            .try_into()
            .expect("8 bytes"),
    )
}

fn join_sorted(peers: &[String]) -> String {
    let mut sorted = peers.to_vec();
    sorted.sort();
    sorted.join("\u{1}")
}
