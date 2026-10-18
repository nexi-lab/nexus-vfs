//! Replicated zone-deletion registry (R12) — deletion epochs on the
//! control store, the authority "zone X is deleted cluster-wide, at
//! epoch E".
//!
//! The tombstone-on-disk is a LOCAL fact (this replica tore the zone
//! down); the epoch HERE is the replicated fact (the zone was
//! deprovisioned). A replica that missed the peer fan-out holds a dir
//! with no tombstone, so local state alone cannot stop it from
//! resurrecting the zone at boot — it must ask this registry. The
//! registry's answer travels via [`DeletionEpochSource`], the seam the
//! `ZoneRaftRegistry` consults without depending on the control store's
//! implementation (high cohesion: the registry knows epochs, not stores).
//!
//! Epoch semantics: wall-clock-based and monotone per zone under the
//! single-writer conditions deprovision actually runs under —
//! `mark_deleted` takes `max(previous + 1, now_ms)`. Preconditions worth
//! stating plainly:
//!
//! * The read-judge-write is NOT a cross-node CAS: two concurrent
//!   `mark_deleted` calls for one zone (different nodes, different
//!   operation ids) can interleave such that the later-applied write
//!   carries the SMALLER epoch under clock skew — the value can regress.
//!   Deprovision is an admin-rate operation and the journal already
//!   dedups per `operation_id`, so the exposure is accepted rather than
//!   paying for a state-machine-side epoch command.
//! * Both sides of the comparison are wall-clocks read on DIFFERENT
//!   nodes: the deletion epoch on the initiating node, the replica's
//!   `.creation-epoch` where it was created. A replica whose clock runs
//!   ahead of the initiator by more than the zone's created→deprovisioned
//!   interval satisfies `creation_epoch >= deletion_epoch` forever, and
//!   the resurrection check never fires for it — fail-open, the same
//!   degradation direction as a store-unreachable `None`. Operations
//!   premise: node clocks stay synchronized to well under a zone's
//!   minimum lifetime.
//!
//! Deliberately NOT provided: any
//! restore/un-delete method — R12 has no recovery requirement. The escape
//! hatch (`NEXUS_FORCE_DELETED_ZONE_RECREATE`, set by `nexusd-cluster
//! --force`) covers recovery WITHOUT one: the guard that re-founds the zone
//! also bumps the local `.creation-epoch`, so the fresh epoch outranks the
//! recorded deletion epoch and normal boots resume the zone — the epoch
//! ordering IS the recovery semantics, no un-delete API needed.

use contracts::CONTROL_NS_ZONE_REGISTRY;

use crate::control_state_store::ControlStateStore;
use crate::raft::{FullStateMachine, ZoneConsensus};

/// What `ZoneRaftRegistry` needs from the deletion world: "is this zone
/// deleted, and at what epoch?" Implemented by [`ZoneDeletionRegistry`];
/// injected at boot (`set_deletion_epoch_source`, the `set_identity_dir`
/// pattern). `None` = no deletion recorded (or the store is not wired —
/// auth-off single node), which degrades to the pre-existing
/// tombstone + 60s-window behavior.
pub trait DeletionEpochSource: Send + Sync {
    fn deletion_epoch(&self, zone_id: &str) -> Option<u64>;
}

/// One deletion-record payload under `zone-registry/deleted/{zone_id}`.
#[derive(serde::Serialize, serde::Deserialize)]
struct DeletedRecord {
    deletion_epoch: u64,
    deleted_at_ms: u64,
    initiated_by_node: u64,
}

/// What status callers ask about a deleted zone: the epoch (the
/// anti-resurrection authority) and when the deletion was recorded.
pub struct DeletedZoneInfo {
    pub deletion_epoch: u64,
    pub deleted_at_ms: u64,
}

pub struct ZoneDeletionRegistry {
    store: ControlStateStore,
    node_id: u64,
}

impl ZoneDeletionRegistry {
    /// Bind to the control zone's consensus (or local root under
    /// `--no-tls` — same availability contract as the operation journal).
    pub fn new(
        node: ZoneConsensus<FullStateMachine>,
        runtime: tokio::runtime::Handle,
        node_id: u64,
    ) -> Self {
        Self {
            store: ControlStateStore::new(node, runtime, CONTROL_NS_ZONE_REGISTRY),
            node_id,
        }
    }

    /// Record (or re-record) `zone_id` as deleted, returning the new
    /// epoch. Idempotent in effect — repeated calls keep bumping the
    /// epoch, which is harmless (any epoch > a stale replica's creation
    /// epoch suppresses it). Monotone under the single-writer conditions
    /// of the module doc: this is a read-judge-write over the locally
    /// applied state, so the `previous` read barriers first (a follower
    /// proposing this must not compute its bump from a stale local view),
    /// and concurrent writers + clock skew remain the documented residual.
    pub fn mark_deleted(&self, zone_id: &str) -> Result<u64, String> {
        self.store
            .read_barrier()
            .map_err(|e| format!("mark_deleted({zone_id}) read barrier: {e}"))?;
        let previous = self.deletion_epoch(zone_id)?;
        let now = now_ms();
        let epoch = previous.map_or(now, |prev| (prev + 1).max(now));
        let record = DeletedRecord {
            deletion_epoch: epoch,
            deleted_at_ms: now,
            initiated_by_node: self.node_id,
        };
        let bytes =
            serde_json::to_vec(&record).map_err(|e| format!("deletion record encode: {e}"))?;
        self.store
            .put(&Self::key(zone_id), &bytes)
            .map_err(|e| format!("mark_deleted({zone_id}): {e}"))?;
        Ok(epoch)
    }

    /// The recorded deletion (epoch + timestamp), if the zone was
    /// deprovisioned. Store-unreachable degrades to `None` like
    /// [`Self::deletion_epoch`].
    pub fn deletion_info(&self, zone_id: &str) -> Result<Option<DeletedZoneInfo>, String> {
        match self.store.get(&Self::key(zone_id)) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let record: DeletedRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("deletion record decode for '{zone_id}': {e}"))?;
                Ok(Some(DeletedZoneInfo {
                    deletion_epoch: record.deletion_epoch,
                    deleted_at_ms: record.deleted_at_ms,
                }))
            }
            Err(e) => {
                tracing::warn!(zone = %zone_id, error = %e, "deletion registry read failed");
                Ok(None)
            }
        }
    }

    /// The recorded deletion info, with store errors PROPAGATED (no
    /// best-effort degradation). For the RPC-facing paths (typed zone
    /// runtime): by the time an RPC is answered the control zone is resident
    /// and serving, so a store error is a real fault the caller must see,
    /// not a "no record" answer — the fail-closed intent the best-effort
    /// variants below cannot express.
    pub fn deletion_info_checked(&self, zone_id: &str) -> Result<Option<DeletedZoneInfo>, String> {
        match self.store.get(&Self::key(zone_id)) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let record: DeletedRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("deletion record decode for '{zone_id}': {e}"))?;
                Ok(Some(DeletedZoneInfo {
                    deletion_epoch: record.deletion_epoch,
                    deleted_at_ms: record.deleted_at_ms,
                }))
            }
            Err(e) => Err(format!("deletion registry read for '{zone_id}': {e}")),
        }
    }

    /// The recorded deletion epoch, if the zone was deprovisioned.
    pub fn deletion_epoch(&self, zone_id: &str) -> Result<Option<u64>, String> {
        match self.store.get(&Self::key(zone_id)) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let record: DeletedRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("deletion record decode for '{zone_id}': {e}"))?;
                Ok(Some(record.deletion_epoch))
            }
            Err(e) => {
                // Store unreachable (control zone not resident yet, auth-off
                // node without one): degrade to "unknown", never to "not
                // deleted" — callers treat None as the pre-R12 behavior.
                tracing::warn!(zone = %zone_id, error = %e, "deletion registry read failed");
                Ok(None)
            }
        }
    }

    /// The recorded deletion epoch, with store errors PROPAGATED. The
    /// RPC-facing counterpart of [`Self::deletion_epoch`] — see
    /// [`Self::deletion_info_checked`] for why the typed zone runtime must
    /// not silently degrade a live store fault to "not deleted".
    pub fn deletion_epoch_checked(&self, zone_id: &str) -> Result<Option<u64>, String> {
        match self.store.get(&Self::key(zone_id)) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let record: DeletedRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("deletion record decode for '{zone_id}': {e}"))?;
                Ok(Some(record.deletion_epoch))
            }
            Err(e) => Err(format!("deletion registry read for '{zone_id}': {e}")),
        }
    }

    fn key(zone_id: &str) -> String {
        format!("deleted/{zone_id}")
    }
}

impl DeletionEpochSource for ZoneDeletionRegistry {
    fn deletion_epoch(&self, zone_id: &str) -> Option<u64> {
        // The trait is the registry's best-effort query face: a store error
        // is "unknown", which the boot check handles as no-record (the
        // tombstone/60s-window paths still apply).
        ZoneDeletionRegistry::deletion_epoch(self, zone_id)
            .ok()
            .flatten()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
