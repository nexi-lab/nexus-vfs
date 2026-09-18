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
//! Epoch semantics: wall-clock-based and strictly increasing —
//! `mark_deleted` takes `max(previous + 1, now_ms)` so an epoch is both
//! monotone per zone and comparable against the local `.creation-epoch`
//! wall-clock the boot check uses. Deliberately NOT provided: any
//! restore/un-delete method — R12 has no recovery requirement, and a
//! recreate is a later explicit work item, not a dead-code path.

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
    /// epoch suppresses it) and keeps the value strictly increasing.
    pub fn mark_deleted(&self, zone_id: &str) -> Result<u64, String> {
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
