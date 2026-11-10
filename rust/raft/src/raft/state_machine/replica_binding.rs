//! Replica binding transitions share the control tree and the Raft apply
//! transaction, including its last-applied marker.

use super::{control_key, Command, CommandResult, FullStateMachine, Result};
use contracts::{
    constants::CONTROL_NS_REPLICA as NAMESPACE,
    replica_binding::{
        ReplicaAllocation, ReplicaBinding, ReplicaBindingChange, ReplicaBindingOutcome,
        ReplicaBindingRequest, ReplicaBindingState,
    },
};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

impl Command {
    pub(crate) fn requires_replica_sc(&self) -> bool {
        match self {
            Self::ApplyReplicaBinding(_) | Self::ReserveNodeIdentity(_) => true,
            Self::PutControlState { namespace, .. }
            | Self::DeleteControlState { namespace, .. } => namespace == NAMESPACE,
            _ => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct Receipt<T> {
    pub(super) request_hash: [u8; 32],
    pub(super) outcome: T,
}

pub(crate) fn allocation_key(allocation: &ReplicaAllocation) -> String {
    // Length-prefixed serialization keeps owner/allocation boundaries exact.
    let bytes = bincode::serialize(allocation).expect("string serialization");
    format!("allocation:{}", blake3::hash(&bytes).to_hex())
}

fn operation_key(request: &ReplicaBindingRequest) -> String {
    format!("operation:{}", request.operation_id)
}

pub(super) fn request_hash(request: &impl Serialize) -> [u8; 32] {
    *blake3::hash(&bincode::serialize(request).expect("request serialization")).as_bytes()
}

pub(super) fn storage_error(error: impl std::fmt::Display) -> super::super::RaftError {
    super::super::RaftError::Storage(format!("replica binding: {error}"))
}

pub(super) fn node_key(id: u64) -> Vec<u8> {
    control_key(NAMESPACE, &format!("node:{id}"))
}

fn decode_binding(bytes: &[u8], allocation: &ReplicaAllocation) -> Result<ReplicaBinding> {
    let binding: ReplicaBinding = bincode::deserialize(bytes)?;
    binding.validate().map_err(storage_error)?;
    if binding.allocation != *allocation {
        return Err(storage_error("allocation key and binding disagree"));
    }
    Ok(binding)
}

impl FullStateMachine {
    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn replica_binding_by_id(&self, id: u64) -> Result<Option<ReplicaBinding>> {
        let Some(pointer) = self.control_state.get(&node_key(id))? else {
            return Ok(None);
        };
        if pointer == super::node_identity::identity_key(id) {
            self.node_identity(id)?;
            return Ok(None);
        }
        if !pointer.starts_with(&control_key(NAMESPACE, "allocation:")) {
            return Err(storage_error("invalid replica allocation reference"));
        }
        let bytes = self
            .control_state
            .get(&pointer)?
            .ok_or_else(|| storage_error("missing reserved replica allocation"))?;
        let binding: ReplicaBinding = bincode::deserialize(&bytes)?;
        binding.validate().map_err(storage_error)?;
        if pointer != control_key(NAMESPACE, &allocation_key(&binding.allocation)) {
            return Err(storage_error("replica reservation and allocation disagree"));
        }
        Ok((binding.replica_id == id).then_some(binding))
    }

    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn replica_binding(
        &self,
        allocation: &ReplicaAllocation,
    ) -> Result<Option<ReplicaBinding>> {
        self.get_control_state(NAMESPACE, &allocation_key(allocation))?
            .map(|bytes| decode_binding(&bytes, allocation))
            .transpose()
    }

    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn replica_binding_receipt(
        &self,
        request: &ReplicaBindingRequest,
    ) -> Result<Option<ReplicaBindingOutcome>> {
        self.get_control_state(NAMESPACE, &operation_key(request))?
            .map(|bytes| {
                let receipt: Receipt<ReplicaBindingOutcome> = bincode::deserialize(&bytes)?;
                Ok(if receipt.request_hash == request_hash(request) {
                    receipt.outcome
                } else {
                    ReplicaBindingOutcome::OperationMismatch
                })
            })
            .transpose()
    }

    pub(super) fn apply_replica_binding(
        &self,
        txn: &redb::WriteTransaction,
        request: &ReplicaBindingRequest,
    ) -> Result<CommandResult> {
        if let Err(error) = request.validate() {
            return Ok(CommandResult::Error(error));
        }
        self.require_storage_format_in_txn(
            txn,
            super::storage_admission::StorageFormat::ReplicaBinding,
        )?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let receipt_key = control_key(NAMESPACE, &operation_key(request));
        let digest = request_hash(request);
        if let Some(bytes) = table.get(receipt_key.as_slice()).map_err(storage_error)? {
            let receipt: Receipt<ReplicaBindingOutcome> = bincode::deserialize(bytes.value())?;
            let outcome = if receipt.request_hash == digest {
                receipt.outcome
            } else {
                ReplicaBindingOutcome::OperationMismatch
            };
            return Ok(CommandResult::Value(bincode::serialize(&outcome)?));
        }
        let key = control_key(NAMESPACE, &allocation_key(&request.allocation));
        let current = table
            .get(key.as_slice())
            .map_err(storage_error)?
            .map(|bytes| decode_binding(bytes.value(), &request.allocation))
            .transpose()?;
        let candidate = transition(request, current.as_ref());
        let outcome = match candidate {
            Some(binding) => {
                let reserve = matches!(
                    request.change,
                    ReplicaBindingChange::Register { .. } | ReplicaBindingChange::Replace { .. }
                );
                let id_key = node_key(binding.replica_id);
                let occupied = reserve
                    && table
                        .get(id_key.as_slice())
                        .map_err(storage_error)?
                        .is_some();
                if occupied {
                    ReplicaBindingOutcome::ReplicaIdReserved
                } else {
                    if reserve {
                        // Reservation survives retirement and replacement. An
                        // old leaf can never acquire another allocation here.
                        table
                            .insert(id_key.as_slice(), key.as_slice())
                            .map_err(storage_error)?;
                    }
                    let encoded = bincode::serialize(&binding)?;
                    table
                        .insert(key.as_slice(), encoded.as_slice())
                        .map_err(storage_error)?;
                    ReplicaBindingOutcome::Applied(binding)
                }
            }
            None => ReplicaBindingOutcome::Conflict(current),
        };
        let encoded = bincode::serialize(&Receipt {
            request_hash: digest,
            outcome: outcome.clone(),
        })?;
        table
            .insert(receipt_key.as_slice(), encoded.as_slice())
            .map_err(storage_error)?;
        Ok(CommandResult::Value(bincode::serialize(&outcome)?))
    }
}

fn transition(
    request: &ReplicaBindingRequest,
    current: Option<&ReplicaBinding>,
) -> Option<ReplicaBinding> {
    match (&request.change, current) {
        (
            ReplicaBindingChange::Register {
                storage,
                replica_id,
            },
            None,
        ) => Some(ReplicaBinding {
            allocation: request.allocation.clone(),
            storage: storage.clone(),
            replica_id: *replica_id,
            revision: 1,
            generation: 1,
            state: ReplicaBindingState::Active,
        }),
        (ReplicaBindingChange::Retire { expected_revision }, Some(old))
            if *expected_revision == old.revision && old.state == ReplicaBindingState::Active =>
        {
            Some(ReplicaBinding {
                revision: old.revision.checked_add(1)?,
                state: ReplicaBindingState::Retired,
                ..old.clone()
            })
        }
        (
            ReplicaBindingChange::Replace {
                expected_revision,
                storage,
                replica_id,
            },
            Some(old),
        ) if *expected_revision == old.revision
            && old.state == ReplicaBindingState::Retired
            && *replica_id != old.replica_id =>
        {
            Some(ReplicaBinding {
                allocation: old.allocation.clone(),
                storage: storage.clone(),
                replica_id: *replica_id,
                revision: old.revision.checked_add(1)?,
                generation: old.generation.checked_add(1)?,
                state: ReplicaBindingState::Active,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{raft::StateMachine, storage::RedbStore};

    fn register(operation: &str, allocation: &str, id: u64) -> ReplicaBindingRequest {
        ReplicaBindingRequest {
            operation_id: operation.into(),
            allocation: ReplicaAllocation {
                owner_id: "owner-a".into(),
                allocation_id: allocation.into(),
            },
            change: ReplicaBindingChange::Register {
                storage: contracts::replica_binding::ReplicaStorage {
                    authority: "cluster-a".into(),
                    uid: "pvc-uid-1".into(),
                },
                replica_id: id,
            },
        }
    }

    fn apply(
        sm: &mut FullStateMachine,
        index: u64,
        request: &ReplicaBindingRequest,
    ) -> ReplicaBindingOutcome {
        let CommandResult::Value(bytes) = sm
            .apply(
                index,
                &Command::ApplyReplicaBinding(Box::new(request.clone())),
            )
            .unwrap()
        else {
            panic!("typed receipt")
        };
        bincode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn aborted_binding_apply_publishes_neither_format_nor_authority() {
        let db = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&db).unwrap();
        let original = register("register-original", "primary", 31);
        {
            let txn = sm.control_state.raw_db().begin_write().unwrap();
            sm.apply_replica_binding(&txn, &original).unwrap();
            txn.abort().unwrap();
        }
        assert!(sm.list_control_state(NAMESPACE).unwrap().is_empty());
        assert!(sm
            .list_control_state(super::super::conditional_metadata::NAMESPACE)
            .unwrap()
            .is_empty());
        assert_eq!(sm.last_applied_index(), 0);
        assert!(matches!(
            apply(&mut sm, 1, &original),
            ReplicaBindingOutcome::Applied(_)
        ));
        assert_eq!(
            sm.get_control_state("content-version-v1", "requires:protected-records-v1")
                .unwrap()
                .as_deref(),
            Some(b"replica-binding-v1".as_slice())
        );
        assert_eq!(sm.last_applied_index(), 1);
    }

    #[test]
    fn original_receipt_survives_retirement_replacement_and_snapshot() {
        let db = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&db).unwrap();
        let original = register("register-original", "primary", 31);
        let outcome = apply(&mut sm, 1, &original);
        let ReplicaBindingOutcome::Applied(first) = &outcome else {
            panic!("created")
        };
        assert_eq!((first.revision, first.generation), (1, 1));
        assert_eq!(apply(&mut sm, 2, &original), outcome);
        let mut changed = original.clone();
        changed.change = ReplicaBindingChange::Register {
            storage: first.storage.clone(),
            replica_id: 32,
        };
        assert_eq!(
            apply(&mut sm, 3, &changed),
            ReplicaBindingOutcome::OperationMismatch
        );

        let mut retire = original.clone();
        retire.operation_id = "retire-original".into();
        retire.change = ReplicaBindingChange::Retire {
            expected_revision: 1,
        };
        let ReplicaBindingOutcome::Applied(retired) = apply(&mut sm, 4, &retire) else {
            panic!("retired")
        };
        assert_eq!(retired.state, ReplicaBindingState::Retired);
        let mut replacement = original.clone();
        replacement.operation_id = "replace-original".into();
        replacement.change = ReplicaBindingChange::Replace {
            expected_revision: 2,
            storage: contracts::replica_binding::ReplicaStorage {
                authority: "cluster-a".into(),
                uid: "pvc-uid-2".into(),
            },
            replica_id: 32,
        };
        let ReplicaBindingOutcome::Applied(second) = apply(&mut sm, 5, &replacement) else {
            panic!("replaced")
        };
        assert_eq!((second.revision, second.generation), (3, 2));
        assert_eq!(apply(&mut sm, 6, &original), outcome);
        assert_eq!(
            sm.replica_binding(&original.allocation).unwrap(),
            Some(second.clone())
        );
        assert_eq!(sm.replica_binding_by_id(31).unwrap(), None);
        assert_eq!(sm.replica_binding_by_id(32).unwrap(), Some(second.clone()));
        assert!(matches!(
            apply(&mut sm, 7, &register("reuse-retired-id", "other", 31)),
            ReplicaBindingOutcome::ReplicaIdReserved
        ));
        assert!(sm
            .replica_binding(&register("other", "other", 31).allocation)
            .unwrap()
            .is_none());

        let snapshot = sm.snapshot().unwrap();
        let restored_db = RedbStore::open_temporary().unwrap();
        let mut restored = FullStateMachine::new(&restored_db).unwrap();
        restored.restore_snapshot(&snapshot).unwrap();
        assert_eq!(
            restored.replica_binding_receipt(&original).unwrap(),
            Some(outcome)
        );
        assert_eq!(
            restored.replica_binding(&original.allocation).unwrap(),
            Some(second)
        );
        assert_eq!(
            apply(&mut restored, 8, &register("reuse-again", "other", 31)),
            ReplicaBindingOutcome::ReplicaIdReserved
        );
        assert!(restored.list_metadata("").unwrap().is_empty());
    }

    #[test]
    fn mismatched_generation_and_generic_writes_preserve_the_binding() {
        let db = RedbStore::open_temporary().unwrap();
        let mut sm = FullStateMachine::new(&db).unwrap();
        let request = register("create", "primary", 41);
        let initial = apply(&mut sm, 1, &request);
        let mut wrong = request.clone();
        wrong.operation_id = "bad-replace".into();
        wrong.change = ReplicaBindingChange::Replace {
            expected_revision: 1,
            storage: contracts::replica_binding::ReplicaStorage {
                authority: "cluster-a".into(),
                uid: "same-name-new-uid".into(),
            },
            replica_id: 42,
        };
        assert!(matches!(
            apply(&mut sm, 2, &wrong),
            ReplicaBindingOutcome::Conflict(Some(_))
        ));
        wrong.operation_id = "stale-retire".into();
        wrong.change = ReplicaBindingChange::Retire {
            expected_revision: 2,
        };
        assert!(matches!(
            apply(&mut sm, 3, &wrong),
            ReplicaBindingOutcome::Conflict(Some(_))
        ));
        for (index, command) in [
            Command::PutControlState {
                namespace: NAMESPACE.into(),
                key: allocation_key(&request.allocation),
                value: vec![0],
                if_absent: false,
            },
            Command::DeleteControlState {
                namespace: NAMESPACE.into(),
                key: allocation_key(&request.allocation),
            },
        ]
        .iter()
        .enumerate()
        {
            assert!(sm.requires_strong_consistency(command).unwrap());
            assert!(sm.apply_local(command).is_err());
            assert!(matches!(
                sm.apply(4 + index as u64, command).unwrap(),
                CommandResult::Error(_)
            ));
        }
        assert!(sm
            .apply_local(&Command::ApplyReplicaBinding(Box::new(request.clone())))
            .is_err());
        let ReplicaBindingOutcome::Applied(original) = initial else {
            panic!("created")
        };
        assert_eq!(
            sm.replica_binding(&request.allocation).unwrap(),
            Some(original)
        );
    }

    #[test]
    fn input_bounds_and_allocation_keys_preserve_identity_boundaries() {
        let a = register("op", "primary", 1);
        a.validate().unwrap();
        for allocation in ["", "../x", "Primary", "a/b", "-primary"] {
            let mut bad = a.clone();
            bad.allocation.allocation_id = allocation.into();
            assert!(bad.validate().is_err());
        }
        let mut other = a.clone();
        other.allocation.owner_id = "owner-b".into();
        assert_ne!(
            allocation_key(&a.allocation),
            allocation_key(&other.allocation)
        );
        other.allocation = a.allocation.clone();
        other.allocation.owner_id.push('\0');
        assert!(other.validate().is_err());
        other = a.clone();
        other.change = ReplicaBindingChange::Retire {
            expected_revision: 0,
        };
        assert!(other.validate().is_err());
    }
}
