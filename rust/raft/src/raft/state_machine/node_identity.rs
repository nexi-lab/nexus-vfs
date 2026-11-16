//! Node enrollment and replica allocation compete on one retained ID index.

use super::{
    control_key,
    replica_binding::{node_key, request_hash, storage_error, Receipt},
    storage_admission::StorageFormat,
    CommandResult, FullStateMachine, Result,
};
#[cfg(any(test, all(feature = "grpc", has_protos)))]
use contracts::node_identity::NodeIdentity;
use contracts::{
    constants::CONTROL_NS_REPLICA as NAMESPACE,
    node_identity::{NodeIdentityOutcome, NodeIdentityRequest},
};
use redb::ReadableTable;

pub(super) fn identity_key(id: u64) -> Vec<u8> {
    control_key(NAMESPACE, &format!("enrollment:{id}"))
}

fn operation_key(request: &NodeIdentityRequest) -> String {
    format!("node-operation:{}", request.operation_id)
}

impl FullStateMachine {
    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn node_identity(&self, id: u64) -> Result<Option<NodeIdentity>> {
        let Some(pointer) = self.control_state.get(&node_key(id))? else {
            return Ok(None);
        };
        if pointer.starts_with(&control_key(NAMESPACE, "allocation:")) {
            self.replica_binding_by_id(id)?;
            return Ok(None);
        }
        if pointer != identity_key(id) {
            return Err(storage_error("invalid Node identity reference"));
        }
        let bytes = self
            .control_state
            .get(&pointer)?
            .ok_or_else(|| storage_error("missing reserved Node identity"))?;
        let identity: NodeIdentity = bincode::deserialize(&bytes)?;
        identity.validate().map_err(storage_error)?;
        if identity.node_id != id {
            return Err(storage_error("Node reservation and identity disagree"));
        }
        Ok(Some(identity))
    }

    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn node_identity_receipt(
        &self,
        request: &NodeIdentityRequest,
    ) -> Result<Option<NodeIdentityOutcome>> {
        self.get_control_state(NAMESPACE, &operation_key(request))?
            .map(|bytes| {
                let receipt: Receipt<NodeIdentityOutcome> = bincode::deserialize(&bytes)?;
                Ok(if receipt.request_hash == request_hash(request) {
                    receipt.outcome
                } else {
                    NodeIdentityOutcome::OperationMismatch
                })
            })
            .transpose()
    }

    pub(super) fn reserve_node_identity(
        &self,
        txn: &redb::WriteTransaction,
        request: &NodeIdentityRequest,
    ) -> Result<CommandResult> {
        if let Err(error) = request.validate() {
            return Ok(CommandResult::Error(error));
        }
        self.require_storage_format_in_txn(txn, StorageFormat::NodeIdentity)?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let receipt_key = control_key(NAMESPACE, &operation_key(request));
        let digest = request_hash(request);
        if let Some(bytes) = table.get(receipt_key.as_slice()).map_err(storage_error)? {
            let receipt: Receipt<NodeIdentityOutcome> = bincode::deserialize(bytes.value())?;
            let outcome = if receipt.request_hash == digest {
                receipt.outcome
            } else {
                NodeIdentityOutcome::OperationMismatch
            };
            return Ok(CommandResult::Value(bincode::serialize(&outcome)?));
        }
        let id_key = node_key(request.identity.node_id);
        let occupied = table
            .get(id_key.as_slice())
            .map_err(storage_error)?
            .is_some();
        let outcome = if occupied {
            NodeIdentityOutcome::IdReserved
        } else {
            let key = identity_key(request.identity.node_id);
            let encoded = bincode::serialize(&request.identity)?;
            table
                .insert(key.as_slice(), encoded.as_slice())
                .map_err(storage_error)?;
            table
                .insert(id_key.as_slice(), key.as_slice())
                .map_err(storage_error)?;
            NodeIdentityOutcome::Reserved(request.identity.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        raft::{Command, MembershipPolicy, StateMachine},
        storage::RedbStore,
    };

    fn request(operation: &str, id: u64) -> NodeIdentityRequest {
        NodeIdentityRequest {
            operation_id: operation.into(),
            identity: NodeIdentity {
                node_id: id,
                subject_public_key_sha256: [9; 32],
            },
        }
    }

    fn apply(
        state: &mut FullStateMachine,
        index: u64,
        request: &NodeIdentityRequest,
    ) -> NodeIdentityOutcome {
        let CommandResult::Value(bytes) = state
            .apply(
                index,
                &Command::ReserveNodeIdentity(Box::new(request.clone())),
            )
            .unwrap()
        else {
            panic!("expected Node reservation receipt");
        };
        bincode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn reservation_receipt_format_and_last_applied_commit_together() {
        let db = RedbStore::open_temporary().unwrap();
        let mut state = FullStateMachine::new(&db).unwrap();
        let original = request("enroll-original", 11);
        let txn = state.control_state.raw_db().begin_write().unwrap();
        state.reserve_node_identity(&txn, &original).unwrap();
        txn.abort().unwrap();
        assert!(state.list_control_state(NAMESPACE).unwrap().is_empty());
        assert!(state
            .list_control_state("content-version-v1")
            .unwrap()
            .is_empty());
        assert_eq!(state.last_applied_index(), 0);

        let outcome = apply(&mut state, 1, &original);
        assert_eq!(
            outcome,
            NodeIdentityOutcome::Reserved(original.identity.clone())
        );
        assert_eq!(
            state.node_identity(11).unwrap(),
            Some(original.identity.clone())
        );
        assert_eq!(
            state.node_identity_receipt(&original).unwrap(),
            Some(outcome.clone())
        );
        assert_eq!(state.replica_binding_by_id(11).unwrap(), None);
        assert_eq!(state.last_applied_index(), 1);
        assert_eq!(
            state
                .get_control_state("content-version-v1", "requires:protected-records-v1")
                .unwrap()
                .as_deref(),
            Some(b"node-identity-v1".as_slice())
        );
        let snapshot = state.snapshot().unwrap();
        state
            .validate_snapshot_membership(&snapshot, MembershipPolicy::FixedLocal)
            .unwrap();
        assert!(state
            .validate_snapshot_membership(&snapshot, MembershipPolicy::Managed)
            .is_err());
        let restored_db = RedbStore::open_temporary().unwrap();
        let mut restored = FullStateMachine::new(&restored_db).unwrap();
        restored.restore_snapshot(&snapshot).unwrap();
        assert_eq!(restored.last_applied_index(), 1);
        assert_eq!(apply(&mut restored, 2, &original), outcome);
        assert_eq!(restored.node_identity(11).unwrap(), Some(original.identity));
        assert_eq!(
            apply(&mut restored, 3, &request("another-request", 11)),
            NodeIdentityOutcome::IdReserved
        );
    }

    #[test]
    fn both_claim_orders_preserve_the_original_identity() {
        use contracts::replica_binding::{
            ReplicaAllocation, ReplicaBindingChange, ReplicaBindingOutcome, ReplicaBindingRequest,
            ReplicaStorage,
        };
        for node_first in [false, true] {
            let db = RedbStore::open_temporary().unwrap();
            let mut state = FullStateMachine::new(&db).unwrap();
            let node = request("node", 12);
            let replica = ReplicaBindingRequest {
                operation_id: "replica".into(),
                allocation: ReplicaAllocation {
                    owner_id: "owner".into(),
                    allocation_id: "primary".into(),
                },
                change: ReplicaBindingChange::Register {
                    storage: ReplicaStorage {
                        authority: "cluster".into(),
                        uid: "pvc".into(),
                    },
                    replica_id: 12,
                },
            };
            if node_first {
                assert!(matches!(
                    apply(&mut state, 1, &node),
                    NodeIdentityOutcome::Reserved(_)
                ));
            }
            let CommandResult::Value(bytes) = state
                .apply(
                    if node_first { 2 } else { 1 },
                    &Command::ApplyReplicaBinding(Box::new(replica.clone())),
                )
                .unwrap()
            else {
                panic!("replica receipt")
            };
            let result: ReplicaBindingOutcome = bincode::deserialize(&bytes).unwrap();
            if node_first {
                assert_eq!(result, ReplicaBindingOutcome::ReplicaIdReserved);
                assert_eq!(state.replica_binding(&replica.allocation).unwrap(), None);
                assert_eq!(state.node_identity(12).unwrap(), Some(node.identity));
            } else {
                assert!(matches!(result, ReplicaBindingOutcome::Applied(_)));
                assert_eq!(apply(&mut state, 2, &node), NodeIdentityOutcome::IdReserved);
                assert_eq!(state.node_identity(12).unwrap(), None);
                assert!(state.replica_binding_by_id(12).unwrap().is_some());
            }
        }
    }

    #[test]
    fn invalid_requests_and_generic_writes_cannot_create_or_change_custody() {
        let db = RedbStore::open_temporary().unwrap();
        let mut state = FullStateMachine::new(&db).unwrap();
        for (index, invalid) in [request("", 13), request("valid-operation", 0)]
            .into_iter()
            .enumerate()
        {
            assert!(matches!(
                state
                    .apply(
                        index as u64 + 1,
                        &Command::ReserveNodeIdentity(Box::new(invalid))
                    )
                    .unwrap(),
                CommandResult::Error(_)
            ));
        }
        assert!(state.list_control_state(NAMESPACE).unwrap().is_empty());
        assert!(state
            .list_control_state("content-version-v1")
            .unwrap()
            .is_empty());
        let original = request("owned", 13);
        let expected = apply(&mut state, 3, &original);
        let mut changed = original.clone();
        changed.identity.subject_public_key_sha256 = [8; 32];
        assert_eq!(
            apply(&mut state, 4, &changed),
            NodeIdentityOutcome::OperationMismatch
        );
        assert_eq!(
            state.node_identity_receipt(&changed).unwrap(),
            Some(NodeIdentityOutcome::OperationMismatch)
        );
        assert_eq!(
            state.node_identity_receipt(&original).unwrap(),
            Some(expected)
        );
        for (index, command) in [
            Command::ReserveNodeIdentity(Box::new(request("local", 14))),
            Command::PutControlState {
                namespace: NAMESPACE.into(),
                key: "node:13".into(),
                value: vec![0],
                if_absent: false,
            },
            Command::DeleteControlState {
                namespace: NAMESPACE.into(),
                key: "enrollment:13".into(),
            },
        ]
        .iter()
        .enumerate()
        {
            assert!(state.requires_strong_consistency(command).unwrap());
            assert!(state.apply_local(command).is_err());
            if !matches!(command, Command::ReserveNodeIdentity(_)) {
                assert!(matches!(
                    state.apply(5 + index as u64, command).unwrap(),
                    CommandResult::Error(_)
                ));
            }
        }
        assert_eq!(state.node_identity(13).unwrap(), Some(original.identity));
        assert_eq!(state.node_identity(14).unwrap(), None);
    }
}
