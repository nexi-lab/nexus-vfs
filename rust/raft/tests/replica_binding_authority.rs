//! Real control-zone proposals/read barriers for competing replica allocation
//! claims and original-operation recovery. Credentials and Pod readiness are
//! exercised by the issuer composition, separately from this store boundary.
#![cfg(all(feature = "grpc", has_protos))]

use contracts::replica_binding::{
    ReplicaAllocation, ReplicaBindingChange, ReplicaBindingOutcome, ReplicaBindingRequest,
    ReplicaBindingState, ReplicaStorage,
};
use nexus_raft::{
    raft::{Command, ZoneRaftRegistry},
    replica_binding_store::{RaftReplicaBindingStore, ReplicaBindingError},
    ZoneManager,
};
use std::sync::{Arc, Barrier};

fn request(operation: &str, id: u64) -> ReplicaBindingRequest {
    ReplicaBindingRequest {
        operation_id: operation.into(),
        allocation: ReplicaAllocation {
            owner_id: "owner-real".into(),
            allocation_id: "primary".into(),
        },
        change: ReplicaBindingChange::Register {
            storage: ReplicaStorage {
                authority: "cluster-real".into(),
                uid: "observed-pvc-uid".into(),
            },
            replica_id: id,
        },
    }
}

#[test]
fn concurrent_claims_and_original_reconciliation_use_one_control_authority() {
    let dir = tempfile::tempdir().unwrap();
    let manager = ZoneManager::isolated(dir.path().to_str().unwrap()).unwrap();
    let root = manager
        .create_zone(contracts::ROOT_ZONE_ID, vec![])
        .unwrap();
    assert!(root.wait_for_leader(std::time::Duration::from_secs(5)));
    let node = root.consensus_node();
    let runtime = manager.runtime_handle();
    runtime.block_on(node.read_linearizable(|_| ())).unwrap();
    let store = Arc::new(RaftReplicaBindingStore::new(node, runtime));
    let gate = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (1..=2)
        .map(|index| {
            let store = store.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let request = request(&format!("claim-{index}"), 100 + index);
                gate.wait();
                let result = store.apply(&request).unwrap();
                (request, result)
            })
        })
        .collect();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, result)| matches!(result, ReplicaBindingOutcome::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, result)| matches!(result, ReplicaBindingOutcome::Conflict(Some(_))))
            .count(),
        1
    );
    let (original, original_result) = outcomes
        .iter()
        .find(|(_, r)| matches!(r, ReplicaBindingOutcome::Applied(_)))
        .unwrap();
    let current = store.current(&original.allocation).unwrap().unwrap();
    assert_eq!(
        store.reconcile(original).unwrap(),
        Some(original_result.clone())
    );
    assert!(store
        .reconcile(&request("not-observed-yet", 200))
        .unwrap()
        .is_none());

    let retirement = ReplicaBindingRequest {
        operation_id: "retire-winner".into(),
        allocation: current.allocation.clone(),
        change: ReplicaBindingChange::Retire {
            expected_revision: current.revision,
        },
    };
    let ReplicaBindingOutcome::Applied(retired) = store.apply(&retirement).unwrap() else {
        panic!("retirement")
    };
    assert_eq!(retired.state, ReplicaBindingState::Retired);
    assert_eq!(store.apply(original).unwrap(), *original_result);
    assert_eq!(
        store.current(&original.allocation).unwrap(),
        Some(retired.clone())
    );
    // A same-name new PVC cannot silently replace the current binding.
    let mut silent_replace = request("same-allocation-new-pvc", 201);
    if let ReplicaBindingChange::Register { storage, .. } = &mut silent_replace.change {
        storage.uid = "replacement-pvc-uid".into();
    }
    assert_eq!(
        store.apply(&silent_replace).unwrap(),
        ReplicaBindingOutcome::Conflict(Some(retired.clone()))
    );
    let replacement = ReplicaBindingRequest {
        operation_id: "explicit-replacement".into(),
        allocation: retired.allocation.clone(),
        change: ReplicaBindingChange::Replace {
            expected_revision: retired.revision,
            storage: ReplicaStorage {
                authority: "cluster-real".into(),
                uid: "replacement-pvc-uid".into(),
            },
            replica_id: 202,
        },
    };
    let ReplicaBindingOutcome::Applied(replaced) = store.apply(&replacement).unwrap() else {
        panic!("replacement")
    };
    assert_eq!(replaced.generation, 2);
    assert_ne!(replaced.replica_id, current.replica_id);
    assert_eq!(
        store.reconcile(original).unwrap(),
        Some(original_result.clone())
    );
    assert_eq!(store.current(&original.allocation).unwrap(), Some(replaced));
    drop(store);
    manager.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_control_refuses_before_unactivated_command_enters_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Handle::current();
    let registry = ZoneRaftRegistry::new(dir.path().to_path_buf(), 1);
    let node = registry
        .create_zone(contracts::CONTROL_ZONE_ID, vec![], &runtime)
        .unwrap();
    node.campaign().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !node.is_leader() || node.applied_index() < node.last_index() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let before = node.last_index();
    let store = RaftReplicaBindingStore::new(node.clone(), runtime);
    let request = request("managed-refusal", 101);
    assert!(matches!(
        store.apply(&request),
        Err(ReplicaBindingError::Unsupported)
    ));
    assert!(node
        .propose(Command::ApplyReplicaBinding(Box::new(request.clone())))
        .await
        .is_err());
    assert_eq!(node.last_index(), before);
    assert_eq!(store.current(&request.allocation).unwrap(), None);
    drop(store);
    registry.shutdown_all();
}
