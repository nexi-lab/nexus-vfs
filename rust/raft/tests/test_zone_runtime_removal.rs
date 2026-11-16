//! Local replica removal preserves other members and its original receipt.
#![cfg(all(feature = "grpc", has_protos))]

#[path = "common/zone_cluster.rs"]
mod cluster;
mod common;

use std::sync::Arc;
use std::time::Duration;

use kernel::kernel::vfs_proto::{ZoneMutationHeader, ZoneRemoveReplicaRequest};
use nexus_raft::zone_deletion_registry::ZoneDeletionRegistry;
use nexus_raft::zone_op_journal::ZoneOpJournal;
use nexus_raft::zone_runtime::ZoneRuntimeBackend;
use nexus_raft::ZoneManager;

async fn backend(manager: &Arc<ZoneManager>) -> ZoneRuntimeBackend {
    let root = manager.create_zone(contracts::ROOT_ZONE_ID).unwrap();
    let waiting = Arc::clone(&root);
    assert!(tokio::task::spawn_blocking(move || {
        waiting.wait_for_leader(Duration::from_secs(10))
    })
    .await
    .unwrap());
    let node = root.consensus_node();
    let runtime = root.runtime_handle();
    ZoneRuntimeBackend::new(
        Arc::clone(manager),
        ZoneOpJournal::new(node.clone(), runtime.clone()),
        Arc::new(ZoneDeletionRegistry::new(node, runtime, manager.node_id())),
    )
}

fn request(zone: &str, operation: &str, force: bool) -> ZoneRemoveReplicaRequest {
    ZoneRemoveReplicaRequest {
        auth_token: String::new(),
        mutation: Some(ZoneMutationHeader {
            operation_id: operation.into(),
            request_hash: 0,
        }),
        zone_id: zone.into(),
        force,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_replica_keeps_remote_data_and_replays_its_original_receipt() {
    let leader = cluster::Node::new();
    let learner = cluster::Node::new();
    let source = cluster::found(&leader, Vec::new()).await;
    let target = learner.start(vec![leader.bind.clone()]).await;
    let backend = Arc::new(backend(&target).await);
    cluster::join_as_learner(&target, &learner, &leader, &learner.bind).await;
    cluster::write(&source, "/before-removal").await;
    cluster::eventually("replicated durable data", || async {
        cluster::has_key(&target, "/before-removal").await
    })
    .await;
    let members = cluster::consensus(&source).membership().await.unwrap();
    let removal = request(cluster::ZONE, "local-removal", false);
    let executing = Arc::clone(&backend);
    let original_request = removal.clone();
    let receipt =
        tokio::task::spawn_blocking(move || executing.zone_remove_replica(&original_request))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(receipt.outcome, "REPLICA_REMOVED");
    assert!(!receipt.replayed);
    assert!(!target.hosts_zone(cluster::ZONE));
    assert!(
        source.hosts_zone(cluster::ZONE),
        "local replica removal deleted the remote member"
    );
    assert!(cluster::has_key(&source, "/before-removal").await);
    cluster::write(&source, "/after-removal").await;
    assert!(cluster::has_key(&source, "/after-removal").await);
    let after = cluster::consensus(&source).membership().await.unwrap();
    assert_eq!(after.voters, members.voters);
    assert_eq!(after.learners, members.learners);

    // Reopening the same local zone is a new action. Replaying an old removal
    // returns its recorded result and leaves this new incarnation intact.
    cluster::join_as_learner(&target, &learner, &leader, &learner.bind).await;
    cluster::eventually("rejoined durable data", || async {
        cluster::has_key(&target, "/after-removal").await
    })
    .await;
    let executing = Arc::clone(&backend);
    let replay = tokio::task::spawn_blocking(move || executing.zone_remove_replica(&removal))
        .await
        .unwrap()
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, receipt.operation_id);
    assert_eq!(replay.completed_at_ms, receipt.completed_at_ms);
    assert!(target.hosts_zone(cluster::ZONE));
    assert!(cluster::has_key(&target, "/after-removal").await);
    drop(backend);
    cluster::stop(target).await;
    cluster::stop(source).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_replica_removal_preserves_reserved_and_reference_guards() {
    let node = cluster::Node::new();
    let manager = cluster::found(&node, Vec::new()).await;
    let backend = Arc::new(backend(&manager).await);
    manager
        .mount_async(contracts::ROOT_ZONE_ID, "/mounted", cluster::ZONE, true)
        .await
        .unwrap();
    let executing = Arc::clone(&backend);
    let refused = tokio::task::spawn_blocking(move || {
        executing.zone_remove_replica(&request(cluster::ZONE, "referenced", false))
    })
    .await
    .unwrap();
    assert!(refused.unwrap_err().to_string().contains("reference(s)"));
    assert!(manager.hosts_zone(cluster::ZONE));
    for zone in contracts::RESERVED_ZONE_IDS {
        let executing = Arc::clone(&backend);
        let zone = zone.to_string();
        let refused = tokio::task::spawn_blocking(move || {
            executing.zone_remove_replica(&request(&zone, &format!("reserved-{zone}"), true))
        })
        .await
        .unwrap();
        assert!(refused.unwrap_err().to_string().contains("reserved"));
    }
    assert!(manager.hosts_zone(contracts::ROOT_ZONE_ID));
    let executing = Arc::clone(&backend);
    let removed = tokio::task::spawn_blocking(move || {
        executing.zone_remove_replica(&request(cluster::ZONE, "forced", true))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(removed.outcome, "REPLICA_REMOVED");
    assert!(!manager.hosts_zone(cluster::ZONE));
    assert!(manager.hosts_zone(contracts::ROOT_ZONE_ID));
    drop(backend);
    cluster::stop(manager).await;
}
