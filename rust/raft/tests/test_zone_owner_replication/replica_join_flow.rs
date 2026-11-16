//! Actual replica transport carries only the zone admitted by the controller.

use super::*;
use lib::transport_primitives::{create_peer_channel, ClientConfig, SharedTlsConfig, TlsConfig};
use nexus_raft::transport::proto::JoinZoneRequest;
use nexus_raft::transport::{generate_node_cert, generate_user_replica_cert, generate_zone_ca};

fn start(
    id: u64,
    path: &std::path::Path,
    address: &str,
    identity: &TlsConfig,
) -> nexus_raft::raft::Result<Arc<ZoneManager>> {
    start_with_peers(id, path, address, identity, Vec::new())
}

fn start_with_peers(
    id: u64,
    path: &std::path::Path,
    address: &str,
    identity: &TlsConfig,
    peers: Vec<String>,
) -> nexus_raft::raft::Result<Arc<ZoneManager>> {
    ZoneManager::with_local_root_shared(
        "restricted-replica-join",
        id,
        path.to_str().unwrap(),
        peers,
        address,
        SharedTlsConfig::new(Some(identity.clone())),
        Some(format!("https://{address}")),
        None,
    )
}

async fn api(
    address: &str,
    identity: &TlsConfig,
) -> ZoneApiServiceClient<tonic::transport::Channel> {
    let channel = create_peer_channel(
        &format!("https://{address}"),
        &ClientConfig {
            tls: Some(identity.clone()),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        31.try_into().unwrap(),
    )
    .await
    .unwrap();
    ZoneApiServiceClient::new(channel)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_runtime_joins_mounts_and_removes_only_its_admitted_replica() {
    use kernel::kernel::vfs_proto::{
        GetZoneOperationRequest, ZoneJoinRequest as RuntimeJoin, ZoneMountRequest,
        ZoneMutationHeader, ZoneRemoveReplicaRequest, ZoneUnmountRequest,
    };
    use nexus_raft::zone_runtime::ZoneRuntimeBackend;

    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source_address = common::node_bind_addr();
    let target_address = common::node_bind_addr();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(31, "root", &ca, &ca_key, &[], None).unwrap();
    let controller_identity = TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    };
    let (cert_pem, key_pem) =
        generate_user_replica_cert("runtime", "alice", 32, 300, &ca, &ca_key).unwrap();
    let target_identity = TlsConfig {
        ca_pem: ca,
        cert_pem,
        key_pem,
    };
    let source = start(31, source_dir.path(), &source_address, &controller_identity).unwrap();
    let target = start_with_peers(
        32,
        target_dir.path(),
        &target_address,
        &target_identity,
        vec![format!("31@{source_address}")],
    )
    .unwrap();
    for zone in [contracts::ROOT_ZONE_ID, AGENT_ZONE, OTHER_ZONE] {
        found(&source, zone).await;
    }
    found(&target, contracts::ROOT_ZONE_ID).await;
    seed_selected_zone(&source, &source_address).await;
    let original_links = source.get_links_count(AGENT_ZONE).unwrap().unwrap();
    assert_eq!(original_links, 2);
    let original_root = target.cluster_status(contracts::ROOT_ZONE_ID).node_id;
    let mut controller = api(&source_address, &controller_identity).await;
    assert!(
        controller
            .join_zone(JoinZoneRequest {
                zone_id: AGENT_ZONE.into(),
                node_id: 32,
                node_address: target_address.clone(),
                as_learner: true,
            })
            .await
            .unwrap()
            .into_inner()
            .success
    );
    let backend = Arc::new(ZoneRuntimeBackend::for_local_root(Arc::clone(&target)).unwrap());
    let header = |id: &str| {
        Some(ZoneMutationHeader {
            operation_id: id.into(),
            request_hash: 0,
        })
    };
    let join = RuntimeJoin {
        mutation: header("local-join"),
        zone_id: AGENT_ZONE.into(),
        learner: true,
        ..Default::default()
    };
    let worker = Arc::clone(&backend);
    let original_join = join.clone();
    let joined = tokio::task::spawn_blocking(move || worker.zone_join(&original_join))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(joined.outcome, "JOINED");
    assert!(target.hosts_zone(AGENT_ZONE));
    assert!(!target.hosts_zone(OTHER_ZONE));
    assert!(!target.hosts_zone(contracts::CONTROL_ZONE_ID));
    let worker = Arc::clone(&backend);
    let mount = ZoneMountRequest {
        mutation: header("local-mount"),
        parent_zone_id: contracts::ROOT_ZONE_ID.into(),
        mount_path: "/shared".into(),
        target_zone_id: AGENT_ZONE.into(),
        ..Default::default()
    };
    let mounted = tokio::task::spawn_blocking(move || worker.zone_mount(&mount))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mounted.outcome, "MOUNTED");
    assert_eq!(mounted.mount.unwrap().i_links_count, original_links + 1);
    assert!(store(&source, contracts::ROOT_ZONE_ID, "/")
        .get("/shared")
        .unwrap()
        .is_none());
    assert!(store(&target, contracts::ROOT_ZONE_ID, "/")
        .get("/shared")
        .unwrap()
        .is_some());
    let worker = Arc::clone(&backend);
    let unmount = ZoneUnmountRequest {
        mutation: header("local-unmount"),
        parent_zone_id: contracts::ROOT_ZONE_ID.into(),
        mount_path: "/shared".into(),
        ..Default::default()
    };
    let unmounted = tokio::task::spawn_blocking(move || worker.zone_unmount(&unmount))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unmounted.outcome, "UNMOUNTED");
    assert_eq!(unmounted.mount.unwrap().i_links_count, original_links);
    let worker = Arc::clone(&backend);
    let referenced = ZoneRemoveReplicaRequest {
        mutation: header("referenced-local-remove"),
        zone_id: AGENT_ZONE.into(),
        force: false,
        ..Default::default()
    };
    let refused = tokio::task::spawn_blocking(move || worker.zone_remove_replica(&referenced))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        refused,
        nexus_raft::zone_runtime::ZoneRuntimeError::Conflict(_)
    ));
    assert!(refused.to_string().contains("reference(s)"));
    assert!(target.hosts_zone(AGENT_ZONE));
    let worker = Arc::clone(&backend);
    let remove = ZoneRemoveReplicaRequest {
        mutation: header("local-remove"),
        zone_id: AGENT_ZONE.into(),
        force: true,
        ..Default::default()
    };
    let removed = tokio::task::spawn_blocking(move || worker.zone_remove_replica(&remove))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(removed.outcome, "REPLICA_REMOVED");
    assert!(!target.hosts_zone(AGENT_ZONE));
    assert!(source.hosts_zone(AGENT_ZONE));
    assert!(store(&source, AGENT_ZONE, "/").get(HOME).unwrap().is_some());
    assert_eq!(
        target.cluster_status(contracts::ROOT_ZONE_ID).node_id,
        original_root
    );
    // The recorded JOINED result is historical. Reading or replaying it must
    // not materialize the locally removed replica or admit another zone.
    let worker = Arc::clone(&backend);
    let old = tokio::task::spawn_blocking(move || worker.zone_join(&join))
        .await
        .unwrap()
        .unwrap();
    assert!(old.replayed);
    assert_eq!(old.completed_at_ms, joined.completed_at_ms);
    let record = backend
        .get_zone_operation(&GetZoneOperationRequest {
            operation_id: "local-join".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(record.status, "COMPLETED");
    assert_eq!(
        target.list_zones(),
        vec![contracts::ROOT_ZONE_ID.to_owned()]
    );
    drop(backend);
    drop(controller);
    tokio::task::spawn_blocking(move || {
        target.shutdown();
        source.shutdown();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_replica_recovers_only_its_zone_with_local_root_and_wal_intact() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let outsider_dir = tempfile::tempdir().unwrap();
    let source_address = common::node_bind_addr();
    let target_address = common::node_bind_addr();
    let outsider_address = common::node_bind_addr();
    let (ca, ca_key) = generate_zone_ca("root").unwrap();
    let (cert_pem, key_pem) = generate_node_cert(31, "root", &ca, &ca_key, &[], None).unwrap();
    let control_identity = TlsConfig {
        ca_pem: ca.clone(),
        cert_pem,
        key_pem,
    };
    let replica_identity = |owner, id| {
        let (cert_pem, key_pem) =
            generate_user_replica_cert("runtime", owner, id, 300, &ca, &ca_key).unwrap();
        TlsConfig {
            ca_pem: ca.clone(),
            cert_pem,
            key_pem,
        }
    };
    let target_identity = replica_identity("alice", 32);
    let outsider_identity = replica_identity("charlie", 33);
    let source = start(31, source_dir.path(), &source_address, &control_identity).unwrap();
    let target = start(32, target_dir.path(), &target_address, &target_identity).unwrap();
    let outsider = start(
        33,
        outsider_dir.path(),
        &outsider_address,
        &outsider_identity,
    )
    .unwrap();
    for zone in ["root", AGENT_ZONE, OTHER_ZONE] {
        found(&source, zone).await;
    }
    found(&target, "root").await;
    found(&outsider, "root").await;
    let target_root_id = target.cluster_status("root").node_id;
    let outsider_root_id = outsider.cluster_status("root").node_id;
    for (manager, owner) in [(&source, "user-source"), (&target, "user-target")] {
        assert!(matches!(
            store(manager, "root", "/")
                .as_conditional_metadata()
                .unwrap()
                .replace_if_version(ROOT_PRIVATE, metadata(ROOT_PRIVATE, 0, "root", owner), None)
                .unwrap(),
            ConditionalMetadataResult::Committed { .. }
        ));
    }
    seed_selected_zone(&source, &source_address).await;
    let request = JoinZoneRequest {
        zone_id: AGENT_ZONE.into(),
        node_id: 32,
        node_address: target_address.clone(),
        as_learner: true,
    };
    let mut replica_api = api(&source_address, &target_identity).await;
    let mut outsider_api = api(&source_address, &outsider_identity).await;
    assert_eq!(
        replica_api
            .join_zone(request.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut controller = api(&source_address, &control_identity).await;
    assert!(
        controller
            .join_zone(request.clone())
            .await
            .unwrap()
            .into_inner()
            .success
    );
    assert!(
        replica_api
            .join_zone(request.clone())
            .await
            .unwrap()
            .into_inner()
            .success
    );

    let joining = Arc::clone(&target);
    let local_address = target_address.clone();
    let source_peer = NodeAddress::parse(&format!("31@{source_address}"), true).unwrap();
    tokio::task::spawn_blocking(move || {
        bootstrap_or_join_zone(
            &joining,
            AGENT_ZONE,
            32,
            &local_address,
            &[source_peer],
            false,
            Some(3),
            true,
        )
        .unwrap();
    })
    .await
    .unwrap();
    for path in [HOME, SESSION] {
        target
            .mount_subtree_async("root", path, AGENT_ZONE, path, false)
            .await
            .unwrap();
    }
    check_agent_state(&target, target_root_id);
    assert_eq!(
        replica_api
            .join_zone(JoinZoneRequest {
                zone_id: OTHER_ZONE.into(),
                ..request.clone()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        outsider_api
            .join_zone(JoinZoneRequest {
                node_id: 33,
                node_address: outsider_address,
                ..request
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(outsider.list_zones().len(), 1);
    assert!(!outsider.hosts_zone(AGENT_ZONE));
    assert!(!outsider.hosts_zone(OTHER_ZONE));
    assert_eq!(
        outsider.get_zone("root").unwrap().consensus_node().voters(),
        vec![outsider_root_id]
    );
    assert!(store(&outsider, "root", "/").get(HOME).unwrap().is_none());
    assert_eq!(
        store(&outsider, "root", "/").stream_tail(STREAM).unwrap(),
        0
    );
    drop(controller);
    drop(replica_api);
    drop(outsider_api);
    tokio::task::spawn_blocking(move || source.shutdown())
        .await
        .unwrap();
    check_agent_state(&target, target_root_id);
    tokio::task::spawn_blocking(move || target.shutdown())
        .await
        .unwrap();
    let restarted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match start(32, target_dir.path(), &target_address, &target_identity) {
                Ok(manager) => break manager,
                Err(nexus_raft::raft::RaftError::DataDirLocked(_))
                | Err(nexus_raft::raft::RaftError::ListenerAddressInUse(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("restart authorized replica: {error}"),
            }
        }
    })
    .await
    .expect("original replica releases its store and socket");
    check_agent_state(&restarted, target_root_id);
    tokio::task::spawn_blocking(move || {
        restarted.shutdown();
        outsider.shutdown();
    })
    .await
    .unwrap();
}
