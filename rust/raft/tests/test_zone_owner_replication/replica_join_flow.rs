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
    ZoneManager::with_local_root_shared(
        "restricted-replica-join",
        id,
        path.to_str().unwrap(),
        Vec::new(),
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
