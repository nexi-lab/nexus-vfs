//! Ownership survives a zone's native replication and restart, including when
//! its home and linked session are exposed through separate subtree mounts.
//! This does not test user authorization, cold blob retention, runtime handoff,
//! or the daemon's automatic discovery.
#![cfg(all(feature = "grpc", has_protos))]

mod common;

use kernel::meta_store::{ConditionalMetadataResult, FileMetadata, MetaStore};
use nexus_raft::distributed_coordinator::bootstrap_or_join_zone;
use nexus_raft::transport::proto::{
    zone_transport_service_client::ZoneTransportServiceClient, GetClusterInfoRequest,
    StepMessageRequest,
};
use nexus_raft::transport::NodeAddress;
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneManager;
use std::sync::Arc;
use std::time::Duration;

const AGENT_ZONE: &str = "agent-alice-data";
const OTHER_ZONE: &str = "agent-bob-data";
const HOME: &str = "/agents/alice";
const SESSION: &str = "/sessions/sid-a";
const LINK: &str = "/agents/alice/sessions/sid-a";
const STREAM: &str = "__wal_stream__/sessions/sid-a/transcript.jsonl/";
const ROOT_PRIVATE: &str = "/__managed_content_v1__/private-root";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_traffic_cannot_admit_an_unknown_zone_on_a_local_root_runtime() {
    use protobuf::Message as _;

    let directory = tempfile::tempdir().unwrap();
    let address = common::node_bind_addr();
    let manager = node(31, directory.path(), &address).unwrap();
    found(&manager, "root", 31, &address).await;
    let root_id = manager.cluster_status("root").node_id;
    let mut client = peer_client(&address).await;
    let mut heartbeat = raft::eraftpb::Message {
        from: 32,
        to: 31,
        term: 1,
        ..Default::default()
    };
    heartbeat.set_msg_type(raft::eraftpb::MessageType::MsgHeartbeat);
    let result = client
        .step_message(StepMessageRequest {
            zone_id: "unadmitted-zone".into(),
            sender_address: "http://127.0.0.1:2126".into(),
            message: heartbeat.write_to_bytes().unwrap(),
        })
        .await
        .unwrap_err();
    assert_eq!(result.code(), tonic::Code::NotFound);
    assert!(!manager.hosts_zone("unadmitted-zone"));
    assert!(!directory.path().join("unadmitted-zone").exists());
    assert_eq!(
        manager.get_zone("root").unwrap().consensus_node().voters(),
        vec![root_id]
    );
    manager.shutdown();
}

fn node(id: u64, dir: &std::path::Path, addr: &str) -> nexus_raft::raft::Result<Arc<ZoneManager>> {
    node_with_peers(id, dir, addr, Vec::new())
}

async fn peer_client(address: &str) -> ZoneTransportServiceClient<tonic::transport::Channel> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(client) =
                ZoneTransportServiceClient::connect(format!("http://{address}")).await
            {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("local data-zone listener starts")
}

fn node_with_peers(
    id: u64,
    dir: &std::path::Path,
    addr: &str,
    peers: Vec<String>,
) -> nexus_raft::raft::Result<Arc<ZoneManager>> {
    ZoneManager::with_local_root(
        "agent-data-zone-probe",
        id,
        dir.to_str().unwrap(),
        peers,
        addr,
        None,
        Some(format!("http://{addr}")),
        None,
    )
}

async fn found(manager: &Arc<ZoneManager>, zone: &str, id: u64, addr: &str) {
    manager
        .create_zone_async(
            zone,
            if zone == "root" {
                vec![]
            } else {
                vec![format!("{id}@{addr}")]
            },
        )
        .await
        .unwrap()
        .consensus_node()
        .campaign()
        .await
        .unwrap();
}

fn store(manager: &ZoneManager, zone: &str, prefix: &str) -> ZoneMetaStore {
    let handle = manager.get_zone(zone).expect("resident zone");
    ZoneMetaStore::new_with_subtree(
        handle.consensus_node(),
        handle.runtime_handle(),
        prefix.into(),
        prefix.into(),
    )
}

fn metadata(path: &str, kind: u8, zone: &str, owner: &str) -> FileMetadata {
    FileMetadata {
        path: path.into(),
        zone_id: Some(zone.into()),
        owner_id: Some(owner.into()),
        entry_type: kind,
        ..Default::default()
    }
}

fn check_agent_state(manager: &ZoneManager, root_id: u64) {
    assert_eq!(
        manager
            .get_zone(AGENT_ZONE)
            .unwrap()
            .consensus_node()
            .voters(),
        vec![31]
    );
    let home = store(manager, AGENT_ZONE, HOME);
    let sessions = store(manager, AGENT_ZONE, SESSION);
    let link = home.get(LINK).unwrap().unwrap();
    assert_eq!(
        home.get(HOME).unwrap().unwrap().owner_id.as_deref(),
        Some("user-alice")
    );
    assert_eq!(link.path, LINK);
    assert_eq!(link.owner_id.as_deref(), Some("user-alice"));
    assert_eq!(link.entry_type, 6);
    assert_eq!(link.link_target.as_deref(), Some(SESSION));
    assert!(home
        .list(HOME)
        .unwrap()
        .iter()
        .all(|m| m.path.starts_with(HOME)));
    let session = sessions.get(SESSION).unwrap().unwrap();
    assert_eq!(session.path, SESSION);
    assert_eq!(session.owner_id.as_deref(), Some("user-alice"));
    assert_eq!(sessions.stream_tail(STREAM).unwrap(), 3);
    assert_eq!(sessions.stream_floor(STREAM).unwrap(), 2);
    assert_eq!(
        sessions.get_stream_entry(&format!("{STREAM}2")).unwrap(),
        Some(b"third-frame".to_vec()),
    );
    let segments = sessions.list_stream_segments(STREAM).unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].base, 0);
    assert_eq!(segments[0].end, 2);
    assert_eq!(segments[0].content_id, "synthetic-cold-blob");
    assert_eq!(manager.list_zones().len(), 2);
    assert!(!manager.hosts_zone(OTHER_ZONE));
    let root = store(manager, "root", "/");
    assert_eq!(
        manager.get_zone("root").unwrap().consensus_node().voters(),
        vec![root_id]
    );
    assert_eq!(
        root.as_conditional_metadata()
            .unwrap()
            .read_versioned(ROOT_PRIVATE)
            .unwrap()
            .unwrap()
            .metadata
            .owner_id
            .as_deref(),
        Some("user-target")
    );
    let mounts = root.list("/").unwrap();
    for path in [HOME, SESSION] {
        let mount = mounts.iter().find(|m| m.path == path).unwrap();
        assert_eq!(mount.target_zone_id.as_deref(), Some(AGENT_ZONE));
        assert_eq!(mount.target_subtree.as_deref(), Some(path));
    }
    assert!(!mounts.iter().any(|m| m.path.contains("bob")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_zone_join_preserves_disjoint_paths_owner_link_and_wal_tables() {
    let source_dir = tempfile::tempdir().unwrap();
    let target_dir = tempfile::tempdir().unwrap();
    let source_addr = common::node_bind_addr();
    let target_addr = common::node_bind_addr();
    let source = node(31, source_dir.path(), &source_addr).unwrap();
    let target = node(32, target_dir.path(), &target_addr).unwrap();
    for zone in ["root", AGENT_ZONE, OTHER_ZONE] {
        found(&source, zone, 31, &source_addr).await;
    }
    found(&target, "root", 32, &target_addr).await;
    let target_root_id = target.cluster_status("root").node_id;
    for (manager, owner) in [(&source, "user-source"), (&target, "user-target")] {
        let root = store(manager, "root", "/");
        assert!(matches!(
            root.as_conditional_metadata()
                .unwrap()
                .replace_if_version(ROOT_PRIVATE, metadata(ROOT_PRIVATE, 0, "root", owner), None,)
                .unwrap(),
            ConditionalMetadataResult::Committed { .. }
        ));
        assert!(manager.join_zone("root", vec![], true).is_err());
    }
    assert!(store(&source, AGENT_ZONE, HOME)
        .as_conditional_metadata()
        .is_none());

    {
        let home = store(&source, AGENT_ZONE, HOME);
        let sessions = store(&source, AGENT_ZONE, SESSION);
        home.put(HOME, metadata(HOME, 1, AGENT_ZONE, "user-alice"))
            .unwrap();
        let mut link = metadata(LINK, 6, AGENT_ZONE, "user-alice");
        link.link_target = Some(SESSION.into());
        home.put(LINK, link).unwrap();
        sessions
            .put(SESSION, metadata(SESSION, 1, AGENT_ZONE, "user-alice"))
            .unwrap();
        for frame in [b"first-frame".as_slice(), b"second-frame", b"third-frame"] {
            sessions.append_stream_entry(STREAM, frame).unwrap();
        }
        // This models only the persisted cold-segment index, never a retained blob.
        sessions
            .seal_stream_segment(STREAM, 0, 2, "synthetic-cold-blob", &source_addr, 23)
            .unwrap();
        let other = store(&source, OTHER_ZONE, "/agents/bob");
        other
            .put(
                "/agents/bob",
                metadata("/agents/bob", 1, OTHER_ZONE, "user-bob"),
            )
            .unwrap();
    }
    for path in [HOME, SESSION] {
        source
            .mount_subtree_async("root", path, AGENT_ZONE, path, true)
            .await
            .unwrap();
    }
    source
        .mount_subtree_async("root", "/agents/bob", OTHER_ZONE, "/agents/bob", true)
        .await
        .unwrap();

    let joining = Arc::clone(&target);
    let target_endpoint = target_addr.clone();
    tokio::task::spawn_blocking(move || {
        bootstrap_or_join_zone(
            &joining,
            AGENT_ZONE,
            32,
            &target_endpoint,
            &[NodeAddress::parse(&format!("31@{source_addr}"), false).unwrap()],
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

    // Local reads on the learner must remain complete when the sole voter stops.
    // This deliberately makes no claim about writes while that voter is offline.
    tokio::task::spawn_blocking(move || source.shutdown())
        .await
        .unwrap();
    check_agent_state(&target, target_root_id);
    tokio::task::spawn_blocking(move || target.shutdown())
        .await
        .unwrap();

    // shutdown signals the transport tasks; their storage handles are released
    // asynchronously. Only retry that specific lock condition, with a bound.
    let restart_addr = common::node_bind_addr();
    let restarted = restart_node(32, target_dir.path(), &restart_addr, Vec::new()).await;
    check_agent_state(&restarted, target_root_id);
    tokio::task::spawn_blocking(move || restarted.shutdown())
        .await
        .unwrap();
}

async fn restart_node(
    id: u64,
    directory: &std::path::Path,
    address: &str,
    peers: Vec<String>,
) -> Arc<ZoneManager> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match node_with_peers(id, directory, address, peers.clone()) {
                Ok(manager) => break manager,
                Err(nexus_raft::raft::RaftError::DataDirLocked(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("restart local-root runtime: {error}"),
            }
        }
    })
    .await
    .expect("local-root runtime released its data directory")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replica_adoption_preserves_local_root_identity_and_writes_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let initial = ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
    let local_id = initial.node_id();
    let replica_id = if local_id == 41 { 42 } else { 41 };
    found(&initial, "root", local_id, "127.0.0.1:0").await;
    let identity_path = directory.path().join(".node_id");
    let identity_bytes = std::fs::read(&identity_path).unwrap();
    let root = store(&initial, "root", "/");
    assert!(matches!(
        root.as_conditional_metadata()
            .unwrap()
            .replace_if_version(
                ROOT_PRIVATE,
                metadata(ROOT_PRIVATE, 0, "root", "user-alice"),
                None,
            )
            .unwrap(),
        ConditionalMetadataResult::Committed { .. }
    ));
    let original_commit = initial.cluster_status("root").commit_index;
    drop(root);
    tokio::task::spawn_blocking(move || initial.shutdown())
        .await
        .unwrap();

    for round in 0..2 {
        let address = common::node_bind_addr();
        let manager = restart_node(
            replica_id,
            directory.path(),
            &address,
            vec![format!("{replica_id}@{address}")],
        )
        .await;
        let root_node = manager.get_zone("root").unwrap().consensus_node();
        root_node.campaign().await.unwrap();
        let root_status = manager.cluster_status("root");
        assert_eq!(manager.node_id(), replica_id);
        assert_eq!(root_status.node_id, local_id);
        assert_eq!(root_node.voters(), vec![local_id]);
        assert!(root_status.commit_index >= original_commit);
        assert!(manager.zone_peers("root").is_empty());
        assert_eq!(std::fs::read(&identity_path).unwrap(), identity_bytes);
        let root = store(&manager, "root", "/");
        assert_eq!(
            root.as_conditional_metadata()
                .unwrap()
                .read_versioned(ROOT_PRIVATE)
                .unwrap()
                .unwrap()
                .metadata
                .owner_id
                .as_deref(),
            Some("user-alice")
        );
        let path = format!("{ROOT_PRIVATE}-{round}");
        assert!(matches!(
            root.as_conditional_metadata()
                .unwrap()
                .replace_if_version(&path, metadata(&path, 0, "root", "user-alice"), None,)
                .unwrap(),
            ConditionalMetadataResult::Committed { .. }
        ));
        if round == 0 {
            found(&manager, AGENT_ZONE, replica_id, &address).await;
        }
        let data = manager.get_zone(AGENT_ZONE).unwrap().consensus_node();
        assert_eq!(data.id(), replica_id);
        assert_eq!(data.voters(), vec![replica_id]);
        assert_eq!(manager.cluster_status(AGENT_ZONE).node_id, replica_id);
        let mut client = peer_client(&address).await;
        for (zone, expected) in [("root", local_id), (AGENT_ZONE, replica_id)] {
            let info = client
                .get_cluster_info(GetClusterInfoRequest {
                    zone_id: zone.into(),
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(info.node_id, expected);
            assert_eq!(info.config.unwrap().voters[0].id, expected);
        }
        drop(client);
        drop(data);
        drop(root);
        drop(root_node);
        tokio::task::spawn_blocking(move || manager.shutdown())
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_replica_removal_preserves_the_existing_route_map() {
    let directory = tempfile::tempdir().unwrap();
    let address = common::node_bind_addr();
    let manager = node(41, directory.path(), &address).unwrap();
    found(&manager, AGENT_ZONE, 41, &address).await;
    let registry = manager.registry();
    let endpoint = "http://127.0.0.1:2526";
    assert!(registry.learn_peer_address(AGENT_ZONE, 42, endpoint));
    let blocker = directory.path().join(AGENT_ZONE).join(".removed");
    std::fs::create_dir(&blocker).unwrap();
    let removal = registry.remove_zone(AGENT_ZONE).await;
    std::fs::remove_dir(&blocker).unwrap();
    assert!(removal.is_err());
    assert_eq!(
        registry.get_peers(AGENT_ZONE).unwrap()[&42].endpoint,
        endpoint
    );
    assert_eq!(registry.get_node(AGENT_ZONE).unwrap().id(), 41);
    assert!(manager.hosts_zone(AGENT_ZONE));
    tokio::task::spawn_blocking(move || manager.shutdown())
        .await
        .unwrap();
}
