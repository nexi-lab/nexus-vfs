//! Ownership survives a zone's native replication and restart, including when
//! its home and linked session are exposed through separate subtree mounts.
//! This does not test user authorization, cold blob retention, runtime handoff,
//! or the daemon's automatic discovery.
#![cfg(all(feature = "grpc", has_protos))]

mod common;

use kernel::meta_store::{FileMetadata, MetaStore};
use nexus_raft::distributed_coordinator::bootstrap_or_join_zone;
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

fn node(id: u64, dir: &std::path::Path, addr: &str) -> nexus_raft::raft::Result<Arc<ZoneManager>> {
    ZoneManager::with_node_id(
        "agent-data-zone-probe",
        id,
        dir.to_str().unwrap(),
        vec![],
        addr,
        None,
        Some(format!("http://{addr}")),
        None,
    )
}

async fn found(manager: &Arc<ZoneManager>, zone: &str, id: u64, addr: &str) {
    manager
        .create_zone_async(zone, vec![format!("{id}@{addr}")])
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

fn check_agent_state(manager: &ZoneManager) {
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
    check_agent_state(&target);

    // Local reads on the learner must remain complete when the sole voter stops.
    // This deliberately makes no claim about writes while that voter is offline.
    tokio::task::spawn_blocking(move || source.shutdown())
        .await
        .unwrap();
    check_agent_state(&target);
    tokio::task::spawn_blocking(move || target.shutdown())
        .await
        .unwrap();

    // shutdown signals the transport tasks; their storage handles are released
    // asynchronously. Only retry that specific lock condition, with a bound.
    let restart_addr = common::node_bind_addr();
    let restarted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match node(32, target_dir.path(), &restart_addr) {
                Ok(manager) => break manager,
                Err(nexus_raft::raft::RaftError::DataDirLocked(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("restart target: {error}"),
            }
        }
    })
    .await
    .expect("target released its data directory");
    check_agent_state(&restarted);
    tokio::task::spawn_blocking(move || restarted.shutdown())
        .await
        .unwrap();
}
