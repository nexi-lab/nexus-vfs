//! Integration coverage for S3 Phase E — DT_MOUNT harvest into
//! `ZoneRaftRegistry::federation_mounts`.
//!
//! Contract to pin: after `bootstrap_static` + `apply_topology`
//! have installed DT_MOUNT entries into the root zone's raft state,
//! `harvest_federation_mounts_from_root` must repopulate the
//! registry snapshot verbatim.  This closes the Phase D restart-
//! mode gap where `DiscoverZones` would otherwise return empty on
//! a restarted founder.

#![cfg(all(feature = "grpc", has_protos))]

use std::collections::BTreeMap;
use std::time::Duration;

use nexus_raft::transport::call_discover_zones_rpc;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

fn mint_random_id() -> u64 {
    let id = rand::random::<u64>();
    if id == 0 {
        1
    } else {
        id
    }
}

fn write_node_id(dir: &std::path::Path, id: u64) {
    std::fs::create_dir_all(dir).expect("create dir");
    std::fs::write(dir.join(NODE_ID_FILE), id.to_be_bytes()).expect("write .node_id");
}

async fn make_node(node_id: u64, dir: &std::path::Path) -> (std::sync::Arc<ZoneManager>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    let bind_str = format!("{}", addr);
    let zm = ZoneManager::with_node_id(
        "test-host",
        node_id,
        dir.to_str().expect("utf-8"),
        vec![],
        &bind_str,
        None,
        Some(format!("http://{bind_str}")),
        None,
    )
    .expect("ZoneManager");
    (zm, bind_str)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn harvest_repopulates_federation_mounts_from_root_dt_mount_entries() {
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (zm, bind) = make_node(id, dir.path()).await;

    // Bootstrap root as a 1-voter SOLO cluster.  Matches what
    // `run_daemon`'s ROOT bootstrap branch does via
    // `bootstrap_or_join_zone("root", ...)`.
    let root_handle = zm
        .create_zone("root", vec![format!("{id}@{bind}")])
        .expect("create root zone");
    for _ in 0..100 {
        if root_handle.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(root_handle.is_leader(), "root must self-elect");

    // Build the federation topology: create sharedzone + corp-eng +
    // queue their mounts in root, then run apply_topology to install
    // the DT_MOUNT entries in root's raft state.
    let mut mounts = BTreeMap::new();
    mounts.insert("/shared".to_string(), "sharedzone".to_string());
    mounts.insert("/corp/eng".to_string(), "corp-eng".to_string());
    zm.bootstrap_static_async(
        vec!["sharedzone".to_string(), "corp-eng".to_string()],
        vec![format!("{id}@{bind}")],
        mounts.clone(),
    )
    .await
    .expect("bootstrap_static_async");

    // Drive apply_topology to convergence.  create_zone gives each
    // zone a 1-voter cluster with self as the only member, so
    // leadership is immediate; apply_topology should converge in one
    // pass but poll a few times to absorb the raft commit latency.
    let mut converged = false;
    for _ in 0..50 {
        if zm
            .apply_topology_async("root")
            .await
            .expect("apply_topology_async")
        {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(converged, "apply_topology did not converge within timeout");

    // Simulate the Phase D limitation: someone else (or a restart-
    // mode boot) blew away the in-memory snapshot.
    zm.registry().set_federation_mounts(BTreeMap::new());
    assert!(
        zm.registry().federation_mounts().is_empty(),
        "post-reset must be empty",
    );

    // Phase E: harvest from root's DT_MOUNT entries repopulates the
    // snapshot.
    let harvested = zm
        .harvest_federation_mounts_from_root_async("root")
        .await
        .expect("harvest_federation_mounts_from_root_async");
    assert_eq!(harvested, 2, "harvest count matches installed mounts");

    let snapshot = zm.registry().federation_mounts();
    assert_eq!(
        snapshot, mounts,
        "harvested snapshot must equal installed mounts"
    );

    // Round-trip via DiscoverZones RPC — proving that Phase D
    // survives a restart-mode boot once the harvest is in place.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let endpoint = format!("http://{bind}");
    let discovered = call_discover_zones_rpc(&endpoint, 5)
        .await
        .expect("DiscoverZones RPC");
    let by_path: BTreeMap<String, String> = discovered
        .into_iter()
        .map(|d| (d.mount_path, d.zone_id))
        .collect();
    assert_eq!(by_path, mounts, "DiscoverZones sees the harvested snapshot");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn harvest_noops_when_root_not_loaded() {
    // Rootless (dynamic-mode) daemon — root zone never gets loaded.
    // Harvest returns 0 with a warn log, does not error.
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (zm, _bind) = make_node(id, dir.path()).await;

    let count = zm
        .harvest_federation_mounts_from_root_async("root")
        .await
        .expect("harvest must not error on missing root");
    assert_eq!(count, 0);
    assert!(zm.registry().federation_mounts().is_empty());
}
