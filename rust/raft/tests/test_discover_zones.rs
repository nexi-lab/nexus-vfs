//! Integration coverage for `ZoneApiService::DiscoverZones` —
//! S3 Phase D fresh-joiner federation-topology discovery + Phase F
//! SSOT tightening.
//!
//! Contract to pin (after Phase F):
//!
//! 1. A node with a root zone that carries DT_MOUNT entries returns
//!    the corresponding `(mount_path, target_zone_id)` pairs — the
//!    handler reads root's state machine at RPC time (no cache).
//!
//! 2. A node with no root zone loaded (pure joiner, dynamic-mode
//!    daemon) returns an empty list.
//!
//! 3. DT_MOUNTs added at runtime (`share --mount-at`, `join`, etc.)
//!    become visible on the next DiscoverZones call — pinned by
//!    installing an initial mount, calling the RPC, adding a second
//!    mount, calling again, and asserting the second call sees the
//!    new entry.  This is the property that motivated Phase F: a
//!    cache/harvest design would need explicit invalidation plumbing
//!    for this case.

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

async fn drive_apply_topology_to_convergence(zm: &std::sync::Arc<ZoneManager>, root_zone_id: &str) {
    for _ in 0..50 {
        if zm
            .apply_topology_async(root_zone_id)
            .await
            .expect("apply_topology_async")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("apply_topology did not converge within timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discover_zones_returns_dt_mount_entries_from_root_state_machine() {
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (zm, bind) = make_node(id, dir.path()).await;

    // Bootstrap root as 1-voter SOLO.
    let root_handle = zm
        .create_zone("root", vec![format!("{id}@{bind}")])
        .expect("create root");
    for _ in 0..100 {
        if root_handle.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(root_handle.is_leader());

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
    drive_apply_topology_to_convergence(&zm, "root").await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    let endpoint = format!("http://{bind}");
    let discovered = call_discover_zones_rpc(&endpoint, None, 5)
        .await
        .expect("DiscoverZones RPC");

    let by_path: BTreeMap<String, String> = discovered
        .into_iter()
        .map(|d| (d.mount_path, d.zone_id))
        .collect();
    assert_eq!(by_path, mounts, "DiscoverZones reads DT_MOUNT verbatim");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discover_zones_returns_empty_on_pure_joiner() {
    // Pure joiner: no root zone loaded.  DiscoverZones returns
    // successfully with an empty list — the operator-correct
    // "I have nothing to advertise" answer.
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (_zm, bind) = make_node(id, dir.path()).await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let endpoint = format!("http://{bind}");
    let discovered = call_discover_zones_rpc(&endpoint, None, 5)
        .await
        .expect("RPC");
    assert!(
        discovered.is_empty(),
        "pure joiner must not advertise; got {discovered:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discover_zones_picks_up_dt_mount_entries_added_at_runtime() {
    // Phase F contract: runtime-added mounts (via `mount()` or a
    // `share --mount-at`) are visible on the very next DiscoverZones
    // call — no cache-invalidation plumbing required.
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (zm, bind) = make_node(id, dir.path()).await;

    let root_handle = zm
        .create_zone("root", vec![format!("{id}@{bind}")])
        .expect("create root");
    for _ in 0..100 {
        if root_handle.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(root_handle.is_leader());

    // Install a first federation zone + mount via bootstrap_static.
    let mut initial = BTreeMap::new();
    initial.insert("/shared".to_string(), "sharedzone".to_string());
    zm.bootstrap_static_async(
        vec!["sharedzone".to_string()],
        vec![format!("{id}@{bind}")],
        initial.clone(),
    )
    .await
    .expect("bootstrap_static_async");
    drive_apply_topology_to_convergence(&zm, "root").await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    let endpoint = format!("http://{bind}");
    let first_call = call_discover_zones_rpc(&endpoint, None, 5)
        .await
        .expect("RPC call 1");
    let first_map: BTreeMap<String, String> = first_call
        .into_iter()
        .map(|d| (d.mount_path, d.zone_id))
        .collect();
    assert_eq!(first_map, initial);

    // Add a SECOND federation zone + mount at runtime (simulates
    // `nexusd-cluster share --mount-at`).  Create the zone, then
    // mount it under root — the same code path `share_subtree_core`
    // triggers.
    let extra_handle = zm
        .create_zone("corp-eng", vec![format!("{id}@{bind}")])
        .expect("create corp-eng");
    for _ in 0..100 {
        if extra_handle.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    zm.mount_async("root", "/corp/eng", "corp-eng", true)
        .await
        .expect("mount_async");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let second_call = call_discover_zones_rpc(&endpoint, None, 5)
        .await
        .expect("RPC call 2");
    let second_map: BTreeMap<String, String> = second_call
        .into_iter()
        .map(|d| (d.mount_path, d.zone_id))
        .collect();
    let mut expected = initial;
    expected.insert("/corp/eng".to_string(), "corp-eng".to_string());
    assert_eq!(
        second_map, expected,
        "runtime-added DT_MOUNT must be visible without any cache-invalidation call"
    );
}
