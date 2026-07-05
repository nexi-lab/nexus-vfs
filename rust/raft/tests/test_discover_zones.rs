//! Integration coverage for `ZoneApiService::DiscoverZones` — the
//! S3 Phase D fresh-joiner federation-topology discovery RPC.
//!
//! Contract to pin:
//!
//! 1. A ZoneManager that has been handed a federation mount map via
//!    `set_federation_mounts` returns it verbatim through the RPC.
//!    Ordering is stable (BTreeMap iteration) so callers can
//!    dedupe against multiple responders without ambiguity.
//!
//! 2. A ZoneManager that has NOT called `set_federation_mounts`
//!    returns an empty list — pure-joiner nodes never advertise
//!    ghost topology to third parties.
//!
//! 3. Concurrent readers see a consistent snapshot: a call while
//!    `set_federation_mounts` is being rewritten either sees the
//!    old or the new snapshot, never a torn view.  (Pinned by
//!    exercising both orderings under `tokio::join!`.)

#![cfg(all(feature = "grpc", has_protos))]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use nexus_raft::transport::{call_discover_zones_rpc, DiscoveredZone};
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

async fn make_node(node_id: u64, dir: &std::path::Path) -> (Arc<ZoneManager>, String) {
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
async fn discover_zones_returns_configured_federation_mounts() {
    // Founder-style node: set the federation mount table on the
    // registry.  DiscoverZones must round-trip the (mount_path,
    // zone_id) pairs verbatim.
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (zm, bind) = make_node(id, dir.path()).await;

    let mut mounts = BTreeMap::new();
    mounts.insert("/shared".to_string(), "sharedzone".to_string());
    mounts.insert("/corp/eng".to_string(), "corp-eng".to_string());
    zm.registry().set_federation_mounts(mounts.clone());

    // Give the gRPC server a beat to fully accept connections.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let endpoint = format!("http://{bind}");
    let discovered = call_discover_zones_rpc(&endpoint, 5)
        .await
        .expect("DiscoverZones RPC");

    // Sanity: same number of entries, same content.  BTreeMap
    // ordering means the wire order is deterministic — assert on
    // set equality since the client re-boxes into a Vec.
    assert_eq!(discovered.len(), 2);
    let by_path: BTreeMap<String, String> = discovered
        .into_iter()
        .map(|d| (d.mount_path, d.zone_id))
        .collect();
    assert_eq!(by_path, mounts);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discover_zones_returns_empty_on_pure_joiner() {
    // Node that never called `set_federation_mounts` — the RPC
    // responds successfully with an empty list.  This is the
    // operator-correct answer: a pure joiner does not advertise
    // ghost topology to third-party discoverers.
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (_zm, bind) = make_node(id, dir.path()).await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let endpoint = format!("http://{bind}");
    let discovered: Vec<DiscoveredZone> = call_discover_zones_rpc(&endpoint, 5).await.expect("RPC");
    assert!(
        discovered.is_empty(),
        "pure joiner must not advertise; got {discovered:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discover_zones_reflects_latest_snapshot_under_concurrent_rewrite() {
    // set_federation_mounts overwrites atomically; a reader either
    // sees the old or the new snapshot, never a torn view.
    let dir = TempDir::new().expect("dir");
    let id = mint_random_id();
    write_node_id(dir.path(), id);
    let (zm, bind) = make_node(id, dir.path()).await;

    // Seed A.
    let mut a = BTreeMap::new();
    a.insert("/a".to_string(), "zone-a".to_string());
    zm.registry().set_federation_mounts(a.clone());

    tokio::time::sleep(Duration::from_millis(100)).await;
    let endpoint = format!("http://{bind}");

    // Rewriter task swaps between A and B repeatedly.
    let zm_writer = zm.clone();
    let a_writer = a.clone();
    let writer_handle = tokio::spawn(async move {
        let mut b = BTreeMap::new();
        b.insert("/b".to_string(), "zone-b".to_string());
        for i in 0..50 {
            zm_writer.registry().set_federation_mounts(if i % 2 == 0 {
                a_writer.clone()
            } else {
                b.clone()
            });
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    // Reader task fires DiscoverZones repeatedly; every result must
    // be exactly one of the two seeds.
    let ep = endpoint.clone();
    let a_seed = a.clone();
    let reader_handle = tokio::spawn(async move {
        for _ in 0..25 {
            let got = call_discover_zones_rpc(&ep, 5).await.expect("RPC");
            let got_map: BTreeMap<String, String> =
                got.into_iter().map(|d| (d.mount_path, d.zone_id)).collect();
            let is_a = got_map == a_seed;
            let is_b =
                got_map.len() == 1 && got_map.get("/b").map(String::as_str) == Some("zone-b");
            assert!(
                is_a || is_b,
                "torn snapshot detected under concurrent rewrite: {got_map:?}",
            );
        }
    });

    let _ = tokio::join!(writer_handle, reader_handle);
}
