//! Credential records replicate, and revocation propagates.
//!
//! The §3.B.3 `AuthKeyStore` design rests on one security claim: because
//! the records live in the raft log, a key minted on one node resolves on
//! every node, and **revoking it on one node stops it resolving on every
//! node** — no restart, no cache-busting side channel, no second store to
//! keep in sync. Nothing about a single-node round-trip tests that claim.
//! This does, over a real two-node cluster.
//!
//! Topology (same shape as `test_ec_drain_1v1l`):
//!   * Founder bootstraps a 1-voter `sharedzone` and self-elects leader.
//!   * Joiner enters as a Learner over a real `JoinZone` gRPC call.
//!
//! The journey — each step consumes the previous step's output:
//!   1. Founder **mints** two keys through `RaftAuthKeyStore::put` (the
//!      same seam the key-minting tool uses; not a raw `Command`).
//!   2. Joiner **resolves** both through its OWN store — byte-exact. This
//!      is the read an auth provider on the joiner performs, on a node
//!      that never saw the write.
//!   3. Founder **revokes** key A.
//!   4. Joiner stops resolving A, still resolves B, and `list()` shows
//!      exactly B. Revocation propagated, and it was targeted rather than
//!      a tree wipe.
//!
//! Both stores are built the way the composition root builds them —
//! `RaftAuthKeyStore::new(zone.consensus_node(), zone.runtime_handle())` —
//! so the test exercises the production construction path, not a stub.

#![cfg(all(feature = "grpc", has_protos))]

use std::time::Duration;

use kernel::hal::auth_key_store::AuthKeyStore;
use nexus_raft::auth_key_store::RaftAuthKeyStore;
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

/// Poll budget for a committed entry to reach the learner's state
/// machine. Generous: on a healthy localhost transport this resolves in
/// well under a second, and a slow CI box should not turn a real
/// replication assertion into a flake.
const REPLICATION_BUDGET: Duration = Duration::from_secs(5);

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

/// Poll `store.get(hash)` until it matches `want`, or the budget expires.
/// Returns what was last observed so a failure can say what it actually
/// saw rather than just "timed out".
async fn await_resolution(
    store: &RaftAuthKeyStore,
    hash: &str,
    want: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + REPLICATION_BUDGET;
    let mut last = None;
    while std::time::Instant::now() < deadline {
        last = store.get(hash).expect("joiner resolve");
        if last.as_deref() == want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_on_the_founder_propagates_to_the_joiner() {
    let dir_founder = TempDir::new().expect("dir-founder");
    let dir_joiner = TempDir::new().expect("dir-joiner");

    let id_founder = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_founder, id_joiner, "two random mints must differ");
    write_node_id(dir_founder.path(), id_founder);
    write_node_id(dir_joiner.path(), id_joiner);

    let (zm_founder, bind_founder) = make_node(id_founder, dir_founder.path()).await;
    let (zm_joiner, bind_joiner) = make_node(id_joiner, dir_joiner.path()).await;

    // ── Cluster: founder self-elects on a 1-voter zone ───────────────
    let zone_founder = zm_founder
        .create_zone("sharedzone", vec![format!("{id_founder}@{bind_founder}")])
        .expect("create sharedzone on founder");
    for _ in 0..100 {
        if zone_founder.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        zone_founder.is_leader(),
        "founder must self-elect on 1-voter create"
    );

    let endpoint_founder = format!("http://{bind_founder}");
    let endpoint_joiner = format!("http://{bind_joiner}");

    let _zone_joiner_local = zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_founder}@{bind_founder}")],
            /* learner */ true,
        )
        .expect("local join_zone(learner) on joiner");

    let join_resp = call_join_zone_rpc(
        &endpoint_founder,
        "sharedzone",
        id_joiner,
        &endpoint_joiner,
        /* as_learner */ true,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(
        join_resp.success,
        "JoinZone(learner) must succeed: {:?}",
        join_resp.error
    );

    for _ in 0..50 {
        if zm_founder.cluster_status("sharedzone").applied_index >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Build both stores exactly as the composition root does.
    let store_founder =
        RaftAuthKeyStore::new(zone_founder.consensus_node(), zone_founder.runtime_handle());
    let zone_joiner = zm_joiner
        .get_zone("sharedzone")
        .expect("joiner must hold a ZoneHandle for sharedzone");
    let store_joiner =
        RaftAuthKeyStore::new(zone_joiner.consensus_node(), zone_joiner.runtime_handle());

    // ── 1. Founder mints two credentials ─────────────────────────────
    // Opaque bytes on purpose — the store never parses a record, so the
    // test does not pretend to know the provider's schema.
    let hash_a = "hmac-of-sk-alpha";
    let hash_b = "hmac-of-sk-bravo";
    let record_a = b"record-for-alpha".to_vec();
    let record_b = b"record-for-bravo".to_vec();
    store_founder.put(hash_a, &record_a).expect("mint alpha");
    store_founder.put(hash_b, &record_b).expect("mint bravo");

    // ── 2. Joiner resolves both, byte-exact ──────────────────────────
    // The node that never saw the write can authenticate the credential.
    assert_eq!(
        await_resolution(&store_joiner, hash_a, Some(&record_a)).await,
        Some(record_a.clone()),
        "joiner must resolve a credential minted on the founder"
    );
    assert_eq!(
        await_resolution(&store_joiner, hash_b, Some(&record_b)).await,
        Some(record_b.clone()),
        "joiner must resolve the second minted credential"
    );

    // ── 3. Founder revokes alpha ─────────────────────────────────────
    assert!(
        store_founder.delete(hash_a).expect("revoke alpha"),
        "revoking a live key reports it removed something"
    );

    // ── 4. The revocation reaches the joiner ─────────────────────────
    // This is the claim the design rests on: no restart, no side channel.
    assert_eq!(
        await_resolution(&store_joiner, hash_a, None).await,
        None,
        "revoked credential must stop resolving on the joiner"
    );
    // Targeted, not a tree wipe.
    assert_eq!(
        store_joiner.get(hash_b).expect("joiner resolve bravo"),
        Some(record_b.clone()),
        "revoking alpha must not disturb bravo"
    );
    let listed = store_joiner.list().expect("joiner list");
    assert_eq!(
        listed,
        vec![(hash_b.to_string(), record_b)],
        "joiner's enumeration must show exactly the surviving credential"
    );
}
