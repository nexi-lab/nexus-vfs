//! `bootstrap_or_join_zone` root-SOLO invariant pin.
//!
//! Every nexus daemon owns its own per-node `root` zone (1-voter,
//! local namespace).  Federation between independent nodes happens
//! through NAMED zones (e.g. `sharedzone`) joined via the
//! `nexusd-cluster join` sidecar — never by adding another node into
//! a peer's root cluster.
//!
//! This test pins the kernel-internal entry-point reject so the
//! operator-facing misconfig surfaces with a clear error instead of
//! cascading through ConfChange / heartbeat / clamping /
//! cross-federation pollution.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;

use lib::transport_primitives::NodeAddress;
use nexus_raft::distributed_coordinator::bootstrap_or_join_zone;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

fn alloc_port() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    format!("{addr}")
}

fn make_node(node_id: u64, dir: &std::path::Path) -> (Arc<ZoneManager>, String) {
    let bind_str = alloc_port();
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
async fn test_root_zone_rejects_non_empty_peers_for_solo_invariant() {
    // Setup: a fresh node with no zones loaded.  Pretend operator set
    // `NEXUS_PEERS=<some-other-node>`, intending to federate with that
    // node but accidentally pointing it at root.
    let dir = TempDir::new().expect("tempdir");
    let (zm, _bind) = make_node(11111, dir.path());

    let peer = NodeAddress::parse("22222@127.0.0.1:54321", false).expect("parse peer");
    let peers = vec![peer];

    // Run bootstrap_or_join_zone for root with non-empty peers.  This is
    // the misconfig pattern: operator put a remote address in NEXUS_PEERS
    // intending federation, but NEXUS_PEERS is consumed by the root-zone
    // boot path.
    //
    // Run on the blocking pool because `bootstrap_or_join_zone` is sync
    // and spins its own multi-thread runtime for JoinZone RPCs inside
    // its joiner branch — calling it on the outer multi-thread runtime
    // worker without `spawn_blocking` would panic with "Cannot start a
    // runtime from within a runtime" the first time the joiner branch
    // tries to dispatch.  We never actually reach the joiner branch
    // (we expect the SOLO-invariant reject at function entry), but
    // future test edits shouldn't have to remember this — wrap in
    // `spawn_blocking` for safety.
    let zm_clone = Arc::clone(&zm);
    let result = tokio::task::spawn_blocking(move || {
        bootstrap_or_join_zone(
            zm_clone.as_ref(),
            "root",
            11111,
            "127.0.0.1:9999",
            &peers,
            /* bootstrap_new */ false,
            /* max_attempts  */ Some(1),
            /* as_learner    */ false,
        )
    })
    .await
    .expect("task join");

    let err = result.expect_err(
        "bootstrap_or_join_zone(root, peers=non-empty) must reject the SOLO-invariant \
         misconfig; instead it returned Ok() — the per-node root namespace was \
         silently exposed to JoinZone against the peer's root cluster, which is the \
         exact bug this contract is meant to prevent",
    );

    assert!(
        err.contains("root zone is per-node SOLO"),
        "reject error must name the invariant ('root zone is per-node SOLO'); \
         got: {err}",
    );
    assert!(
        err.contains("NEXUS_PEERS"),
        "reject error must name the misconfigured env var (NEXUS_PEERS) so the \
         operator can locate the source; got: {err}",
    );
    assert!(
        err.contains("nexusd-cluster join"),
        "reject error must hand the operator the correct fix path (named-zone \
         join via sidecar); got: {err}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_root_zone_accepts_empty_peers_solo_founder_path() {
    // Setup: a fresh node with no zones loaded.  Operator intended a
    // SOLO root (no peers) — this is the happy path that every nexus
    // daemon takes at boot.
    let dir = TempDir::new().expect("tempdir");
    let (zm, _bind) = make_node(33333, dir.path());

    let zm_clone = Arc::clone(&zm);
    let result = tokio::task::spawn_blocking(move || {
        bootstrap_or_join_zone(
            zm_clone.as_ref(),
            "root",
            33333,
            "127.0.0.1:9998",
            /* peers         */ &[],
            /* bootstrap_new */ false,
            /* max_attempts  */ None,
            /* as_learner    */ false,
        )
    })
    .await
    .expect("task join");

    result.expect(
        "bootstrap_or_join_zone(root, peers=empty) must succeed via the \
         FoundImmediately solo-founder branch; SOLO-invariant reject must not \
         fire when peers is empty",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_named_zone_still_accepts_non_empty_peers() {
    // The SOLO invariant is root-specific.  Named federation zones
    // (sharedzone, dc1-namespace, …) MUST still accept non-empty peers
    // — that's how the `nexusd-cluster join` sidecar joins them.
    //
    // We don't actually reach Branch 3 join here (the unreachable peer
    // would loop forever on max_attempts=Some(1) → Err after one round),
    // but we DO need to confirm the SOLO reject does NOT fire for
    // named zones.  A Branch 3 join failure to an unreachable peer
    // surfaces as a different error string than the SOLO reject —
    // that's the assertion below.
    let dir = TempDir::new().expect("tempdir");
    let (zm, _bind) = make_node(44444, dir.path());

    let peer = NodeAddress::parse("55555@127.0.0.1:55555", false).expect("parse peer");
    let peers = vec![peer];

    let zm_clone = Arc::clone(&zm);
    let result = tokio::task::spawn_blocking(move || {
        bootstrap_or_join_zone(
            zm_clone.as_ref(),
            "sharedzone",
            44444,
            "127.0.0.1:9997",
            &peers,
            /* bootstrap_new */ false,
            /* max_attempts  */ Some(1),
            /* as_learner    */ false,
        )
    })
    .await
    .expect("task join");

    // We expect failure (peer unreachable), but NOT the SOLO-invariant
    // failure — the named-zone join path must be reached.
    let err = result.expect_err("unreachable peer should produce some Err");
    assert!(
        !err.contains("root zone is per-node SOLO"),
        "named zone (sharedzone) misclassified as root-SOLO violation — \
         the invariant is root-only and must not bleed into named zones; \
         got: {err}",
    );
}
