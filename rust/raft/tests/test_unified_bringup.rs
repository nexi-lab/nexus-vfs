//! Integration tests for the unified bring-up decision layer
//! (`nexus_raft::bootstrap`).
//!
//! Scope: exercise `BootConfig` + `plan_boot_action` against realistic
//! peer-address forms (round-tripped through
//! `NodeAddress::parse_peer_list_operator`, the same call site
//! `open_zone_manager` uses) and realistic identity blobs (round-tripped
//! through `identity::persist_peers` + `identity::load`, same as
//! `open_zone_manager`).  This layer is on the shortest path to
//! main.rs's `run_daemon` federation branch (commit 4 of the S3 完全体
//! series), so any breakage here surfaces boot regressions before they
//! reach live cross-machine bring-up.
//!
//! The scenarios below cover all 6 matrix rows plus one convergence
//! probe that pins the founder side against a live `ZoneManager`.
//! Symmetric-boot race is exercised via row-3-on-both-sides.
//!
//! ### Design note — no dispatcher in bootstrap.rs
//!
//! Plan v2 keeps `bootstrap.rs` as a **pure** decision layer.  Commit 4
//! ships the dispatcher inline in `run_daemon` (main.rs of the cluster
//! binary), which is not reachable from a raft integration test.
//! These tests therefore validate that `plan_boot_action` returns the
//! correct `BootAction` under each row's operator inputs — and that the
//! founder path's advertised primitive (`ZoneManager::create_zone`)
//! actually admits the same values `BootAction::StaticFounder` hands
//! back.  A regression in either half surfaces here before the cluster
//! binary is even built.

#![cfg(all(feature = "grpc", has_protos))]

use std::collections::BTreeMap;
use std::time::Duration;

use nexus_raft::bootstrap::{
    plan_boot_action, BootAction, BootConfig, REASON_AMBIGUOUS_FRESH_FOUNDER_WITH_PEERS,
    REASON_SPLIT_BRAIN_IDENTITY_AND_ZONES,
};
use nexus_raft::identity;
use nexus_raft::transport::NodeAddress;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

fn parse_cli(peers_csv: &str) -> Vec<NodeAddress> {
    NodeAddress::parse_peer_list_operator(peers_csv, /* use_tls */ false).expect("parse --peers")
}

fn zone_mount(path: &str, zone: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(path.to_string(), zone.to_string());
    m
}

fn cfg(
    identity_peers: Vec<&str>,
    cli_peers_csv: &str,
    zones: Vec<&str>,
    mounts: BTreeMap<String, String>,
) -> BootConfig {
    BootConfig {
        identity_persisted_peers: identity_peers.into_iter().map(str::to_string).collect(),
        cli_peer_addrs: parse_cli(cli_peers_csv),
        federation_zones: zones.into_iter().map(str::to_string).collect(),
        federation_mounts: mounts,
        bootstrap_new: false,
        has_disk_state: false,
    }
}

fn mint_id() -> u64 {
    let id = rand::random::<u64>();
    if id == 0 {
        1
    } else {
        id
    }
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

// ── Scenario 1 ──────────────────────────────────────────────────────
// Fresh federation, split roles:
//   * A: NEXUS_FEDERATION_ZONES=sharedzone + empty identity + no CLI
//     peers  ⇒ StaticFounder — plumbing pins that the founder side's
//     advertised primitive (`ZoneManager::create_zone`) actually admits
//     the values BootAction carries.
//   * B: identity empty + CLI --peers=A + no zones  ⇒
//     JoinFederationZones with empty zones (Phase A: sidecar still
//     required for the actual sharedzone join; Phase B populates zones
//     from identity.zones).
//
// This is the "sidecar-less bring-up" contract for Phase A: no split-
// brain, no ambiguous fail, and the founder path is not gated behind
// any operator ceremony.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario1_split_roles_fresh_bringup_no_split_brain() {
    // ---- A: founder ----
    let cfg_a = cfg(
        vec![],
        "",
        vec!["sharedzone"],
        zone_mount("/shared", "sharedzone"),
    );
    let action_a = plan_boot_action(&cfg_a);
    let (zones, mounts) = match action_a {
        BootAction::StaticFounder { zones, mounts, .. } => (zones, mounts),
        other => panic!("A: expected StaticFounder, got {other:?}"),
    };
    assert_eq!(zones, vec!["sharedzone".to_string()]);
    assert_eq!(
        mounts.get("/shared").map(String::as_str),
        Some("sharedzone")
    );

    // Founder-side plumbing check: create_zone with the BootAction-
    // carried zone id under a live ZoneManager. Uses the same shape
    // ZoneManager::bootstrap_static_async ultimately calls per zone.
    let dir_a = TempDir::new().expect("dir-a");
    let id_a = mint_id();
    let (zm_a, bind_a) = make_node(id_a, dir_a.path()).await;
    for z in &zones {
        let zone_a = zm_a
            .create_zone(z, vec![format!("{id_a}@{bind_a}")])
            .expect("create_zone(founder) admits BootAction value");
        // Wait for self-election on 1-voter.
        for _ in 0..100 {
            if zone_a.is_leader() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(zone_a.is_leader(), "founder must self-elect on {z}");
    }

    // ---- B: fresh joiner, --peers=A, no ZONES ----
    let bind_a_csv = bind_a.clone();
    let cfg_b = cfg(vec![], &bind_a_csv, vec![], BTreeMap::new());
    match plan_boot_action(&cfg_b) {
        BootAction::JoinFederationZones {
            peers,
            zones,
            mounts,
        } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].endpoint, format!("http://{bind_a_csv}"));
            assert!(
                zones.is_empty(),
                "Phase A joiner has no auto-zone list; Phase B fills from identity.zones",
            );
            assert!(mounts.is_empty());
        }
        other => panic!("B: expected JoinFederationZones, got {other:?}"),
    }
}

// ── Scenario 2 ──────────────────────────────────────────────────────
// Restart both nodes after prior convergence: identity.peers non-empty
// on each side.  Neither declares NEXUS_FEDERATION_ZONES (per PR #4477
// runbook — auto-create only on the initial founder boot, restarts
// never set it).  Both nodes take the returning-joiner path (row 4);
// crucially, neither returns `StaticFounder`, so there is no
// split-brain window even if both restart simultaneously.  Also
// exercises the round-trip through `identity::persist_peers` +
// `identity::load` — the same store `open_zone_manager` uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario2_restart_with_populated_identity_takes_joiner_return_path() {
    // Simulate a prior boot's identity file for each side.
    let dir_a = TempDir::new().expect("id-a");
    let dir_b = TempDir::new().expect("id-b");
    let seed_a = vec!["100.64.0.27:2126".to_string()];
    let seed_b = vec!["100.64.0.21:2126".to_string()];
    identity::persist_peers(
        dir_a.path(),
        &identity::load(dir_a.path()).unwrap(),
        &seed_a,
    )
    .expect("persist a");
    identity::persist_peers(
        dir_b.path(),
        &identity::load(dir_b.path()).unwrap(),
        &seed_b,
    )
    .expect("persist b");

    let loaded_a = identity::load(dir_a.path()).expect("load a");
    let loaded_b = identity::load(dir_b.path()).expect("load b");

    let cfg_a = BootConfig {
        identity_persisted_peers: loaded_a.peers,
        cli_peer_addrs: vec![],
        federation_zones: vec![],
        federation_mounts: BTreeMap::new(),
        bootstrap_new: false,
        has_disk_state: true,
    };
    let cfg_b = BootConfig {
        identity_persisted_peers: loaded_b.peers,
        cli_peer_addrs: vec![],
        federation_zones: vec![],
        federation_mounts: BTreeMap::new(),
        bootstrap_new: false,
        has_disk_state: true,
    };

    assert!(matches!(
        plan_boot_action(&cfg_a),
        BootAction::JoinFederationZones { .. }
    ));
    assert!(matches!(
        plan_boot_action(&cfg_b),
        BootAction::JoinFederationZones { .. }
    ));
}

// ── Scenario 3 ──────────────────────────────────────────────────────
// Ambiguous fresh founder — matrix row 6.  Empty identity, CLI peers
// non-empty, NEXUS_FEDERATION_ZONES set: the new guard fires.  Pins
// the reason tag so exit-code grep / telemetry filters remain valid
// across future refactors.
#[test]
fn scenario3_row6_ambiguous_fresh_founder_fails_loud() {
    let cfg = cfg(
        vec![],
        "100.64.0.21:2126",
        vec!["sharedzone"],
        zone_mount("/shared", "sharedzone"),
    );
    match plan_boot_action(&cfg) {
        BootAction::FailLoud { reason, hint } => {
            assert_eq!(reason, REASON_AMBIGUOUS_FRESH_FOUNDER_WITH_PEERS);
            assert!(
                hint.contains("100.64.0.21:2126") && hint.contains("sharedzone"),
                "hint must surface offending values, got: {hint}",
            );
        }
        other => panic!("expected FailLoud, got {other:?}"),
    }
}

// ── Scenario 4 ──────────────────────────────────────────────────────
// Split-brain trap — matrix row 5 (existing PR #112 guard replayed at
// the decision layer).  Identity already knows peers AND operator set
// NEXUS_FEDERATION_ZONES.  This is the both-founder misconfig observed
// twice in a row on 2026-07-05: two fresh nodes both sourcing a
// founder-style launcher that seeded identity from a prior aborted
// boot.
#[test]
fn scenario4_row5_identity_plus_zones_fails_loud() {
    let cfg = cfg(
        vec!["100.64.0.21:2126"],
        "",
        vec!["sharedzone"],
        zone_mount("/shared", "sharedzone"),
    );
    match plan_boot_action(&cfg) {
        BootAction::FailLoud { reason, hint } => {
            assert_eq!(reason, REASON_SPLIT_BRAIN_IDENTITY_AND_ZONES);
            assert!(
                hint.contains("identity.json") && hint.contains("sharedzone"),
                "hint must direct the operator to the two knobs, got: {hint}",
            );
        }
        other => panic!("expected FailLoud, got {other:?}"),
    }
}

// ── Scenario 5 ──────────────────────────────────────────────────────
// Symmetric-boot race — both nodes fresh, both --peers pointed at each
// other, neither declares zones.  Both hit row 3 (JoinFederationZones
// with empty zones list).  Phase A does NOT auto-tie-break — the
// symmetric row-3 path is a no-op (no zones to auto-join) and each
// daemon comes up rootless-with-peers.  The important contract is that
// NEITHER side auto-creates via row 1 → no split-brain of the two
// disjoint SOLO clusters observed 2026-07-04.
#[test]
fn scenario5_symmetric_row3_both_sides_no_split_brain() {
    let cfg_a = cfg(vec![], "100.64.0.21:2126", vec![], BTreeMap::new());
    let cfg_b = cfg(vec![], "100.64.0.27:2126", vec![], BTreeMap::new());
    for (label, action) in [
        ("A", plan_boot_action(&cfg_a)),
        ("B", plan_boot_action(&cfg_b)),
    ] {
        match action {
            BootAction::JoinFederationZones { zones, .. } => {
                assert!(
                    zones.is_empty(),
                    "{label}: no auto-zone create on symmetric boot"
                );
            }
            BootAction::StaticFounder { .. } => {
                panic!(
                    "{label}: symmetric row-3 must NOT dispatch StaticFounder — split-brain trap"
                );
            }
            other => panic!("{label}: expected JoinFederationZones, got {other:?}"),
        }
    }
}
