//! End-to-end coverage for the S3 Phase B ConfState apply → identity
//! mirror pipeline.
//!
//! Contract: after a JoinZone RPC lands and the ConfChange commits on
//! the joiner side, the driver's apply callback (installed by
//! `ZoneRaftRegistry::set_identity_dir`) must have persisted the
//! zone's membership into `identity.json` — the durable snapshot that
//! powers the "wipe `data_dir`, keep identity → daemon auto-rejoins"
//! promise.
//!
//! The scenarios below exercise:
//!
//! 1. Owner + joiner-as-learner converge → joiner's identity.json
//!    carries a `zones` entry with the sharedzone id + this node's
//!    role (Learner).  Members list reflects `voters ∪ learners`
//!    projected through the peer map.
//!
//! 2. A subsequent `plan_boot_action` fed with the loaded identity
//!    dispatches `JoinFederationZones { zones: [sharedzone], ... }` —
//!    proving the round-trip through the on-disk file drives the
//!    boot decision layer.

#![cfg(all(feature = "grpc", has_protos))]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use nexus_raft::bootstrap::{plan_boot_action, BootAction, BootConfig};
use nexus_raft::identity::{self, IdentityZoneRole};
use nexus_raft::transport::call_join_zone_rpc;
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

fn write_node_id(dir: &Path, id: u64) {
    std::fs::create_dir_all(dir).expect("create dir");
    std::fs::write(dir.join(NODE_ID_FILE), id.to_be_bytes()).expect("write .node_id");
}

async fn make_node(
    node_id: u64,
    data_dir: &Path,
    identity_dir: Option<&Path>,
) -> (std::sync::Arc<ZoneManager>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    let bind_str = format!("{}", addr);

    let zm = ZoneManager::with_node_id(
        "test-host",
        node_id,
        data_dir.to_str().expect("utf-8"),
        vec![],
        &bind_str,
        None,
        Some(format!("http://{bind_str}")),
        None,
    )
    .expect("ZoneManager");
    // Wire the identity mirror BEFORE registering any zone so the
    // apply callback is installed at zone-setup time.
    if let Some(id_dir) = identity_dir {
        zm.registry().set_identity_dir(id_dir.to_path_buf());
    }
    (zm, bind_str)
}

async fn wait_for_zone_in_identity(
    identity_dir: &Path,
    zone_id: &str,
    self_addr: &str,
    deadline_ms: u64,
) -> identity::Identity {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < deadline_ms as u128 {
        if let Ok(ident) = identity::load(identity_dir) {
            if let Some(z) = ident.zones.iter().find(|z| z.zone_id == zone_id) {
                if z.members.iter().any(|m| m == self_addr) {
                    return ident;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "identity did not gain zone {zone_id} within {deadline_ms} ms; \
         dir={:?}",
        identity_dir
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conf_state_apply_persists_zone_membership_on_joiner() {
    let dir_owner_data = TempDir::new().expect("owner data");
    let dir_joiner_data = TempDir::new().expect("joiner data");
    let dir_joiner_id = TempDir::new().expect("joiner identity");

    let id_owner = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_owner, id_joiner);
    write_node_id(dir_owner_data.path(), id_owner);
    write_node_id(dir_joiner_data.path(), id_joiner);

    // Owner: no identity mirror (test focuses on joiner-side apply).
    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner_data.path(), None).await;
    // Joiner: identity mirror ON.
    let (zm_joiner, bind_joiner) = make_node(
        id_joiner,
        dir_joiner_data.path(),
        Some(dir_joiner_id.path()),
    )
    .await;

    // Owner creates 1-voter sharedzone and self-elects.
    let zone_owner = zm_owner
        .create_zone("sharedzone", vec![format!("{id_owner}@{bind_owner}")])
        .expect("create sharedzone on owner");
    for _ in 0..100 {
        if zone_owner.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(zone_owner.is_leader(), "owner must self-elect");

    // Joiner registers locally as learner, then JoinZone RPC.
    let endpoint_owner = format!("http://{bind_owner}");
    let endpoint_joiner = format!("http://{bind_joiner}");
    let _zone_joiner = zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_owner}@{bind_owner}")],
            /* learner */ true,
        )
        .expect("local join_zone on joiner");
    let r = call_join_zone_rpc(
        &endpoint_owner,
        "sharedzone",
        id_joiner,
        &endpoint_joiner,
        /* as_learner */ true,
        None,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(r.success, "JoinZone must succeed: {:?}", r.error);

    // Wait for the joiner's apply-cb to fire and land on disk.  The
    // joiner's ConfState apply happens once the leader's snapshot /
    // append-entries stream commits the ConfChange on the joiner
    // side.
    let self_addr_operator = format!("http://{bind_joiner}");
    let ident = wait_for_zone_in_identity(
        dir_joiner_id.path(),
        "sharedzone",
        &self_addr_operator,
        3000,
    )
    .await;

    let zone_entry = ident
        .zones
        .iter()
        .find(|z| z.zone_id == "sharedzone")
        .expect("zones must include sharedzone");
    assert_eq!(
        zone_entry.as_role,
        IdentityZoneRole::Learner,
        "joiner joined as learner",
    );
    assert!(
        zone_entry.members.iter().any(|m| m == &self_addr_operator),
        "self must appear in the members list; got {:?}",
        zone_entry.members,
    );
    assert!(
        zone_entry.last_confirmed_unix_secs.is_some(),
        "apply cb must stamp last_confirmed",
    );

    // Round-trip: feed the loaded identity into plan_boot_action with
    // no CLI peers and no NEXUS_FEDERATION_ZONES.  Row 4 dispatch
    // must carry sharedzone as an auto-join target — the on-disk
    // durable state now drives the boot decision.
    //
    // has_disk_state=false: the scenario this test simulates is
    // "identity survives, data_dir was wiped" — the exact S3 Phase B
    // auto-rejoin promise.  Under Phase G, `has_disk_state=true`
    // would collapse to `Resume` regardless of identity contents.
    let boot_cfg = BootConfig {
        identity_persisted_peers: ident.peers.clone(),
        cli_peer_addrs: vec![],
        federation_zones: vec![],
        federation_mounts: BTreeMap::new(),
        bootstrap_new: false,
        has_disk_state: false,
        identity_zones: ident.zones.clone(),
    };
    match plan_boot_action(&boot_cfg) {
        BootAction::JoinFederationZones { zones, .. } => {
            assert_eq!(zones, vec!["sharedzone".to_string()]);
        }
        other => panic!("expected JoinFederationZones, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_cb_no_op_when_identity_dir_unset() {
    // If ZoneRaftRegistry has no identity_dir, the callback is never
    // installed and no identity file materializes.  This is the test
    // harness / embedded-mode contract.
    let dir_owner_data = TempDir::new().expect("owner data");
    let dir_maybe_id = TempDir::new().expect("would-be identity");

    let id_owner = mint_random_id();
    write_node_id(dir_owner_data.path(), id_owner);
    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner_data.path(), None).await;

    let zone_owner = zm_owner
        .create_zone("sharedzone", vec![format!("{id_owner}@{bind_owner}")])
        .expect("create");
    for _ in 0..50 {
        if zone_owner.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Wait a beat for any apply that might fire.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !dir_maybe_id.path().join(identity::IDENTITY_FILE).exists(),
        "identity file must not exist when identity_dir is unset",
    );
}
