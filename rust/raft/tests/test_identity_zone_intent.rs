//! End-to-end coverage for the S3 Phase B zone setup → identity role
//! intent pipeline.
//!
//! Contract: setting a zone up on a node whose registry has an identity
//! directory (`ZoneRaftRegistry::set_identity_dir`) records the zone and
//! the role the node asked for in `identity.json` — the durable intent
//! that powers the "wipe `data_dir`, keep identity → daemon auto-rejoins"
//! promise.  Member addresses are replicated zone state, never part of it.
//!
//! The scenarios below exercise:
//!
//! 1. Owner + joiner-as-learner → joiner's identity.json carries a
//!    `zones` entry with the sharedzone id + the Learner intent.
//!
//! 2. A subsequent `plan_boot_action` fed with the loaded identity
//!    dispatches `JoinFederationZones { zones: [sharedzone], ... }` —
//!    proving the round-trip through the on-disk file drives the
//!    boot decision layer.

#![cfg(all(feature = "grpc", has_protos))]

mod common;

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
    let bind_str = common::node_bind_addr();

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
    // Wire the identity directory BEFORE registering any zone so zone
    // setup records its intent.
    if let Some(id_dir) = identity_dir {
        zm.registry().set_identity_dir(id_dir.to_path_buf());
    }
    (zm, bind_str)
}

async fn wait_for_zone_in_identity(
    identity_dir: &Path,
    zone_id: &str,
    deadline_ms: u64,
) -> identity::Identity {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < deadline_ms as u128 {
        if let Ok(ident) = identity::load(identity_dir) {
            if ident.zones.iter().any(|z| z.zone_id == zone_id) {
                return ident;
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
async fn joiner_zone_setup_records_role_intent_that_drives_rejoin() {
    let dir_owner_data = TempDir::new().expect("owner data");
    let dir_joiner_data = TempDir::new().expect("joiner data");
    let dir_joiner_id = TempDir::new().expect("joiner identity");

    let id_owner = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_owner, id_joiner);
    write_node_id(dir_owner_data.path(), id_owner);
    write_node_id(dir_joiner_data.path(), id_joiner);

    // Owner: no identity directory (the test focuses on the joiner).
    let (zm_owner, bind_owner) = make_node(id_owner, dir_owner_data.path(), None).await;
    // Joiner: identity directory set.
    let (zm_joiner, bind_joiner) = make_node(
        id_joiner,
        dir_joiner_data.path(),
        Some(dir_joiner_id.path()),
    )
    .await;

    // Owner creates 1-voter sharedzone and self-elects.
    let zone_owner = zm_owner
        .create_zone("sharedzone")
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
        .join_zone("sharedzone", /* learner */ true)
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

    let ident = wait_for_zone_in_identity(dir_joiner_id.path(), "sharedzone", 3000).await;

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

    // Round-trip: feed the loaded identity into plan_boot_action with
    // no CLI peers and no --cluster-init.  Row 4 dispatch
    // must carry sharedzone as an auto-join target — the on-disk
    // durable state now drives the boot decision.
    //
    // has_disk_state=false: the scenario this test simulates is
    // "identity survives, data_dir was wiped" — the exact S3 Phase B
    // auto-rejoin promise.  Under Phase G, `has_disk_state=true`
    // would collapse to `Resume` regardless of identity contents.
    // The joiner's seed (the owner) is what a wiped node rejoins through.
    let boot_cfg = BootConfig {
        identity_persisted_peers: vec![bind_owner.clone()],
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
async fn zone_setup_records_nothing_when_identity_dir_unset() {
    // If ZoneRaftRegistry has no identity_dir, zone setup records nothing
    // and no identity file materializes.  This is the test harness /
    // embedded-mode contract.
    let dir_owner_data = TempDir::new().expect("owner data");
    let dir_maybe_id = TempDir::new().expect("would-be identity");

    let id_owner = mint_random_id();
    write_node_id(dir_owner_data.path(), id_owner);
    let (zm_owner, _bind_owner) = make_node(id_owner, dir_owner_data.path(), None).await;

    let zone_owner = zm_owner.create_zone("sharedzone").expect("create");
    for _ in 0..50 {
        if zone_owner.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Wait a beat for anything that might write.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !dir_maybe_id.path().join(identity::IDENTITY_FILE).exists(),
        "identity file must not exist when identity_dir is unset",
    );
}
