//! Black-box E2E (M2): a deprovision must be refused — cleanly, with no
//! side effects — on a node that does not host the target zone, and a
//! deprovision of a never-existed zone id must not ban that id.
//!
//! The zone registry is node-local: before the hosting guard, a
//! deprovision on a non-hosting node silently skipped the i_links check,
//! still wrote the GLOBAL deletion epoch, fanned out to zero peers (the
//! peer list came from the same local registry), and then failed the local
//! teardown — the caller received a failure receipt for a deletion that
//! had in fact taken effect cluster-wide. A never-existed id went down the
//! same path and left a permanent epoch record behind (zone_create for
//! that id refused forever).
//!
//! The guard answers NotFound BEFORE any epoch write, so:
//!   1. A non-hosting node refuses, and the hosting node's zone survives.
//!   2. A never-existed id refuses, and a subsequent create of that id
//!      succeeds (no ban).

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;

const ZONE_A: &str = "hosted-zone";
const ZONE_B: &str = "other-node-zone";
const GHOST: &str = "never-existed-zone";
const BUDGET: Duration = Duration::from_secs(120);

fn env<'a>(data: &'a str, id: &'a str, adv: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deprovision_on_a_non_hosting_node_refuses_without_side_effects() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Node A hosts ZONE_A; node B hosts an unrelated zone. B's registry
    // has never heard of ZONE_A — the non-hosting shape.
    let (a_data, a_id) = (
        tmp.path().join("a-data").to_string_lossy().into_owned(),
        tmp.path().join("a-id").to_string_lossy().into_owned(),
    );
    let (b_data, b_id) = (
        tmp.path().join("b-data").to_string_lossy().into_owned(),
        tmp.path().join("b-id").to_string_lossy().into_owned(),
    );
    let a_port = free_port();
    let b_port = free_port();
    let a_adv = format!("127.0.0.1:{a_port}");
    let b_adv = format!("127.0.0.1:{b_port}");

    let _a = Daemon::spawn(
        &["--bind-addr", &a_adv, "--no-tls"],
        &env(&a_data, &a_id, &a_adv),
    );
    let mut b = Daemon::spawn(
        &["--bind-addr", &b_adv, "--no-tls"],
        &env(&b_data, &b_id, &b_adv),
    );
    b.wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("node B boots the typed surface");
    let mut rt_a = ZoneRuntime::dial_ready(a_port, BUDGET).await;
    let mut rt_b = ZoneRuntime::dial_ready(b_port, BUDGET).await;

    rt_a.zone_create(ZONE_A, &[], "op-hg-create-a-0001", "")
        .await
        .expect("node A creates its zone");
    rt_b.zone_create(ZONE_B, &[], "op-hg-create-b-0002", "")
        .await
        .expect("node B creates its own zone");

    // 1. Node B refuses the deprovision of node A's zone — NotFound, not a
    //    bogus Internal failure, and nothing was written.
    let refused = rt_b
        .zone_deprovision(ZONE_A, "op-hg-cross-dep-0003", "")
        .await
        .expect_err("non-hosting node must refuse the deprovision");
    assert_eq!(refused.code(), tonic::Code::NotFound, "{refused:?}");
    assert!(
        refused.message().contains("not hosted on this node"),
        "the refusal should point the caller at the hosting nodes: {}",
        refused.message()
    );

    // The zone on the hosting node survived untouched.
    let status = rt_a.zone_status(ZONE_A, "").await.expect("status");
    assert_eq!(
        status.presence,
        i32::from(Presence::Resident),
        "a refused non-hosting deprovision must leave the zone intact"
    );

    // 2. A never-existed id: NotFound now, and a later create succeeds —
    //    the refusal must not ban the id via a stray epoch record.
    let ghost = rt_b
        .zone_deprovision(GHOST, "op-hg-ghost-dep-0004", "")
        .await
        .expect_err("deprovision of a never-existed id must be refused");
    assert_eq!(ghost.code(), tonic::Code::NotFound, "{ghost:?}");

    let created = rt_b
        .zone_create(GHOST, &[], "op-hg-ghost-create-0005", "")
        .await
        .expect("the id was never banned — create must succeed");
    assert_eq!(created.outcome, "CREATED");
}
