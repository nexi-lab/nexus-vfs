//! Declaring a federation zone is enough — the operator does not also have to
//! know which prefixes need replicating.
//!
//! An unmounted prefix routes to this node's own SOLO `root` zone (the fallback
//! in `VFSRouter::route`), which is not replicated. A write there succeeds, a
//! local read returns it, and the peer never sees it — no error at any layer.
//! So "the operator forgot a `--cluster-init-mount` line" and "A2A is broken
//! cross-machine" are the same event, and it is silent.
//!
//! That is not a hypothetical: the production compose files mount
//! `/shared=sharedzone` and never `/agents`, and `/sessions` appears in no mount
//! declaration anywhere in either repo. So the subsystems now declare their own
//! prefixes (`a2a::REPLICATED_PREFIXES`, `contracts::SESSIONS_BASE`) and the
//! composition root mounts them.
//!
//! The unit tests beside `with_default_replicated_mounts` cover the decision in
//! isolation — which arm fires for how many declared zones. What they cannot
//! see is whether the resulting map actually reaches the router: a mount that
//! is computed and then dropped on the floor passes every one of them. This
//! boots a real daemon with `NEXUS_CLUSTER_INIT` and **no** mount flag at all,
//! and asks the server where each prefix landed.
//!
//! `stat_zone` rather than `stat_found` is the point. Existence cannot tell a
//! federation mount from the root fallback — both answer yes — so an
//! existence check here would pass just as happily with the feature removed.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const BUDGET: Duration = Duration::from_secs(90);

/// One probe under each prefix a subsystem declared. They are spelled out
/// rather than derived from `a2a::REPLICATED_PREFIXES` on purpose: this is the
/// e2e side, and reading the same constant the daemon reads would let a prefix
/// disappear from the list without a single test noticing. The unit test
/// iterates the list; this one states the paths.
const PROBES: &[(&str, &str)] = &[
    ("/conversations/zone-probe", "A2A conversation store"),
    ("/agents/zone-probe", "A2A agent presence"),
    ("/sessions/zone-probe", "flat session store"),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_prefixes_route_to_the_zone_with_no_mount_flag() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let id = tmp.path().join("id");
    let id = id.to_string_lossy();
    let adv = format!("127.0.0.1:{port}");
    let bind = adv.clone();

    // NEXUS_CLUSTER_INIT_MOUNTS is DELIBERATELY ABSENT — that absence is the
    // whole test. The operator declares a zone and nothing else.
    let env = vec![
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("RUST_LOG", LOG_FILTER),
    ];

    let mut founder = Daemon::spawn(&["--bind-addr", &bind], &env);
    founder
        .wait_tcp(port, BUDGET)
        .await
        .expect("founder serves");
    // Mounts are staged by `bootstrap_static` and applied by `apply_topology`
    // on a tick, so the probes below must not race convergence.
    //
    // Gate on "VFS data plane ready" and NOT on "Static topology applied",
    // even though the latter reads like the more precise signal. It is emitted
    // at `zone_manager.rs`'s `pending_after == 0` branch, which is only reached
    // when there were mounts to apply at all — `apply_topology` returns early
    // on an empty snapshot and logs nothing. So with the injection removed
    // (exactly the mutation that must make this test fail) that line never
    // appears, and the test would die on a 90-SECOND GATE TIMEOUT having never
    // evaluated a single assertion below. It looks red either way, which is
    // the trap: a mutation that kills the gate instead of the assertion proves
    // the assertion is never exercised. "VFS data plane ready" fires on
    // convergence regardless of how many mounts there were, so the mutation
    // reaches the assertion and fails there, naming the zone it actually got.
    founder
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("founder opens its data plane");

    let mut vfs = Vfs::dial_ready(port, BUDGET).await;

    for (probe, what) in PROBES {
        vfs.write_file(probe, b"zone probe", "")
            .await
            .unwrap_or_else(|e| panic!("write {probe} ({what}): {e}"));
        let zone = vfs
            .stat_zone(probe, "")
            .await
            .unwrap_or_else(|| panic!("{probe} ({what}) must exist after a successful write"));
        assert_eq!(
            zone, ZONE,
            "{what}: {probe} routed to {zone:?}, not the declared zone {ZONE:?}. \
             A prefix that lands on the node-local root zone is not replicated, \
             so every write to it succeeds locally and no peer ever sees it."
        );
    }
}

/// The control: a path NOBODY declared still falls to the node-local root.
///
/// Without this, "everything routes to sharedzone" would satisfy the test above
/// just as well as "the declared prefixes do" — and a bug that mounted the
/// whole namespace would read as a pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_undeclared_prefix_still_falls_back_to_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let id = tmp.path().join("id");
    let id = id.to_string_lossy();
    let adv = format!("127.0.0.1:{port}");
    let bind = adv.clone();

    let env = vec![
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("RUST_LOG", LOG_FILTER),
    ];

    let mut founder = Daemon::spawn(&["--bind-addr", &bind], &env);
    founder
        .wait_tcp(port, BUDGET)
        .await
        .expect("founder serves");
    founder
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("founder opens its data plane");

    let mut vfs = Vfs::dial_ready(port, BUDGET).await;
    let undeclared = "/not-a-declared-prefix/zone-probe";
    vfs.write_file(undeclared, b"zone probe", "")
        .await
        .unwrap_or_else(|e| panic!("write {undeclared}: {e}"));

    let zone = vfs
        .stat_zone(undeclared, "")
        .await
        .expect("the probe must exist after a successful write");
    assert_ne!(
        zone, ZONE,
        "injection must fill the DECLARED prefixes only; {undeclared} landing in \
         {ZONE:?} means the whole namespace was mounted, which would make the \
         test above vacuous"
    );
}
