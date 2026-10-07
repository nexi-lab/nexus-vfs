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
//! `stat_zone` rather than `stat_found` is the point of the first test.
//! Existence cannot tell a federation mount from the root fallback — both
//! answer yes — so an existence check there would pass just as happily with the
//! feature removed.
//!
//! The declaration carries a second guarantee, and `stat_zone` is blind to it:
//! the prefixes all name the SAME zone, so each must be its own namespace
//! inside it. `each_mounted_prefix_is_its_own_namespace_inside_the_shared_zone`
//! covers that half.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const BUDGET: Duration = Duration::from_secs(90);

/// Every prefix a subsystem declared. They are spelled out rather than derived
/// from `a2a::REPLICATED_PREFIXES` on purpose: this is the e2e side, and reading
/// the same constant the daemon reads would let a prefix disappear from the list
/// without a single test noticing. The unit test iterates the list; this one
/// states the paths.
const PREFIXES: &[(&str, &str)] = &[
    ("/conversations", "A2A conversation store"),
    ("/agents", "A2A agent presence"),
    ("/sessions", "flat session store"),
];

/// The prefix the namespace probe writes under; the other two are its negative
/// space. Any member of `PREFIXES` would do. Renaming it out of that list does
/// not make the test vacuous — the loop would then assert not-found on the path
/// we just wrote and fail there.
const WRITTEN_PREFIX: &str = "/sessions";

/// Boot a founder that declares `ZONE` and nothing else.
///
/// NEXUS_CLUSTER_INIT_MOUNTS is DELIBERATELY ABSENT — that absence is the whole
/// fixture. The operator declares a zone; every mount these tests observe was
/// injected by the composition root.
async fn founder_declaring_only_the_zone(tmp: &std::path::Path) -> (Daemon, u16) {
    let port = free_port();
    let data = tmp.join("data");
    let data = data.to_string_lossy();
    let id = tmp.join("id");
    let id = id.to_string_lossy();
    let adv = format!("127.0.0.1:{port}");

    let env = vec![
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("RUST_LOG", LOG_FILTER),
    ];

    let mut founder = Daemon::spawn(&["--bind-addr", &adv], &env);
    founder
        .wait_tcp(port, BUDGET)
        .await
        .expect("founder serves");
    // Mounts are staged by `bootstrap_static` and applied by `apply_topology`
    // on a tick, so the probes must not race convergence.
    //
    // Gate on "VFS data plane ready" and NOT on "Static topology applied",
    // even though the latter reads like the more precise signal. It is emitted
    // at `zone_manager.rs`'s `pending_after == 0` branch, which is only reached
    // when there were mounts to apply at all — `apply_topology` returns early
    // on an empty snapshot and logs nothing. So with the injection removed
    // (exactly the mutation that must make these tests fail) that line never
    // appears, and a test would die on a 90-SECOND GATE TIMEOUT having never
    // evaluated a single assertion. It looks red either way, which is the trap:
    // a mutation that kills the gate instead of the assertion proves the
    // assertion is never exercised. "VFS data plane ready" fires on convergence
    // regardless of how many mounts there were, so the mutation reaches the
    // assertion and fails there, naming the zone it actually got.
    founder
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("founder opens its data plane");
    (founder, port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declared_prefixes_route_to_the_zone_with_no_mount_flag() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_founder, port) = founder_declaring_only_the_zone(tmp.path()).await;
    let mut vfs = Vfs::dial_ready(port, BUDGET).await;

    for (prefix, what) in PREFIXES {
        let probe = format!("{prefix}/zone-probe");
        vfs.write_file(&probe, b"zone probe", "")
            .await
            .unwrap_or_else(|e| panic!("write {probe} ({what}): {e}"));
        let zone = vfs
            .stat_zone(&probe, "")
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

/// The second guarantee a mount declaration carries, and the one `stat_zone`
/// above cannot see: each prefix is its OWN namespace inside the shared zone.
///
/// All three prefixes mount the same zone, so "which zone" is identical for
/// every one of them and a router that threw the mount prefix away would
/// satisfy every assertion in the test above. One did: before a mount carried a
/// declared target subtree, `/agents/x`, `/conversations/x` and `/sessions/x`
/// all composed the SAME zone key, so `agent_list` returned every session and
/// registering an agent made a conversation appear under its name (#361).
///
/// `found` on the path we wrote is the state gate. Without it a daemon that
/// dropped the write on the floor would also report "not visible elsewhere",
/// and the negative space would be satisfied by nothing happening at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_mounted_prefix_is_its_own_namespace_inside_the_shared_zone() {
    const MARKER: &str = "namespace-probe";

    let tmp = tempfile::tempdir().expect("tempdir");
    let (_founder, port) = founder_declaring_only_the_zone(tmp.path()).await;
    let mut vfs = Vfs::dial_ready(port, BUDGET).await;

    // A mount nothing has been written to yet must list EMPTY, not raise. The
    // subtree a mount exposes has to exist as a directory inside the target
    // zone for that to hold; when only the zone's own `/` was ever created,
    // `agent_list` on a fresh cluster failed instead of returning nothing.
    for (prefix, what) in PREFIXES {
        let listed = vfs.readdir_names(prefix, "").await.unwrap_or_else(|e| {
            panic!("{prefix} ({what}) must list as empty on a fresh cluster, not fail: {e}")
        });
        assert!(
            listed.is_empty(),
            "{prefix} ({what}) is not empty on a fresh cluster: {listed:?}"
        );
    }

    let written = format!("{WRITTEN_PREFIX}/{MARKER}");
    vfs.write_file(&written, b"namespace probe", "")
        .await
        .unwrap_or_else(|e| panic!("write {written}: {e}"));
    assert!(
        vfs.stat_found(&written, "").await,
        "state gate: {written} must exist after a successful write, or the \
         not-found assertions below are satisfied by the write having vanished"
    );
    assert_eq!(
        vfs.readdir_names(WRITTEN_PREFIX, "").await.as_deref(),
        Ok(&[written.clone()][..]),
        "{WRITTEN_PREFIX} must list exactly the entry written under it"
    );

    for (prefix, what) in PREFIXES {
        if *prefix == WRITTEN_PREFIX {
            continue;
        }
        let aliased = format!("{prefix}/{MARKER}");
        assert!(
            !vfs.stat_found(&aliased, "").await,
            "{aliased} exists, but {MARKER} was only ever written to \
             {written}. {what} and the session store share a zone; sharing a \
             zone must not mean sharing a namespace."
        );
        let listed = vfs
            .readdir_names(prefix, "")
            .await
            .unwrap_or_else(|e| panic!("readdir {prefix} ({what}): {e}"));
        assert!(
            listed.is_empty(),
            "{prefix} ({what}) lists {listed:?} after a write to {written}"
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
    let (_founder, port) = founder_declaring_only_the_zone(tmp.path()).await;
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
