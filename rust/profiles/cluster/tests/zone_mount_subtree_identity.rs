//! Black-box E2E (L-1): the subtree is part of a mount's identity on the
//! typed mount surface.
//!
//! A single-zone deployment's default prefix mounts are SUBTREE mounts
//! (`/agents` exposes only the zone's `/agents` subtree). Asking the RPC
//! to mount the WHOLE zone at the same path of the same target used to
//! answer MOUNTED while the subtree mount silently stayed in place (the
//! idempotence check compared only the target). Now it is refused — an
//! in-place upgrade would double-count the target's i_links — and a
//! fresh whole-zone mount succeeds after the old one is unmounted.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};

const ZONE: &str = "tenant-a";
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_target_different_subtree_mount_is_refused_not_merged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    // Single declared zone: the boot's auto-prefix mounts land
    // /agents, /conversations and /sessions as SUBTREE mounts of it.
    let env = vec![
        ("NEXUS_DATA_DIR", data.as_str()),
        ("NEXUS_IDENTITY_DIR", id.as_str()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut daemon = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env);
    daemon
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("boot wires the typed zone runtime surface");
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;

    // RPC mount = WHOLE zone at /agents of root, same target as the boot's
    // subtree mount: a different mount, so not idempotent — refused with a
    // pointer to unmount, not merged into a phantom MOUNTED.
    let refused = rt
        .zone_mount("root", "/agents", ZONE, "op-subtree-mount-0001", "")
        .await
        .expect_err("a same-target different-subtree mount must be refused");
    assert_eq!(
        refused.code(),
        tonic::Code::FailedPrecondition,
        "{refused:?}"
    );
    assert!(
        refused.message().contains("unmount first"),
        "the refusal should tell the operator what to do: {}",
        refused.message()
    );

    // After unmounting the boot's subtree mount, the whole-zone mount
    // succeeds — and the RPC's read-back (which now demands
    // target_subtree == VFS_ROOT) proves the mount it reported is the one
    // that is really there.
    rt.zone_unmount("root", "/agents", "op-subtree-unmount-0002", "")
        .await
        .expect("unmount the boot's subtree mount");
    let mounted = rt
        .zone_mount("root", "/agents", ZONE, "op-subtree-mount-0003", "")
        .await
        .expect("whole-zone mount after unmount");
    assert_eq!(mounted.outcome, "MOUNTED");
}
