//! Black-box E2E (R12): the reserved zones — `root` (every node's local
//! namespace) and `__control__` (the replicated control store the deletions
//! themselves ride on) — refuse deletion at EVERY layer: the typed surface,
//! and the peer fan-out path (`remove_zone`'s guard fires BEFORE any peer is
//! dialed, so the fan-out can never order a reserved-zone destroy).

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;
use tonic::Code;

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
async fn reserved_zones_refuse_deletion_on_every_layer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();

    let fport = free_port();
    let jport = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");

    // Two nodes, so the fan-out layer is real (a reserved-zone destroy
    // would order a DeleteZone at the peer if the guard were missing).
    let fenv = env(&fdata, &fid, &fadv);
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv, "--no-tls"], &fenv);
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("founder boots the typed surface");

    let jenv = {
        let mut e = env(&jdata, &jid, &jadv);
        e.push(("NEXUS_PEERS", fadv.as_str()));
        e
    };
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv, "--no-tls"], &jenv);
    joiner
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("joiner boots the typed surface");
    let mut rt = ZoneRuntime::dial_ready(fport, BUDGET).await;

    // ── Typed deprovision of `root` → refused ──
    let err = rt
        .zone_deprovision("root", "op-dep-root-0001", "")
        .await
        .expect_err("deprovision(root) must be refused");
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "root is reserved: {}",
        err.message()
    );

    // ── Typed deprovision of `__control__` → refused ──
    let err = rt
        .zone_deprovision("__control__", "op-dep-control-0002", "")
        .await
        .expect_err("deprovision(__control__) must be refused");
    assert_eq!(err.code(), Code::FailedPrecondition, "{}", err.message());

    // ── Remove-replica of a reserved zone → refused (fan-out layer) ──
    let err = rt
        .zone_remove_replica("root", false, "op-rm-root-0003", "")
        .await
        .expect_err("remove_replica(root) must be refused");
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "the remove-zone guard must fire before any peer dial: {}",
        err.message()
    );
    let err = rt
        .zone_remove_replica("__control__", true, "op-rm-control-0004", "")
        .await
        .expect_err(
            "remove_replica(__control__, force) must be refused — force does not \
                     override reserved",
        );
    assert_eq!(err.code(), Code::FailedPrecondition, "{}", err.message());

    // ── And the refusals were not destructive: root is still RESIDENT ──
    let status = rt.zone_status("root", "").await.expect("root status");
    assert_eq!(
        status.presence,
        i32::from(Presence::Resident),
        "root must survive every refused deletion attempt"
    );
    // Both daemons are still alive and answering (fail-open nowhere: the
    // refusal is per-mutation, never a boot/boot-path failure).
    let mut j_rt = ZoneRuntime::dial_ready(jport, BUDGET).await;
    let j_status = j_rt
        .zone_status("root", "")
        .await
        .expect("joiner root status");
    assert_eq!(j_status.presence, i32::from(Presence::Resident));
}
