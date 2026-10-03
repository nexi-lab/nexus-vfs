//! Black-box E2E (R10 / acceptance for the presence ladder + D3 mount
//! gates): `ZoneStatus` distinguishes the presence ladder AND the typed
//! mount surface is admin-gated while the gRPC `setattr(DT_MOUNT)` entrance
//! refuses a low-privilege token at its own admin gate.
//!
//!   * RESIDENT — a live local raft runtime (hot after creation/mount).
//!   * HOSTED_NOT_RESIDENT — catalogued after restart, runtime cold; asking
//!     must NOT materialize it (the answer is a fact, not a side effect).
//!   * LOCAL_NOT_FOUND — this node has never heard of the zone.
//!   * DELETED — global identity via the deletion epoch.
//!
//! Posture: ApiKey + `--no-tls` (the low-privilege token is real, the
//! mount refusals are the boundary, not TLS noise).

mod common;

use std::time::Duration;

use common::{free_port, mint_token_key, Daemon, Vfs, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;
use tonic::Code;

const SECRET: &str = "presence-secret";
const ZONE: &str = "tenant-a";
const BUDGET: Duration = Duration::from_secs(150);
const DT_MOUNT: i32 = 2;

fn env(data: &str, id: &str, adv: &str) -> Vec<(String, String)> {
    vec![
        ("NEXUS_DATA_DIR".into(), data.into()),
        ("NEXUS_IDENTITY_DIR".into(), id.into()),
        ("NEXUS_ADVERTISE_ADDR".into(), adv.into()),
        ("NEXUS_API_KEY_SECRET".into(), SECRET.into()),
        ("NEXUS_NO_TLS".into(), "true".into()),
        ("RUST_LOG".into(), LOG_FILTER.into()),
    ]
}

fn as_strs(env: &[(String, String)]) -> Vec<(&str, &str)> {
    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presence_ladder_and_mount_gates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    // Mint keys offline: an admin (creates zones, mounts, deprovisions) and
    // a low-privilege user (mounts must be refused). NO_TLS in the mint env
    // keeps the offline store-zone choice (root) identical to the daemon's.
    let cli_env = [
        ("NEXUS_DATA_DIR", data.as_str()),
        ("NEXUS_IDENTITY_DIR", id.as_str()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_NO_TLS", "true"),
    ];
    let admin = {
        let (ok, out, err) = common::cli(
            &cli_env,
            &[
                "auth",
                "mint",
                "--subject-type",
                "user",
                "--subject-id",
                "admin-op",
                "--admin",
                "--name",
                "e2e",
            ],
        );
        assert!(
            ok && out.trim().starts_with("sk-"),
            "admin mint failed: {err}"
        );
        out.trim().to_string()
    };
    let low = mint_token_key(&cli_env, "user", "alice", &format!("{ZONE}:rw"));

    // ── Boot ──
    let e = env(&data, &id, &adv);
    let mut d = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &as_strs(&e));
    d.wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("typed surface wired");
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;

    // ── LOCAL_NOT_FOUND before anything exists ──
    let miss = rt.zone_status(ZONE, &admin).await.expect("status");
    assert_eq!(miss.presence, i32::from(Presence::LocalNotFound));
    assert!(
        miss.cluster.is_none(),
        "an absent zone carries no cluster facts"
    );

    // ── RESIDENT after a typed create ──
    rt.zone_create(ZONE, &[], "op-presence-create-0001", &admin)
        .await
        .expect("admin creates the zone");
    let hot = rt.zone_status(ZONE, &admin).await.expect("status");
    assert_eq!(hot.presence, i32::from(Presence::Resident));
    let facts = hot.cluster.expect("resident zone carries live facts");
    assert!(facts.has_store && facts.voter_count >= 1);

    // ── HOSTED_NOT_RESIDENT after a restart (cold catalog entry) ──
    drop(d);
    let mut d2 = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &as_strs(&e));
    d2.wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("daemon reboots");
    let mut rt2 = ZoneRuntime::dial_ready(port, BUDGET).await;
    let cold = rt2.zone_status(ZONE, &admin).await.expect("status");
    assert_eq!(
        cold.presence,
        i32::from(Presence::HostedNotResident),
        "after restart the zone is catalogued but its runtime is cold: {cold:?}"
    );
    assert!(
        cold.cluster.is_none(),
        "a cold zone carries no cluster facts — and asking must not materialize it"
    );

    // Materialize it for real (a typed mount touches the parent+target),
    // then the ladder reads RESIDENT again.
    rt2.zone_mount(
        "root",
        format!("/{ZONE}").as_str(),
        ZONE,
        "op-presence-mount-0002",
        &admin,
    )
    .await
    .expect("admin mounts the zone");
    let warm = rt2.zone_status(ZONE, &admin).await.expect("status");
    assert_eq!(warm.presence, i32::from(Presence::Resident));

    // ── DELETED after a typed deprovision (global identity) ──
    rt2.zone_unmount(
        "root",
        format!("/{ZONE}").as_str(),
        "op-presence-unmount-0003",
        &admin,
    )
    .await
    .expect("unmount first (i_links guard)");
    rt2.zone_deprovision(ZONE, "op-presence-dep-0004", &admin)
        .await
        .expect("admin deprovisions");
    let gone = rt2.zone_status(ZONE, &admin).await.expect("status");
    assert_eq!(gone.presence, i32::from(Presence::Deleted));
    assert!(
        gone.deletion
            .as_ref()
            .expect("deletion info")
            .deletion_epoch
            > 0
    );

    // ── D3: a low-privilege token cannot mount ──
    // (a) typed ZoneMount — the uniform zone-lifecycle admin gate.
    let err = rt2
        .zone_mount("root", "/lowpriv", "root", "op-low-mount-0005", &low)
        .await
        .expect_err("a low-privilege token must not mount");
    assert_eq!(err.code(), Code::PermissionDenied, "{}", err.message());

    // (b) the gRPC setattr(DT_MOUNT) entrance — its own admin gate
    //     (the generic sys_setattr entrance admits domestic callers by
    //     containment design; THIS entrance is the boundary a client rides).
    let mut vfs = Vfs::connect_authenticated(port, &low, BUDGET).await;
    let inner = vfs
        .setattr_raw(kernel::kernel::vfs_proto::SetattrRequest {
            path: "/lowpriv-mount".into(),
            auth_token: low.clone(),
            entry_type: DT_MOUNT,
            ..Default::default()
        })
        .await
        .expect("setattr transport");
    assert!(
        inner.is_error,
        "setattr(DT_MOUNT) with a low-privilege token must refuse: {}",
        String::from_utf8_lossy(&inner.error_payload)
    );
    assert!(
        String::from_utf8_lossy(&inner.error_payload)
            .to_ascii_lowercase()
            .contains("admin"),
        "the refusal names the admin gate: {}",
        String::from_utf8_lossy(&inner.error_payload)
    );
}
