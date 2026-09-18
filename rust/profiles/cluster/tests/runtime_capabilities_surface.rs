//! Black-box E2E (R13 / acceptance 7): `GetRuntimeCapabilities` tells an
//! assembling Nexus WHAT it is talking to — the auth posture (armed?
//! which mode?), the permission gate, the zone-runtime substrate — so a
//! production assembly can refuse to compose against a default it did not
//! choose.
//!
//! Three postures:
//!   * no-auth: `--no-tls` loopback, no secret → armed=false, mode
//!     "no-auth", provider_armed=false (the explicit open posture).
//!   * armed: TLS-on ApiKey/cert plane → mode "api-key", provider_armed
//!     true (boot installs the containment provider under TLS).
//!   * boot window: a request that arrives before the data plane is wired
//!     is HELD at the service door and answered once boot completes
//!     (`data_plane_ready=true`); `Unavailable` is the over-budget refusal
//!     a readiness probe treats as retry. Both are "not ready yet" — this
//!     test pins the hold-then-answer behavior (deterministic) with many
//!     declared zones to widen the window.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};

const BUDGET: Duration = Duration::from_secs(180);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_auth_loopback_declares_itself() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let _d = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env);
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;
    let caps = rt.get_runtime_capabilities("").await.expect("caps");
    assert!(caps.data_plane_ready, "an answered request passed the gate");
    let auth = caps.auth.expect("auth capability");
    assert!(!auth.armed, "no-auth posture: no identity plane is armed");
    assert_eq!(auth.mode, "no-auth", "the provider declares its own mode");
    let perm = caps.permission.expect("permission capability");
    assert!(
        !perm.provider_armed,
        "--no-tls: no permission provider is installed (the gate is a no-op)"
    );
    let zr = caps.zone_runtime.expect("zone-runtime capability");
    assert!(
        zr.deletion_protection,
        "the anti-resurrection epoch check is armed"
    );
    assert!(
        !zr.journal_zone.is_empty(),
        "the capability names the journal zone"
    );
    assert!(
        caps.capabilities
            .iter()
            .any(|c| c.contains("operation-journal")),
        "the capability list advertises the journal: {:?}",
        caps.capabilities
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_armed_posture_declares_the_real_plane() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    // Bind non-loopback: the posture invariant holds that a LOOPBACK bind
    // with no credential policy is the legal Open posture; an armed test
    // must be the reachable-bind case where mTLS is the identity plane.
    let bind = format!("0.0.0.0:{port}");
    let adv = format!("127.0.0.1:{port}");

    // TLS founder (cert-identity plane — no sk- secret needed).
    let env = vec![
        ("NEXUS_DATA_DIR", data.as_str()),
        ("NEXUS_IDENTITY_DIR", id.as_str()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut d = Daemon::spawn(&["--bind-addr", &bind], &env);
    d.wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("TLS founder boots the typed surface");

    let tls = std::path::Path::new(&data).join("tls");
    let ca = std::fs::read(tls.join("ca.pem")).expect("ca");
    let cert = std::fs::read(tls.join("node.pem")).expect("node cert");
    let key = std::fs::read(tls.join("node-key.pem")).expect("node key");
    let mut rt = ZoneRuntime::dial_tls(port, &ca, &cert, &key, BUDGET).await;
    let caps = rt.get_runtime_capabilities("").await.expect("caps");
    assert!(caps.data_plane_ready);
    let auth = caps.auth.expect("auth capability");
    assert!(auth.armed, "TLS-on: the identity plane IS armed");
    assert_eq!(auth.mode, "api-key", "the provider's own mode declaration");
    let perm = caps.permission.expect("permission capability");
    assert!(
        perm.provider_armed,
        "TLS-on boot installs the containment provider — the gate is real"
    );
    let zr = caps.zone_runtime.expect("zone-runtime capability");
    assert_eq!(zr.journal_zone, "__control__");
    assert!(zr.deletion_protection);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_in_the_boot_window_waits_then_answers_ready() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    // Widen the boot window: 40 declared zones must each be founded before
    // the data plane is marked ready.
    let zones: Vec<String> = (0..40)
        .map(|i| format!("boot-widening-zone-{i:02}"))
        .collect();
    let init = zones.join(",");
    let env = vec![
        ("NEXUS_DATA_DIR", data.as_str()),
        ("NEXUS_IDENTITY_DIR", id.as_str()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", init.as_str()),
        ("RUST_LOG", LOG_FILTER),
    ];
    let _d = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &env);
    // Dial the moment the port accepts (boot is likely still running) and
    // fire the FIRST request immediately — it must be held at the door and
    // answered only once the kernel is wired, never answered early.
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;
    let first = tokio::time::timeout(BUDGET, rt.get_runtime_capabilities(""))
        .await
        .expect("the held request is answered within the budget (hold ≠ hang)")
        .expect("first capabilities answer");
    assert!(
        first.data_plane_ready,
        "a request that got through the boot gate is answered ready — the gate \
         answered it, so the data plane is wired"
    );
    // The surface is idempotent across the window: a later ask agrees.
    let again = rt.get_runtime_capabilities("").await.expect("second ask");
    assert_eq!(again.auth.unwrap().mode, "no-auth");
}
