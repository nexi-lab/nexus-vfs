//! Contract regression: a joiner that advertises an address a REMOTE peer
//! cannot dial (loopback / wildcard / bare hostname / no `:port`) must FAIL
//! LOUD at boot — not warn and proceed.
//!
//! Warn-and-proceed is exactly what wedged the Win↔Mac duet: the joiner
//! advertised `localhost:12022`, the founder recorded that as the voter address
//! in `duetrt826`, could never dial it, the 2-voter zone lost quorum, and it
//! surfaced only hours later as a buried `ZoneMetaStore.put: not leader`. A
//! misconfiguration that silently wedges a cluster is unusable in production;
//! failing loud at the source makes it impossible to form.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, LOG_FILTER};

const BUDGET: Duration = Duration::from_secs(30);

/// The joiner advertises a loopback address while its peer is on another
/// machine — the daemon must EXIT with a clear error naming --advertise-addr,
/// not come up serving an unreachable membership.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joiner_advertising_loopback_to_a_remote_peer_refuses_to_boot() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("j-data").to_string_lossy().into_owned();
    let id = tmp.path().join("j-id").to_string_lossy().into_owned();
    let jport = free_port();
    let jadv = format!("127.0.0.1:{jport}"); // loopback advertise — the misconfig
                                             // A peer on "another machine". Only its address SHAPE matters — the boot
                                             // check runs before any dial, so it need not be reachable.
    let remote_peer = "100.64.0.99:2126";

    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jadv],
        &[
            ("NEXUS_DATA_DIR", data.as_str()),
            ("NEXUS_IDENTITY_DIR", id.as_str()),
            ("NEXUS_ADVERTISE_ADDR", jadv.as_str()),
            ("NEXUS_NO_TLS", "true"),
            ("NEXUS_INSECURE_NO_AUTH", "true"),
            ("NEXUS_PEERS", remote_peer),
            ("RUST_LOG", LOG_FILTER),
        ],
    );

    let out = joiner.wait_exit(BUDGET).await.expect(
        "daemon must REFUSE to boot (exit) when advertising a loopback address to a remote peer, \
         not serve an unreachable membership",
    );
    let lower = out.to_lowercase();
    assert!(
        out.contains("refusing to boot") && lower.contains("loopback"),
        "expected a fail-loud loopback-advertise boot error naming the fix; got:\n{out}"
    );
}
