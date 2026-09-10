//! Black-box E2E gate: restart time tracks ACTIVE zones, not persisted ones,
//! and a zone that was never opened is still fully there when someone asks.
//!
//! Boot used to open every persisted zone before serving — two redb opens, a
//! state machine, a snapshot rehydrate and several fsyncs each — so a node that
//! accumulated zones over a year got slower to restart every week, for zones
//! nobody would touch that day. It now indexes them (one readdir) and
//! materializes each on first access.
//!
//! The two halves are one test on purpose: "boots fast" is trivially
//! satisfiable by a daemon that forgot its zones, so the same restarted daemon
//! then has to serve a byte written before the restart, out of a zone it never
//! opened at boot, through a federation mount that was wired without opening
//! it either.

mod common;

use std::time::{Duration, Instant};

use common::{free_port, Daemon, Vfs, LOG_FILTER};

/// Enough zones that an open-everything boot would be clearly visible, while
/// the fresh-create half still fits a CI budget.
const ZONES: usize = 40;
/// The zone the payload lives in — one of the many, not the first or last.
const PROBE_ZONE: &str = "z0023";
const PROBE_MOUNT: &str = "/probe";
const PAYLOAD: &[u8] = b"survives-a-restart";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_does_not_open_every_persisted_zone_yet_serves_all_of_them() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let id = tmp.path().join("id");
    let id = id.to_string_lossy();
    let bind = format!("127.0.0.1:{port}");
    let adv = format!("127.0.0.1:{port}");
    let path = format!("{PROBE_MOUNT}/payload.bin");

    let zones: Vec<String> = (0..ZONES).map(|i| format!("z{i:04}")).collect();
    let zones = zones.join(",");
    let mount = format!("{PROBE_MOUNT}={PROBE_ZONE}");
    let args = [
        "--bind-addr",
        &bind,
        "--cluster-init",
        &zones,
        "--cluster-init-mount",
        &mount,
    ];

    // ── 1. Found the topology and put a byte in one of the zones. ──────────
    {
        let mut d = Daemon::spawn(&args, &env(&data, &id, &adv));
        d.wait_for_log_count("' registered", ZONES + 1, BUDGET)
            .await
            .expect("every declared zone is founded");
        d.wait_tcp(port, BUDGET).await.expect("daemon serves");
        // The declared mount must be WIRED before the write, or the payload
        // lands in root and the restart half would be testing nothing.
        d.wait_for_log("Static topology applied", BUDGET)
            .await
            .expect("the declared federation mount is applied");
        let mut vfs = Vfs::connect_serving(port, BUDGET).await;
        vfs.write_file(&path, PAYLOAD, "")
            .await
            .expect("write through the federation mount");
        assert_eq!(
            vfs.read_file(&path, "").await.expect("read back"),
            PAYLOAD,
            "the byte is in the zone before we restart"
        );
    } // drop → SIGKILL, like a crash.

    // ── 2. Restart. Boot must not open the zones it does not need. ─────────
    let restart_started = Instant::now();
    let mut d = Daemon::spawn(&args, &env(&data, &id, &adv));
    d.wait_tcp(port, BUDGET).await.expect("daemon serves again");
    let restart_took = restart_started.elapsed();

    let registered_at_boot = d.drain().matches("' registered").count();
    assert!(
        registered_at_boot <= 3,
        "restart opened {registered_at_boot} zones — boot must open only what it \
         cannot serve without (root, plus the credential zone), and materialize the \
         rest on first access"
    );
    assert!(
        restart_took < Duration::from_secs(30),
        "restart with {ZONES} persisted zones took {restart_took:?}"
    );

    // ── 3. ...and the zone nobody opened is still all there. ───────────────
    let mut vfs = Vfs::connect_serving(port, BUDGET).await;
    let read = match vfs.read_file(&path, "").await {
        Ok(bytes) => bytes,
        Err(e) => panic!(
            "a never-opened zone must serve its bytes on first touch: {e}\n{}",
            d.drain()
        ),
    };
    assert_eq!(read, PAYLOAD, "byte-exact across the restart");
    assert!(
        d.log_contains("Zone materialized on first access"),
        "the read must have materialized the zone, not read it from somewhere else:\n{}",
        d.drain()
    );

    // A write lands too — the zone is fully live, not read-only warmed.
    let second = format!("{PROBE_MOUNT}/after-restart.bin");
    vfs.write_file(&second, b"still writable", "")
        .await
        .expect("write into the materialized zone");
    assert_eq!(
        vfs.read_file(&second, "").await.expect("read back"),
        b"still writable",
    );

    // The count above was a snapshot taken the moment the port opened; a sweep
    // that ran a beat later would have slipped past it. Re-count after the
    // traffic, with a settle, so the assertion is about the steady state:
    // resident zones are the ones someone actually asked for.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let registered_after_traffic = d.drain().matches("' registered").count();
    assert!(
        registered_after_traffic <= registered_at_boot + 1,
        "after serving one zone's traffic, {registered_after_traffic} zones are open (boot \
         opened {registered_at_boot}) — only the zone that was touched should have been added"
    );
}
