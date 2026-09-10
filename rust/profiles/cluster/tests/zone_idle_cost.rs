//! Black-box E2E gate: a zone nobody is using must cost ~nothing, and must
//! still answer instantly when someone finally calls.
//!
//! Zone count is a product variable — Sudo Cloud maps a tenant to a zone, so
//! "one zone per person" only works if an idle zone is free. It used to cost
//! ~0.1% of a core each, because every zone ran its own 100 Hz transport loop
//! whether or not anything was happening in it: 50 idle zones burned ~5% of a
//! core, 10k would have burned ~10 cores. The loop now waits on work with a
//! raft deadline, and a lone-leader zone with no peers has neither, so it
//! parks (see `ZoneConsensusDriver::tick_is_noop`).
//!
//! The two halves are one test on purpose: "costs no CPU" is trivially
//! satisfiable by a broken loop that never wakes, so the same daemon that just
//! proved it was quiet then has to serve a write into one of those parked
//! zones and read it back.
//!
//! Linux-only: the measurement reads the daemon's CPU time from `/proc`. That
//! is where CI runs and where the daemon ships; the Windows dev box gets the
//! same coverage from the Docker bench.
#![cfg(target_os = "linux")]

mod common;

use std::time::{Duration, Instant};

use common::{free_port, Daemon, Vfs, LOG_FILTER};

/// Enough zones that the old per-zone cost is unmistakable (~5% of a core)
/// while the daemon still boots well inside the test budget.
const ZONES: usize = 50;
/// The zone the write lands in — one that has been parked the whole time, and
/// not the first or last one registered.
const PROBE_ZONE: &str = "z0031";
const PROBE_MOUNT: &str = "/probe";

/// Ceiling for 50 idle zones, as a fraction of ONE core.
///
/// Baseline before the fix: ~0.1% per zone ⇒ ~5%. Parked, the daemon should
/// sit at essentially zero; the budget is set well above that but well below
/// the old cost, so it catches a regression to per-zone polling without
/// flaking on a noisy shared runner.
const IDLE_CPU_BUDGET_FRACTION_OF_ONE_CORE: f64 = 0.02;
const SAMPLE_WINDOW: Duration = Duration::from_secs(5);
const BUDGET: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_zones_burn_no_cpu_and_still_serve_on_first_touch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let id = tmp.path().join("id");
    let id = id.to_string_lossy();
    let bind = format!("127.0.0.1:{port}");
    let adv = format!("127.0.0.1:{port}");

    let zones: Vec<String> = (0..ZONES).map(|i| format!("z{i:04}")).collect();
    let zones = zones.join(",");
    let mount = format!("{PROBE_MOUNT}={PROBE_ZONE}");

    let mut d = Daemon::spawn(
        &[
            "--bind-addr",
            &bind,
            "--cluster-init",
            &zones,
            "--cluster-init-mount",
            &mount,
        ],
        &[
            ("NEXUS_DATA_DIR", &data),
            ("NEXUS_IDENTITY_DIR", &id),
            ("NEXUS_ADVERTISE_ADDR", &adv),
            ("NEXUS_NO_TLS", "true"),
            ("NEXUS_INSECURE_NO_AUTH", "true"),
            ("RUST_LOG", LOG_FILTER),
        ],
    );
    // Every declared zone registered, plus `root`.
    d.wait_for_log_count("' registered", ZONES + 1, BUDGET)
        .await
        .expect("all declared zones register");
    d.wait_tcp(port, BUDGET).await.expect("daemon serves");

    // Let boot tail-work (elections, topology apply) finish before sampling —
    // otherwise we would measure the bring-up, not the idle state.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let before = d.cpu_seconds();
    tokio::time::sleep(SAMPLE_WINDOW).await;
    let burned = d.cpu_seconds() - before;
    let fraction = burned / SAMPLE_WINDOW.as_secs_f64();
    assert!(
        fraction < IDLE_CPU_BUDGET_FRACTION_OF_ONE_CORE,
        "{ZONES} idle zones burned {:.1}% of one core ({burned:.3}s over {:?}) — budget is \
         {:.1}%. A zone with no peers and nothing to do must park, not poll; see \
         ZoneConsensusDriver::tick_is_noop.\n{}",
        fraction * 100.0,
        SAMPLE_WINDOW,
        IDLE_CPU_BUDGET_FRACTION_OF_ONE_CORE * 100.0,
        d.drain(),
    );

    // ...and the quiet is not a wedge: a write into a zone that has been
    // parked this whole time must land promptly, without waiting out a timer.
    let mut vfs = Vfs::connect_serving(port, BUDGET).await;
    let path = format!("{PROBE_MOUNT}/wake.txt");
    let started = Instant::now();
    vfs.write_file(&path, b"awake", "")
        .await
        .expect("write into a parked zone");
    let write_took = started.elapsed();
    let read = vfs.read_file(&path, "").await.expect("read it back");
    assert_eq!(read, b"awake", "the parked zone served the byte it stored");
    assert!(
        write_took < Duration::from_secs(5),
        "waking a parked zone took {write_took:?} — a parked loop must wake on the message \
         itself, not on a timer"
    );
}
