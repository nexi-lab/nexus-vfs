//! Black-box E2E for the WAL DT_STREAM cold tier (nexus-vfs #229): a wal stream
//! is a logically-infinite log — append past the hot window and the oldest seqs
//! roll off into cold segments, yet the WHOLE log still reads back byte-exact,
//! on the writer AND on a peer that never had the hot rows.
//!
//! Real `nexusd-cluster` daemons on loopback, real raft, real gRPC, real cold
//! segment blobs on disk (the path-addressed federation cache) — nothing
//! stubbed. The seal thresholds are shrunk via `NEXUS_STREAM_HOT_WINDOW /
//! _SEAL_BATCH` so a modest write count forces several seals.
//!
//! Two real user journeys, each a multi-step data flow:
//!  1. SINGLE NODE — create a wal stream → append 40 frames past the window →
//!     the background seal fires (log-gated) → `stream_collect_all` reconstructs
//!     all 40 frames byte-exact (early ones now cold, recent ones hot).
//!  2. CROSS NODE — the founder writes a long log past several seals → a joiner
//!     that booted afterwards cold-reads the whole thing with a bare
//!     `stream_collect_all` (no open/watch), pulling each sealed segment from
//!     the founder over `ReadBlob` — the exact A2A-mailbox shape (a peer wrote
//!     history, a late reader collects it).

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(90);
const SEAL_LOG: &str = "wal DT_STREAM sealed cold segment";
const COMPACT_LOG: &str = "raft SC log snapshot+compact";
const SNAPSHOT_INSTALL_LOG: &str = "Applying snapshot from leader";

/// 40 fixed-width 6-byte frames (`f00000`..`f00039`). Fixed width makes the
/// `stream_collect_all` concatenation (no separators) a deterministic expected
/// value, and 40 » hot_window+seal_batch (16) forces multiple seals.
const N_FRAMES: usize = 40;

fn frame(i: usize) -> Vec<u8> {
    format!("f{i:05}").into_bytes()
}

fn expected_log() -> Vec<u8> {
    expected_upto(N_FRAMES)
}

/// The concatenation of frames `0..n` — the deterministic `collect_all` result.
fn expected_upto(n: usize) -> Vec<u8> {
    (0..n).flat_map(frame).collect()
}

/// Env shrinking the seal + raft-compaction thresholds so a modest write count
/// forces real seals (keep 8 seqs hot, roll 8 at a time) AND real SC raft-log
/// snapshot+compaction (once the log runs 16 entries past the last snapshot).
/// Production runs both together, so the tests do too.
fn seal_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("NEXUS_STREAM_HOT_WINDOW", "8"),
        ("NEXUS_STREAM_SEAL_BATCH", "8"),
        ("NEXUS_SC_SNAPSHOT_THRESHOLD", "16"),
    ]
}

fn founder_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    mounts: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut env = vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts),
        ("RUST_LOG", LOG_FILTER),
    ];
    env.extend(seal_env());
    env
}

fn joiner_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    peers: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut env = vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_PEERS", peers),
        ("RUST_LOG", LOG_FILTER),
    ];
    env.extend(seal_env());
    env
}

/// Boot a founder that owns `ZONE` at `MOUNT`. Gated on `Static topology
/// applied` (the mount committed into root ⇒ the zone is live + discoverable),
/// the same reliable signal `a2a_wakeup` uses.
async fn boot_founder(tmp: &std::path::Path) -> (Daemon, u16) {
    let fport = free_port();
    let fdata = tmp.join("f-data");
    let fid = tmp.join("f-id");
    let fadv = format!("127.0.0.1:{fport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let fbind = format!("127.0.0.1:{fport}");
    let mut founder = Daemon::spawn(
        &["--bind-addr", &fbind],
        &founder_env(
            &fdata.to_string_lossy(),
            &fid.to_string_lossy(),
            &fadv,
            &mounts,
        ),
    );
    founder
        .wait_tcp(fport, BUDGET)
        .await
        .expect("founder serves");
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder applies federation topology");
    (founder, fport)
}

/// Poll `stream_collect_all(path)` until it returns exactly `want` (raft
/// replication + background seals are asynchronous), or panic with the last
/// value at the budget. Never re-opens the stream — pure read.
async fn await_collect(v: &mut Vfs, path: &str, want: &[u8]) {
    let deadline = std::time::Instant::now() + BUDGET;
    loop {
        match v.stream_collect_all(path, "").await {
            Ok(bytes) if bytes == want => return,
            other => {
                if std::time::Instant::now() >= deadline {
                    let got = other.map(|b| b.len()).unwrap_or(0);
                    panic!(
                        "collect_all({path}) never matched the full log: got {got} bytes, want {}",
                        want.len()
                    );
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// SINGLE NODE: append past the hot window, the seal fires, and the whole log
/// reads back byte-exact (cold + hot).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_node_append_past_window_seals_and_cold_reads_whole_log() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut founder, fport) = boot_founder(tmp.path()).await;
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    let log = format!("{MOUNT}/logp");
    fc.create_stream(&log, "").await.expect("create wal stream");
    for i in 0..N_FRAMES {
        fc.stream_write(&log, &frame(i), "")
            .await
            .unwrap_or_else(|e| panic!("write frame {i}: {e}"));
    }

    // A background seal must fire — proof the hot tail spilled to cold segments.
    founder
        .wait_for_log(SEAL_LOG, BUDGET)
        .await
        .expect("a seal must fire once the log passes the hot window");

    // The full logical log reconstructs: early seqs (now cold) + recent (hot).
    await_collect(&mut fc, &log, &expected_log()).await;
}

/// CROSS NODE: the founder writes a long log past several seals; a joiner that
/// booted afterwards cold-reads the entire thing with a bare `collect_all`,
/// pulling each sealed segment from the founder over `ReadBlob`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joiner_cold_reads_a_sealed_log_pulling_segments_from_the_founder() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut founder, fport) = boot_founder(tmp.path()).await;
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    // Founder writes the long log FIRST, forcing several seals before the joiner
    // exists — so the joiner never sees the hot rows for the early seqs.
    let log = format!("{MOUNT}/xlog");
    fc.create_stream(&log, "").await.expect("create wal stream");
    for i in 0..N_FRAMES {
        fc.stream_write(&log, &frame(i), "")
            .await
            .unwrap_or_else(|e| panic!("write frame {i}: {e}"));
    }
    founder
        .wait_for_log(SEAL_LOG, BUDGET)
        .await
        .expect("founder must seal before the joiner joins");

    // Boot a joiner that reaches the zone purely by DiscoverZones.
    let jport = free_port();
    let jdata = tmp.path().join("j-data");
    let jid = tmp.path().join("j-id");
    let jadv = format!("127.0.0.1:{jport}");
    let peers = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind],
        &joiner_env(
            &jdata.to_string_lossy(),
            &jid.to_string_lossy(),
            &jadv,
            &peers,
        ),
    );
    joiner.wait_tcp(jport, BUDGET).await.expect("joiner serves");
    joiner
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("joiner joins the zone");
    let mut jc = Vfs::dial(jport).await.expect("dial joiner");

    // Joiner cold-reads the ENTIRE log — no create_stream, no watch. Early seqs
    // are cold: their segment index replicated via raft, but the blobs live in
    // the founder's cache, so the joiner pulls them over ReadBlob. Bytes must be
    // byte-exact vs. what the founder wrote.
    await_collect(&mut jc, &log, &expected_log()).await;
    drop(joiner);
    drop(founder);
}

/// P2 (bounds the raft LOG + join transfer): the founder's SC raft log is
/// bounded by snapshot+compaction, and a joiner that boots AFTER compaction
/// catches up by INSTALLING the snapshot (not replaying the full log), then
/// cold-reads the whole logical log from the bounded snapshot + CAS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joiner_installs_snapshot_after_compaction_then_cold_reads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut founder, fport) = boot_founder(tmp.path()).await;
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    // Founder writes a long log — forcing seals (spill to CAS) AND SC raft-log
    // snapshot+compaction — all BEFORE the joiner exists, so the joiner cannot
    // replay from index 1: the early log is compacted away.
    let log = format!("{MOUNT}/plog");
    fc.create_stream(&log, "").await.expect("create wal stream");
    for i in 0..N_FRAMES {
        fc.stream_write(&log, &frame(i), "")
            .await
            .unwrap_or_else(|e| panic!("write frame {i}: {e}"));
    }
    founder
        .wait_for_log(SEAL_LOG, BUDGET)
        .await
        .expect("founder seals to CAS");
    founder
        .wait_for_log(COMPACT_LOG, BUDGET)
        .await
        .expect("founder snapshots + compacts its SC raft log (log bounded)");

    // Boot a joiner. Its log starts empty and the founder's is compacted, so the
    // founder MUST send it an InstallSnapshot instead of replaying every entry.
    let jport = free_port();
    let jdata = tmp.path().join("pj-data");
    let jid = tmp.path().join("pj-id");
    let jadv = format!("127.0.0.1:{jport}");
    let peers = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind],
        &joiner_env(
            &jdata.to_string_lossy(),
            &jid.to_string_lossy(),
            &jadv,
            &peers,
        ),
    );
    joiner.wait_tcp(jport, BUDGET).await.expect("joiner serves");
    joiner
        .wait_for_log(&format!("Zone '{ZONE}' registered"), BUDGET)
        .await
        .expect("joiner joins the zone");
    // The definitive P2 assertion: the joiner caught up via an INSTALLED
    // snapshot, not a full-log replay (the compacted log made replay impossible).
    joiner
        .wait_for_log(SNAPSHOT_INSTALL_LOG, BUDGET)
        .await
        .expect("joiner must install the founder's snapshot (compacted log ⇒ no full replay)");

    // With only the bounded snapshot (hot tail + segment index) + cold CAS
    // fetches, the joiner reconstructs the ENTIRE logical log byte-exact.
    let mut jc = Vfs::dial(jport).await.expect("dial joiner");
    await_collect(&mut jc, &log, &expected_log()).await;

    // STEADY STATE: the joiner is now a promoted voter. Keep appending past
    // ANOTHER compaction — the caught-up follower stays in sync via ordinary
    // replication (no snapshot needed), both logs stay bounded, and BOTH nodes
    // read the full extended log byte-exact. This guards the common post-join
    // path (2-voter compaction), not just the one-shot catch-up.
    let total = N_FRAMES + 40;
    for i in N_FRAMES..total {
        fc.stream_write(&log, &frame(i), "")
            .await
            .unwrap_or_else(|e| panic!("write frame {i}: {e}"));
    }
    let want = expected_upto(total);
    await_collect(&mut fc, &log, &want).await;
    await_collect(&mut jc, &log, &want).await;
    drop(joiner);
    drop(founder);
}
