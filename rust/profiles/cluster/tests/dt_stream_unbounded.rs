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
const TRIM_LOG: &str = "wal DT_STREAM trimmed cold segments";
/// The trim-GC observer's reclaim line — proof the trimmed segment BLOBS were
/// physically deleted (not just dropped from the index), on the node that owns
/// them. Distinct from `TRIM_LOG` (the index-side trim).
const TRIM_GC_LOG: &str = "wal DT_STREAM trim-GC reclaimed cold segment blobs";
const COMPACT_LOG: &str = "raft SC log snapshot+compact";
const SNAPSHOT_INSTALL_LOG: &str = "Applying snapshot from leader";

/// The distinct `OffsetOutOfRange` wire code (grpc `RpcErrorCode`), as it
/// appears in the JSON error payload. A read below the retention floor must
/// carry THIS, not a generic `InternalError` (-32603).
const OFFSET_OUT_OF_RANGE_CODE: &str = "-32019";

/// Retention budget for the trim test: a few sealed segments' worth of headroom
/// is far larger than this, so appending `N_FRAMES` forces the oldest cold
/// segments to drop. Small enough to trim, non-zero so the stream is bounded
/// (not keep-forever). The test asserts the RESULT generically (`0 < earliest <
/// N_FRAMES`), never a size-derived exact floor.
const RETENTION_BYTES: u64 = 100;

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

/// Parse the retention floor out of a Truncated error payload
/// (`…"message":"offset 0 trimmed; earliest 24"…`). `None` if the payload is
/// not a floor message (e.g. the offset is not trimmed yet).
fn parse_earliest(payload: &str) -> Option<u64> {
    let after = payload.split("earliest ").nth(1)?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Poll a non-blocking read of offset 0 until it becomes Truncated (trimming is
/// async, behind the background seal), returning the parsed retention floor.
async fn await_truncated_earliest(v: &mut Vfs, path: &str) -> u64 {
    let deadline = std::time::Instant::now() + BUDGET;
    loop {
        let r = v
            .stream_read_at(path, 0, "")
            .await
            .expect("stream_read_at rpc");
        if r.is_error {
            if let Some(e) = parse_earliest(&r.error_payload) {
                return e;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "offset 0 never became Truncated (last: is_error={}, payload={:?})",
                r.is_error, r.error_payload
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// P3 (retention trim + Truncated / OffsetOutOfRange): a wal stream created with
/// a small cold-storage budget trims its oldest sealed segments as the log grows
/// — storage stays bounded — and a read below the retention floor returns a
/// DISTINCT `OffsetOutOfRange`, while reads at/above the floor still resolve
/// byte-exact and `collect_all` returns exactly the surviving suffix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_trims_old_segments_and_reads_below_earliest_are_truncated() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut founder, fport) = boot_founder(tmp.path()).await;
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    // A wal stream with a TINY cold budget, so appending well past it forces
    // real trims — the oldest sealed segments drop and `earliest` advances.
    let log = format!("{MOUNT}/trimlog");
    fc.create_stream_cap(&log, RETENTION_BYTES, "")
        .await
        .expect("create bounded wal stream");
    for i in 0..N_FRAMES {
        fc.stream_write(&log, &frame(i), "")
            .await
            .unwrap_or_else(|e| panic!("write frame {i}: {e}"));
    }

    // Both a seal AND a trim must fire (log-gated): the cold tier spilled, then
    // was bounded back under budget.
    founder
        .wait_for_log(SEAL_LOG, BUDGET)
        .await
        .expect("a seal fires once the log passes the hot window");
    founder
        .wait_for_log(TRIM_LOG, BUDGET)
        .await
        .expect("a trim fires once cold storage exceeds the retention budget");

    // Offset 0 is now below the retention floor — read it as Truncated and
    // recover the floor `earliest`.
    let earliest = await_truncated_earliest(&mut fc, &log).await;
    assert!(
        earliest > 0 && (earliest as usize) < N_FRAMES,
        "earliest {earliest} must be a proper interior floor (0 < e < {N_FRAMES})"
    );

    // The wire error is the DISTINCT OffsetOutOfRange, not a generic internal
    // error, and its message names the trim + the floor.
    let below = fc.stream_read_at(&log, 0, "").await.expect("read rpc");
    assert!(below.is_error, "offset 0 is trimmed → error");
    assert!(
        below.error_payload.contains(OFFSET_OUT_OF_RANGE_CODE),
        "wire code must be OffsetOutOfRange ({OFFSET_OUT_OF_RANGE_CODE}): {}",
        below.error_payload
    );
    assert!(
        below.error_payload.contains("trimmed") && below.error_payload.contains("earliest"),
        "message names the trim + floor: {}",
        below.error_payload
    );

    // Just below the floor is still Truncated; AT the floor resolves byte-exact.
    let below_floor = fc
        .stream_read_at(&log, earliest - 1, "")
        .await
        .expect("rpc");
    assert!(
        below_floor.is_error,
        "earliest-1 is below the floor → Truncated"
    );
    let at_floor = fc.stream_read_at(&log, earliest, "").await.expect("rpc");
    assert!(
        !at_floor.is_error,
        "the earliest surviving offset resolves: {}",
        at_floor.error_payload
    );
    assert_eq!(
        at_floor.data,
        frame(earliest as usize),
        "earliest frame byte-exact"
    );
    assert_eq!(
        at_floor.next_offset,
        earliest + 1,
        "next offset advances by one"
    );

    // `collect_all` returns EXACTLY the surviving suffix [earliest, N): old data
    // is gone (bounded) and the rest is byte-exact.
    let want_suffix: Vec<u8> = (earliest as usize..N_FRAMES).flat_map(frame).collect();
    await_collect(&mut fc, &log, &want_suffix).await;

    // PHYSICAL reclaim (the actual point of retention): the trim-GC observer must
    // delete the trimmed segments' BLOBS, not only drop their index entries —
    // otherwise storage grows unbounded on disk while the logical floor advances.
    // Gate on the reclaim log, then assert the on-disk cold blobs are bounded to
    // ~the budget, far fewer than the ~N/seal_batch segments sealed. (A no-op GC
    // would pass every assertion above; only this catches it.)
    founder
        .wait_for_log(TRIM_GC_LOG, BUDGET)
        .await
        .expect("trim-GC physically reclaims the trimmed cold blobs");
    let seg_blobs = count_seg_blobs(tmp.path());
    assert!(
        (1..=2).contains(&seg_blobs),
        "cold segment blobs on disk must be bounded by retention after trim-GC \
         (kept ~1 segment, dropped the rest), found {seg_blobs}"
    );

    drop(founder);
}

/// Count sealed cold-segment blobs on disk: files under a `__seg__` directory
/// (the `{stream}/__seg__/{base}` seal layout, the SSOT in `cold_segment.rs`).
/// The physical-storage proof for retention — a trimmed segment's blob is gone
/// from here once the trim-GC observer reclaims it.
fn count_seg_blobs(dir: &std::path::Path) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                n += count_seg_blobs(&p);
            } else if p.to_string_lossy().contains("__seg__") {
                n += 1;
            }
        }
    }
    n
}

/// P3 cross-node: the retention floor is REPLICATED. The founder trims a bounded
/// stream; a joiner that boots afterwards honours the SAME floor — a read below
/// `earliest` is Truncated on the joiner too, and its `collect_all` returns the
/// identical surviving suffix, pulling the kept cold segment from the founder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joiner_honours_the_replicated_retention_floor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut founder, fport) = boot_founder(tmp.path()).await;
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    // Founder writes + trims BEFORE the joiner exists, so the joiner learns the
    // floor purely from replicated raft state, never from the hot rows.
    let log = format!("{MOUNT}/trimx");
    fc.create_stream_cap(&log, RETENTION_BYTES, "")
        .await
        .expect("create bounded wal stream");
    for i in 0..N_FRAMES {
        fc.stream_write(&log, &frame(i), "")
            .await
            .unwrap_or_else(|e| panic!("write frame {i}: {e}"));
    }
    founder
        .wait_for_log(TRIM_LOG, BUDGET)
        .await
        .expect("founder trims before the joiner joins");

    // Boot a joiner that reaches the zone via DiscoverZones.
    let jport = free_port();
    let jdata = tmp.path().join("tj-data");
    let jid = tmp.path().join("tj-id");
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

    // Read the founder's STABLE floor: all writes/trims have long settled by
    // here, so offset 0's Truncated `earliest` is the final floor (the value the
    // joiner must converge on). Reading it now — rather than mid-trim, when the
    // floor is still advancing 8→16→24 — is what makes the cross-node compare
    // deterministic.
    let f_earliest = await_truncated_earliest(&mut fc, &log).await;

    // The joiner honours the SAME replicated floor: offset 0 is Truncated with
    // the identical `earliest`, no create_stream / watch — pure replicated read.
    let j_earliest = await_truncated_earliest(&mut jc, &log).await;
    assert_eq!(
        j_earliest, f_earliest,
        "the retention floor must replicate to the joiner"
    );

    // And the joiner reconstructs the identical surviving suffix, pulling the
    // kept cold segment from the founder over ReadBlob.
    let want_suffix: Vec<u8> = (f_earliest as usize..N_FRAMES).flat_map(frame).collect();
    await_collect(&mut jc, &log, &want_suffix).await;

    drop(joiner);
    drop(founder);
}
