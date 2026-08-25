//! Black-box E2E: a THREE-voter federation survives losing its founder — the
//! surviving majority (2 of 3) auto-elects a new raft leader and writes
//! continue. This pins the property the `Resume` peerless-gate relies on ("a
//! founder can go offline while its voter joiners keep the zone alive"):
//! `a2a_wakeup` step 9 proves the CONTRARY 2-voter case (kill 1 of 2 → no
//! majority → wal write fails loud), and this proves the ≥3-voter recovery that
//! the gate assumes when it defers to `reconcile_federation_from_peers` rather
//! than re-founding SOLO.
//!
//! Topology: a static FOUNDER owns `sharedzone` mounted at `/agents`; two
//! JOINERS reach it purely via boot-time DiscoverZones (`--peers`), each
//! joining as a VOTER (the DiscoverZones join path is all-voter). After all
//! three replicate a health byte and a mailbox inode, the founder (the initial
//! leader) is KILLED. With 2 of 3 voters left there is still a majority, so a
//! surviving voter's wal-stream write must SUCCEED — proving a new leader was
//! elected among the survivors — and the other survivor reads the bytes back.
//! Nothing is stubbed: real raft election, real wal DT_STREAM replication.

mod common;

use std::time::Duration;

use common::{await_replicated, free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(90);

fn founder_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    mounts: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts),
        ("RUST_LOG", LOG_FILTER),
    ]
}

fn joiner_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    peers: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_PEERS", peers),
        ("RUST_LOG", LOG_FILTER),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_voter_zone_survives_founder_loss_via_new_leader() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fport = free_port();
    let j1port = free_port();
    let j2port = free_port();

    let mk = |name: &str| {
        let p = tmp.path().join(name);
        p.to_string_lossy().into_owned()
    };
    let (fdata, fid) = (mk("f-data"), mk("f-id"));
    let (j1data, j1id) = (mk("j1-data"), mk("j1-id"));
    let (j2data, j2id) = (mk("j2-data"), mk("j2-id"));

    let fadv = format!("127.0.0.1:{fport}");
    let j1adv = format!("127.0.0.1:{j1port}");
    let j2adv = format!("127.0.0.1:{j2port}");
    let fbind = format!("127.0.0.1:{fport}");
    let j1bind = format!("127.0.0.1:{j1port}");
    let j2bind = format!("127.0.0.1:{j2port}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = format!("127.0.0.1:{fport}");
    let zone_registered = format!("Zone '{ZONE}' registered");

    // ── 1. Boot founder, then two DiscoverZones joiners (each a VOTER). ──
    let mut founder = Daemon::spawn(
        &["--bind-addr", &fbind],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_tcp(fport, BUDGET)
        .await
        .expect("founder serves");
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder registers sharedzone");
    // Joiners discover `sharedzone` via a one-shot DiscoverZones read of the
    // founder's ROOT DT_MOUNT entries, which commit via `apply_topology` AFTER
    // the "registered" log. Gate on "Static topology applied" so the mount is
    // discoverable before booting the joiners — otherwise a joiner reads 0
    // entries and stays rootless (the same race fixed in `founder_resume`).
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder MUST commit its declared mount into root (zone discoverable)");

    let mut j1 = Daemon::spawn(
        &["--bind-addr", &j1bind],
        &joiner_env(&j1data, &j1id, &j1adv, &peers),
    );
    j1.wait_tcp(j1port, BUDGET).await.expect("joiner1 serves");
    j1.wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner1 joins sharedzone");

    let mut j2 = Daemon::spawn(
        &["--bind-addr", &j2bind],
        &joiner_env(&j2data, &j2id, &j2adv, &peers),
    );
    j2.wait_tcp(j2port, BUDGET).await.expect("joiner2 serves");
    j2.wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner2 joins sharedzone");

    // Both joiners register the zone before their all-voter promotion COMMITS on
    // the founder. Writing while a 1→2 or 2→3 AddNode ConfChange is still pending
    // makes raft drop the proposal (`raft: proposal dropped`). Gate on the
    // founder promoting BOTH learners to voters — one log per joiner — so the
    // 3-voter config is committed and no ConfChange is in flight before we write.
    founder
        .wait_for_log_count("caught-up learner promoted to voter", 2, BUDGET)
        .await
        .expect("founder MUST promote both joiners to voters (3-voter quorum stable)");

    // ── 2. Health + plant a mailbox while all three are up (founder leads). ─
    let mut fc = Vfs::dial_ready(fport, BUDGET).await;
    let mut j1c = Vfs::dial_ready(j1port, BUDGET).await;
    let mut j2c = Vfs::dial_ready(j2port, BUDGET).await;

    let health = format!("{MOUNT}/health.txt");
    fc.write_file(&health, b"3voter-health", "")
        .await
        .expect("founder writes health");
    await_replicated(&mut j1c, &health, "", BUDGET).await;
    await_replicated(&mut j2c, &health, "", BUDGET).await;

    let mailbox = format!("{MOUNT}/probe-ai/chat-with-me");
    fc.mkdir(&format!("{MOUNT}/probe-ai"), "")
        .await
        .expect("mkdir agent dir");
    fc.create_stream(&mailbox, "")
        .await
        .expect("founder plants mailbox");
    await_replicated(&mut j1c, &mailbox, "", BUDGET).await;
    await_replicated(&mut j2c, &mailbox, "", BUDGET).await;

    // ── 3. KILL the founder (the initial leader). 2 of 3 voters remain. ──
    drop(founder);

    // ── 4. A surviving voter's wal write MUST eventually commit: 2 of 3 voters
    //       is a majority, so the survivors elect a new leader. Poll rather than
    //       sleep a fixed interval so the assertion tests RECOVERY, not election
    //       latency, and stays robust under CI load. (Contrast a2a_wakeup step 9:
    //       2 voters, kill 1 → no majority → this same write fails forever.) A
    //       failed attempt does not append, so the first success lands at 0. ──
    let envelope = br#"{"from":"probe-ai","to":"probe-ai","body":"post-founder-loss"}"#;
    let deadline = std::time::Instant::now() + BUDGET;
    let off = loop {
        // Re-open on each attempt: materializing the local wal backend can
        // itself need the (newly elected) leader, so it belongs in the retry.
        let _ = j1c.create_stream(&mailbox, "").await;
        match j1c.stream_write(&mailbox, envelope, "").await {
            Ok(off) => break off,
            Err(e) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "after the founder (leader) died, a surviving voter's wal write never \
                     committed within budget — the 2 remaining voters (a majority of 3) \
                     should have elected a new leader. last error: {e}"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    };
    assert_eq!(off, 0, "first entry on the mailbox lands at offset 0");

    // ── 5. The OTHER survivor reads the post-loss bytes back — replication
    //       continues under the newly elected leader. The stream ENTRY (unlike
    //       the inode, awaited at step 2) replicates asynchronously after the
    //       raft commit, so poll until it lands rather than racing the apply. ──
    j2c.create_stream(&mailbox, "")
        .await
        .expect("other survivor re-opens mailbox");
    let deadline = std::time::Instant::now() + BUDGET;
    let got = loop {
        let g = String::from_utf8_lossy(
            &j2c.stream_collect_all(&mailbox, "")
                .await
                .expect("other survivor reads mailbox"),
        )
        .into_owned();
        if g.contains("post-founder-loss") || std::time::Instant::now() >= deadline {
            break g;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert!(
        got.contains("post-founder-loss"),
        "the second survivor must replicate the post-founder-loss write under the new \
         leader; got {got:?}"
    );
}
