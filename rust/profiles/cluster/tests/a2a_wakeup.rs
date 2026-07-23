//! Black-box E2E: a mailbox write wakes a PEER's parked `sys_watch` across a
//! real two-node federation — the cross-machine interrupt the whole A2A design
//! rests on.
//!
//! Two real `nexusd-cluster` daemons on loopback, wired like a Win<->Mac
//! deployment: a static FOUNDER owns `sharedzone` mounted at `/agents`; a
//! JOINER reaches it purely by boot-time DiscoverZones (`--peers`, no
//! federation env). Nothing is stubbed — real raft JoinZone, real wal
//! DT_STREAM replication over the raft log, real gRPC. Auth is OFF here
//! (`--insecure-no-auth`); the auth-ON `from`-stamp is covered by
//! `agent_bind_from_stamp`. Rust replacement for the retired
//! `scripts/e2e_a2a_wakeup.py`. The journey, each step consuming the last:
//! BOOT founder (owner) + joiner (DiscoverZones); HEALTH founder writes under
//! `/agents` and the joiner reads it back; A2A the joiner owns a mailbox, the
//! founder (a peer) opens + sends, the joiner's parked Watch wakes on its own
//! replica and reads the envelope back; REVERSE swap roles (both nodes arm the
//! wakeup + can send); HONEST kill the leader and the survivor's wal write
//! FAILS LOUD (no quorum ⇒ no leader ⇒ the mount must not accept undeliverable
//! bytes).

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
        ("NEXUS_FEDERATION_ZONES", ZONE),
        ("NEXUS_FEDERATION_MOUNTS", mounts),
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

/// One real A2A direction: `agent` owns the mailbox on `owner_port`; a `sender`
/// peer that never created it opens + writes it; the owner's parked Watch wakes
/// and it reads the envelope back.
async fn mailbox_round(owner_port: u16, sender_port: u16, sender_name: &str, agent: &str) {
    let mailbox = format!("{MOUNT}/{agent}/chat-with-me");
    let envelope =
        format!(r#"{{"from":"{sender_name}","to":"{agent}","body":"ping from {sender_name}"}}"#);

    let mut owner = Vfs::dial(owner_port).await.expect("dial owner");
    let mut sender = Vfs::dial(sender_port).await.expect("dial sender");

    // Owner plants the mailbox (wal DT_STREAM), sender waits for it to replicate.
    owner
        .mkdir(&format!("{MOUNT}/{agent}"), "")
        .await
        .expect("mkdir agent dir");
    owner
        .create_stream(&mailbox, "")
        .await
        .expect("owner creates mailbox");
    await_replicated(&mut sender, &mailbox, "", BUDGET).await;

    // Sender opens the peer-owned mailbox (materializes a wal backend for it).
    sender
        .create_stream(&mailbox, "")
        .await
        .expect("sender opens peer mailbox");

    // Owner parks a Watch in the background; give it a beat to actually park.
    let watch_mbox = mailbox.clone();
    let watch = tokio::spawn(async move {
        let mut w = Vfs::dial(owner_port).await.expect("dial owner (watch)");
        w.watch(&watch_mbox, 20_000, "").await
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Sender sends the envelope — a replicated AppendStreamEntry.
    sender
        .stream_write(&mailbox, envelope.as_bytes(), "")
        .await
        .expect("sender sends");

    let matched = watch
        .await
        .expect("watch task joined")
        .expect("watch rpc ok");
    assert!(
        matched,
        "{agent}'s Watch TIMED OUT — the apply-side stream-wakeup observer did not fire on its {ZONE} replica"
    );

    let got = owner
        .stream_collect_all(&mailbox, "")
        .await
        .expect("owner reads back");
    let got = String::from_utf8_lossy(&got);
    assert!(
        got.contains(&envelope),
        "{agent} read {got:?}, expected to contain {envelope:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mailbox_write_wakes_a_peers_parked_sys_watch_both_directions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fport = free_port();
    let jport = free_port();

    let fdata = tmp.path().join("f-data");
    let fdata = fdata.to_string_lossy();
    let fid = tmp.path().join("f-id");
    let fid = fid.to_string_lossy();
    let jdata = tmp.path().join("j-data");
    let jdata = jdata.to_string_lossy();
    let jid = tmp.path().join("j-id");
    let jid = jid.to_string_lossy();

    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = format!("127.0.0.1:{fport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");

    // ── 1. Boot founder (owner) then joiner (DiscoverZones) ────────────
    let mut founder = Daemon::spawn(
        &["--bind-addr", &fbind],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_tcp(fport, BUDGET)
        .await
        .expect("founder serves");
    // Gate the joiner's boot on the founder having REGISTERED sharedzone.
    // readdir/stat on the /agents mount point don't distinguish a live
    // federation mount from a root-served empty path (readdir returns non-error
    // for any path; stat returns not-found for a mount point), so probing them
    // lets the joiner boot early and its DiscoverZones race — and lose to —
    // this registration, leaving it rootless (it does not retry) so nothing
    // ever replicates. The zone-registration log line is the reliable signal.
    let zone_registered = format!("Zone '{ZONE}' registered");
    founder
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("founder must register sharedzone");
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner.wait_tcp(jport, BUDGET).await.expect("joiner serves");
    // The joiner joins sharedzone via DiscoverZones; wait until it has actually
    // registered the zone (joined), not come up rootless.
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner must join sharedzone");
    let mut jc = Vfs::dial(jport).await.expect("dial joiner");

    // ── 2. Federation health — founder writes, joiner reads back ───────
    let health = format!("{MOUNT}/health-founder.txt");
    let payload = b"federation-health-probe-v1";
    fc.write_file(&health, payload, "")
        .await
        .expect("founder write");
    await_replicated(&mut jc, &health, "", BUDGET).await;
    let got = jc.read_file(&health, "").await.expect("joiner read");
    assert_eq!(got, payload, "joiner must read the founder's bytes back");

    // ── 3-7. A2A: joiner owns mailbox, founder (peer) sends ────────────
    mailbox_round(jport, fport, "founder", "joiner-ai").await;

    // ── 8. Reverse: founder owns mailbox, joiner (peer) sends ──────────
    mailbox_round(fport, jport, "joiner", "founder-ai").await;

    // ── 9. Honest mount: kill the leader; a write with no quorum FAILS ─
    // The founder is a voter; killing it leaves the 2-voter zone without a
    // majority, so the survivor has no leader to commit through. A wal
    // DT_STREAM write must FAIL rather than silently accept bytes it can never
    // replicate — the `write_sync` durability contract (the mount must not lie).
    drop(founder);
    tokio::time::sleep(Duration::from_secs(2)).await; // let the survivor observe the loss
    let leaderless = jc
        .stream_write(
            &format!("{MOUNT}/founder-ai/chat-with-me"),
            b"{\"from\":\"probe\"}",
            "",
        )
        .await;
    assert!(
        leaderless.is_err(),
        "a wal-stream write with no leader MUST fail loud, not silently accept undeliverable bytes"
    );
}
