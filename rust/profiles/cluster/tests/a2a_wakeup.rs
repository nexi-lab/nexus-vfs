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
//! `agent_signed_authorship`. The journey, each step consuming the last:
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

/// One real A2A direction: `agent` owns the mailbox on `owner_port`; a `sender`
/// peer that never created it opens + writes it; the owner's parked Watch wakes
/// and it reads the envelope back.
async fn mailbox_round(owner_port: u16, sender_port: u16, sender_name: &str, agent: &str) {
    let mailbox = format!("{MOUNT}/{agent}/chat-with-me");
    let envelope =
        format!(r#"{{"from":"{sender_name}","to":"{agent}","body":"ping from {sender_name}"}}"#);

    let mut owner = Vfs::dial_ready(owner_port, BUDGET).await;
    let mut sender = Vfs::dial_ready(sender_port, BUDGET).await;

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
        let mut w = Vfs::dial_ready(owner_port, BUDGET).await;
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

/// Boot a founder (owns `ZONE` at `MOUNT`) + a joiner (DiscoverZones), both
/// auth-off loopback, blocking until BOTH have REGISTERED `ZONE`. Returns the
/// live daemons + dialed clients + ports; the caller keeps the daemons alive
/// (dropping a `Daemon` kills it) and keeps `tmp` alive for the data dirs.
///
/// The joiner's boot-time DiscoverZones reads the founder's DT_MOUNT entries
/// from the ROOT state machine, so it must not spawn until those entries have
/// committed there. The founder's `Zone '…' registered` log fires earlier — at
/// zone-node registration, before the mount's raft apply into root — so gating
/// the joiner on it alone races the root apply: the joiner's one-shot
/// DiscoverZones reads 0 entries and stays rootless (it does not retry) and
/// nothing replicates. The reliable discoverable signal is the founder's
/// `Static topology applied` log, which fires once every mount has committed.
async fn boot_federation(tmp: &std::path::Path) -> (Daemon, Daemon, Vfs, Vfs, u16, u16) {
    let fport = free_port();
    let jport = free_port();
    let fdata = tmp.join("f-data");
    let fdata = fdata.to_string_lossy();
    let fid = tmp.join("f-id");
    let fid = fid.to_string_lossy();
    let jdata = tmp.join("j-data");
    let jdata = jdata.to_string_lossy();
    let jid = tmp.join("j-id");
    let jid = jid.to_string_lossy();

    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = format!("127.0.0.1:{fport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let zone_registered = format!("Zone '{ZONE}' registered");

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
        .expect("founder must register sharedzone");
    // A federation mount is discoverable (visible to a joiner's DiscoverZones)
    // only once its DT_MOUNT entry commits into the ROOT state machine — a raft
    // apply that lags the zone-registry "registered" log above. Gating the
    // joiner on that log alone races the root apply: the joiner boots one-shot
    // rootless, its DiscoverZones reads 0 DT_MOUNT entries, and it never
    // retries. Wait for the topology-applied signal, which fires once every
    // mount has committed into root.
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder must apply federation topology (zone discoverable)");
    let fc = Vfs::dial_ready(fport, BUDGET).await;

    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jbind],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner.wait_tcp(jport, BUDGET).await.expect("joiner serves");
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner must join sharedzone");
    let jc = Vfs::dial_ready(jport, BUDGET).await;

    (founder, joiner, fc, jc, fport, jport)
}

/// Cross-machine COLD read: a wal DT_STREAM created + written on the founder
/// must be readable on the joiner with a bare `stream_collect_all` — NO prior
/// `create_stream`/`setattr` and NO `watch` on the joiner to materialize it.
///
/// Regression guard for the A2A mailbox cold-read gap: the DT_STREAM inode +
/// entries replicate via raft, but a replica's local `StreamManager` handle is
/// only built on an explicit open. Reads used to miss (`StreamNotFound`) until
/// something setattr'd/armed a watch first — so "messages are always there,
/// read them any time" did NOT hold cross-node. `Kernel::arm_stream_materializer`
/// closes it by resolving-or-materializing through the single `StreamManager`
/// chokepoint. This mirrors the live Win↔Mac bug exactly (peer wrote, reader
/// cold-collected). Distinct from `mailbox_round`, whose reader opens/arms first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_collect_reads_a_peer_created_wal_stream_without_open_or_watch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_founder, _joiner, mut fc, mut jc, _fport, _jport) = boot_federation(tmp.path()).await;

    // Founder creates a wal DT_STREAM (NOT a chat-with-me, so no stamp envelope
    // wraps the payload — a clean exact-bytes assertion) and writes one frame.
    let probe = format!("{MOUNT}/cold-probe");
    fc.create_stream(&probe, "")
        .await
        .expect("founder creates wal stream");
    fc.stream_write(&probe, b"hello-cold", "")
        .await
        .expect("founder writes frame");

    // Joiner reads it COLD — no create_stream, no watch. Poll only for raft
    // replication timing (inode + entry apply), never re-opening the stream.
    let deadline = std::time::Instant::now() + BUDGET;
    let got = loop {
        match jc.stream_collect_all(&probe, "").await {
            Ok(bytes) if bytes == b"hello-cold" => break bytes,
            _ if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            other => panic!(
                "cold stream_collect_all never returned the peer's bytes \
                 (materialize-on-read regressed): last = {other:?}"
            ),
        }
    };
    assert_eq!(got, b"hello-cold");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mailbox_write_wakes_a_peers_parked_sys_watch_both_directions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // `founder` is dropped in step 9 (kill-leader); `_joiner` just stays alive.
    let (founder, _joiner, mut fc, mut jc, fport, jport) = boot_federation(tmp.path()).await;

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
