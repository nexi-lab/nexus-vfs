//! Anti-entropy snapshot catch-up (L3b) — a peer that joins behind the
//! compacted EC WAL region converges via a `SnapshotEcState` transfer, not
//! incremental replay.
//!
//! This is the drain-trigger half of the EC-drain hardening: `spawn_ec_replications`
//! detects a peer whose next-needed seq was compacted away (`needs_snapshot`),
//! re-materializes the full EC state as idempotent commands — metadata as
//! `SetMetadata`, STREAM entries as `AppendStreamEntry` — and ships it over
//! `SnapshotEcState`.  The receiver applies each via `apply_ec_from_peer`
//! (LWW / union) and catches up to state that no longer exists in any WAL.
//!
//! Covers BOTH payload types: a metadata key AND a stream entry (an A2A
//! message) must survive compaction and reach a late learner via the snapshot.
//! Stream entries live in a separate tree from metadata, so a metadata-only
//! snapshot (pre-Piece-5a) would silently drop them — breaking the AP delivery
//! promise for the mailbox payload.
//!
//! Topology / method:
//!   1. Founder bootstraps a 1-voter `sharedzone` and self-elects.
//!   2. Learner A joins — its presence lets the founder's drain run compaction
//!      (the drain skips compaction when it has no peers).
//!   3. Founder writes N EC entries.  With `NEXUS_EC_WAL_RETENTION=2` the
//!      retention floor (`max_seq - 2`) compacts the WAL past seq 1 on the
//!      first post-write drain tick.  `/snap/0` lands at seq 1.
//!   4. Barrier: assert the founder's WAL `earliest > 1` (seq 1 is gone), so
//!      `/snap/0` is provably unreachable by incremental replay.
//!   5. Learner B joins LATE (acked_seq=0, next-needed seq 1 < earliest).  The
//!      only path that can deliver `/snap/0` to B is an anti-entropy snapshot.
//!   6. Assert B converges to the FULL state — `/snap/0` (snapshot-only) and
//!      the newest key.
//!
//! Must fail if the `needs_snapshot` branch skips (the pre-L3b "not yet
//! implemented" behavior): B never receives `/snap/0`.

#![cfg(all(feature = "grpc", has_protos))]

use std::time::Duration;

use nexus_raft::prelude::Command;
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::ZoneManager;
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

fn mint_random_id() -> u64 {
    let id = rand::random::<u64>();
    if id == 0 {
        1
    } else {
        id
    }
}

fn write_node_id(dir: &std::path::Path, id: u64) {
    std::fs::create_dir_all(dir).expect("create dir");
    std::fs::write(dir.join(NODE_ID_FILE), id.to_be_bytes()).expect("write .node_id");
}

async fn make_node(node_id: u64, dir: &std::path::Path) -> (std::sync::Arc<ZoneManager>, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    let bind_str = format!("{}", addr);

    let zm = ZoneManager::with_node_id(
        "test-host",
        node_id,
        dir.to_str().expect("utf-8"),
        vec![],
        &bind_str,
        None,
        Some(format!("http://{bind_str}")),
        None,
    )
    .expect("ZoneManager");
    (zm, bind_str)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_ec_snapshot_catchup_late_learner_behind_compacted_wal() {
    // Force a tiny WAL retention so a handful of writes compact past a lagging
    // peer, exercising the anti-entropy snapshot path deterministically (the
    // 10k default would need 10k writes to reach compaction).  This is the
    // test binary's own process, so the env var cannot race other integration
    // test binaries.
    std::env::set_var("NEXUS_EC_WAL_RETENTION", "2");

    let dir_founder = TempDir::new().expect("dir-founder");
    let dir_a = TempDir::new().expect("dir-a");
    let dir_b = TempDir::new().expect("dir-b");

    let id_founder = mint_random_id();
    let id_a = mint_random_id();
    let id_b = mint_random_id();
    assert!(
        id_founder != id_a && id_a != id_b && id_founder != id_b,
        "three random mints must differ"
    );
    write_node_id(dir_founder.path(), id_founder);
    write_node_id(dir_a.path(), id_a);
    write_node_id(dir_b.path(), id_b);

    let (zm_founder, bind_founder) = make_node(id_founder, dir_founder.path()).await;
    let (zm_a, bind_a) = make_node(id_a, dir_a.path()).await;
    let (zm_b, bind_b) = make_node(id_b, dir_b.path()).await;

    // Founder: 1-voter sharedzone.  Self-elects (quorum=1).
    let zone_founder = zm_founder
        .create_zone("sharedzone", vec![format!("{id_founder}@{bind_founder}")])
        .expect("create sharedzone");
    for _ in 0..100 {
        if zone_founder.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(zone_founder.is_leader(), "founder must self-elect");

    let endpoint_founder = format!("http://{bind_founder}");

    // Learner A joins — its presence lets the founder's drain reach compaction.
    let _zone_a = zm_a
        .join_zone(
            "sharedzone",
            vec![format!("{id_founder}@{bind_founder}")],
            /* learner */ true,
        )
        .expect("A local join_zone(learner)");
    let ja = call_join_zone_rpc(
        &endpoint_founder,
        "sharedzone",
        id_a,
        &format!("http://{bind_a}"),
        /* as_learner */ true,
        None,
        30,
    )
    .await
    .expect("A JoinZone RPC");
    assert!(ja.success, "A JoinZone must succeed: {:?}", ja.error);

    // Wait for A to be visible in the founder's applied config.
    for _ in 0..50 {
        if zm_founder.cluster_status("sharedzone").applied_index >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let founder_consensus = zone_founder.consensus_node();

    // Append an EC STREAM entry (an A2A message) FIRST, at the earliest seq, so
    // it is compacted away and reachable ONLY via snapshot. It lives in the
    // separate stream_entries tree — a metadata-only snapshot would drop it.
    let stream_key = "__wal_stream__/agents/win-ai/chat-with-me/0";
    founder_consensus
        .propose_ec_local(Command::AppendStreamEntry {
            key: stream_key.to_string(),
            data: b"ec-msg-0".to_vec(),
        })
        .await
        .expect("propose_ec_local(AppendStreamEntry) failed");

    // Write N EC metadata entries.  /snap/0 lands right after the stream entry.
    const N: usize = 16;
    for i in 0..N {
        founder_consensus
            .propose_ec_local(Command::SetMetadata {
                key: format!("/snap/{i}"),
                value: format!("v{i}").into_bytes(),
            })
            .await
            .unwrap_or_else(|e| panic!("propose_ec_local(/snap/{i}) failed: {e:?}"));
    }

    // Barrier: wait until the founder's WAL has FULLY compacted (earliest ==
    // max_seq ⇒ zero unreplicated entries) BEFORE B joins. This makes the test
    // deterministically exercise BOTH fixes in one shot:
    //   1. /snap/0 (seq 1) is compacted away ⇒ reachable only via snapshot; and
    //   2. B joins into an IDLE drain (no fresh entries), so the anti-entropy
    //      dispatch fires only because the early-return-on-empty guard now
    //      yields to a lagging peer instead of returning. Without either fix B
    //      never receives /snap/0.
    // Compaction is monotonic + retention-floored, so once emptied it stays
    // emptied even as B (acked=0) enters the peer set.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let (mut earliest, mut max) = (1u64, 0u64);
    while std::time::Instant::now() < deadline {
        if let Some((e, m)) = founder_consensus.ec_wal_bounds() {
            (earliest, max) = (e, m);
            if earliest >= max && earliest > 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        earliest >= max && earliest > 1,
        "founder WAL must fully compact past seq 1 before B joins (idle drain, \
         /snap/0 snapshot-only) — earliest={earliest} max={max}"
    );

    // Learner B joins LATE — fresh (acked_seq=0), so its next-needed seq (1) is
    // below the founder's earliest.  Incremental replay is impossible; only an
    // anti-entropy snapshot can deliver the compacted keys.
    let _zone_b = zm_b
        .join_zone(
            "sharedzone",
            vec![format!("{id_founder}@{bind_founder}")],
            /* learner */ true,
        )
        .expect("B local join_zone(learner)");
    let jb = call_join_zone_rpc(
        &endpoint_founder,
        "sharedzone",
        id_b,
        &format!("http://{bind_b}"),
        /* as_learner */ true,
        None,
        30,
    )
    .await
    .expect("B JoinZone RPC");
    assert!(jb.success, "B JoinZone must succeed: {:?}", jb.error);

    let zone_b = zm_b.get_zone("sharedzone").expect("B ZoneHandle");
    let b_consensus = zone_b.consensus_node();

    // B must converge to the FULL state: /snap/0 (seq 1, compacted from the
    // founder WAL — snapshot-only) and the newest key /snap/{N-1}.
    let last_key = format!("/snap/{}", N - 1);
    let last_val = format!("v{}", N - 1).into_bytes();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut have_first = false;
    let mut have_last = false;
    let mut have_stream = false;
    while std::time::Instant::now() < deadline {
        let (first, last, stream) = b_consensus
            .with_state_machine(|sm| {
                let f = sm.get_metadata("/snap/0").ok().flatten();
                let l = sm.get_metadata(&last_key).ok().flatten();
                let s = sm.get_stream_entry(stream_key).ok().flatten();
                (f, l, s)
            })
            .await;
        have_first = first.as_deref() == Some(b"v0".as_ref());
        have_last = last.as_deref() == Some(last_val.as_slice());
        have_stream = stream.as_deref() == Some(b"ec-msg-0".as_ref());
        if have_first && have_last && have_stream {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        have_first,
        "learner B must receive /snap/0 (compacted from the founder WAL) \
         via an anti-entropy snapshot — this is the L3b drain-trigger under test"
    );
    assert!(
        have_last,
        "learner B must also converge to the newest key {last_key}"
    );
    assert!(
        have_stream,
        "learner B must receive the compacted STREAM entry {stream_key} via the \
         snapshot too (Piece 5a) — a metadata-only snapshot drops A2A messages, \
         breaking the mailbox's AP delivery promise"
    );
}
