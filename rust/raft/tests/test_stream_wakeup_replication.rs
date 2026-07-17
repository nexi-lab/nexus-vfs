//! A replicated `AppendStreamEntry` wakes a `sys_watch` parked on a replica
//! — but only once the apply-side wakeup observer is armed.
//!
//! This is the ONE unknown the whole A2A design rests on. On the node that
//! runs the write, `Kernel::dispatch_observers` fires the file-watch wake
//! inline. On a **replica** the mutation arrives over the raft log and is
//! materialised by the apply loop, which never touches the kernel's
//! `FileWatchRegistry` — so a parked `sys_watch` there does not wake on its
//! own. `stream_wakeup::install_stream_wakeup_observer` is the missing
//! subscriber that closes that gap by riding the unified apply-observer
//! spine. This test proves both halves of that claim over a real two-node
//! cluster with a real `kernel::Kernel` on the joiner.
//!
//! Topology (same shape as `test_auth_key_replication`):
//!   * Founder bootstraps a 1-voter `sharedzone` and self-elects leader.
//!   * Joiner enters as a Learner over a real `JoinZone` gRPC call.
//!
//! The journey — three phases, each consuming the previous phase's state:
//!   1. **Negative control (no observer).** The founder proposes an
//!      `AppendStreamEntry`; the joiner's state machine applies it (proven
//!      by a direct read), yet a `sys_watch` parked on the joiner across
//!      that apply must **time out**. This is the diagnosis: apply alone
//!      does not wake a parked watcher on a replica.
//!   2. **Positive (observer armed).** Register the wakeup observer on the
//!      joiner's consensus, park a fresh `sys_watch`, and have the founder
//!      propose to that key. The parked watcher must **wake** and report
//!      the watched path — the replicated apply now reaches the kernel's
//!      wake primitive.
//!   3. **Durability.** Drop the founder entirely, then re-read the stream
//!      payload off the joiner's own applied log. It must still be there:
//!      the message is in the raft log, so it outlives its sender.
//!
//! If phase 1 ever *wakes* without the observer, the whole `stream_wakeup`
//! module is unnecessary and should be deleted — the test is the judge.

#![cfg(all(feature = "grpc", has_protos))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use kernel::kernel::Kernel;
use nexus_raft::prelude::{Command, CommandResult, FullStateMachine};
use nexus_raft::stream_wakeup::install_stream_wakeup_observer;
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::{ZoneHandle, ZoneManager};
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

/// Poll budget for a committed entry to reach the learner's state machine.
/// Generous on purpose: on a healthy localhost transport this resolves in
/// well under a second, and a slow CI box should not turn a real
/// replication assertion into a flake.
const REPLICATION_BUDGET: Duration = Duration::from_secs(5);

/// How long the phase-1 negative-control watcher stays parked. Kept
/// strictly larger than [`REPLICATION_BUDGET`] so the entry is guaranteed
/// to apply while the watcher is still blocked — otherwise a "did not wake"
/// would be vacuous (the watcher could have timed out before the entry ever
/// arrived). We confirm the apply within the budget, then let the watcher
/// run out its remaining time.
const PHASE1_WATCH_MS: u64 = 6_000;

/// Ceiling for the phase-2 positive watcher. It should wake in well under a
/// second once the observer is armed; this is only a backstop so a broken
/// wake path fails as a timeout rather than hanging the test.
const PHASE2_WATCH_MS: u64 = 15_000;

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

async fn make_node(node_id: u64, dir: &std::path::Path) -> (Arc<ZoneManager>, String) {
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

/// Poll the joiner's state machine until `get_stream_entry(key)` matches
/// `want`, or the budget expires. Returns what was last observed so a
/// failure can say what it actually saw rather than just "timed out".
async fn await_stream(zone: &ZoneHandle, key: &str, want: Option<&[u8]>) -> Option<Vec<u8>> {
    let deadline = Instant::now() + REPLICATION_BUDGET;
    let mut last = None;
    while Instant::now() < deadline {
        let k = key.to_string();
        last = zone
            .consensus_node()
            .with_state_machine(move |sm: &FullStateMachine| sm.get_stream_entry(&k))
            .await
            .expect("joiner get_stream_entry");
        if last.as_deref() == want {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last
}

/// Park a blocking `sys_watch` on `path` off the tokio worker pool so it
/// can't starve the runtime. Returns the woken event's path, or `None` on
/// timeout.
fn park_watch(
    kernel: Arc<Kernel>,
    path: &str,
    timeout_ms: u64,
) -> tokio::task::JoinHandle<Option<String>> {
    let path = path.to_string();
    tokio::task::spawn_blocking(move || {
        kernel
            .sys_watch(&path, timeout_ms)
            .map(|event| event.path().to_string())
    })
}

/// Propose an `AppendStreamEntry` on the founder and assert the cluster did
/// not reject it.
async fn append_on_founder(founder: &ZoneHandle, key: &str, data: &[u8]) {
    let result = founder
        .consensus_node()
        .propose(Command::AppendStreamEntry {
            key: key.to_string(),
            data: data.to_vec(),
        })
        .await
        .expect("founder propose AppendStreamEntry");
    assert!(
        !matches!(result, CommandResult::Error(_)),
        "founder rejected AppendStreamEntry for {key}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_stream_append_wakes_a_parked_watch_only_with_the_observer() {
    let dir_founder = TempDir::new().expect("dir-founder");
    let dir_joiner = TempDir::new().expect("dir-joiner");

    let id_founder = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_founder, id_joiner, "two random mints must differ");
    write_node_id(dir_founder.path(), id_founder);
    write_node_id(dir_joiner.path(), id_joiner);

    let (zm_founder, bind_founder) = make_node(id_founder, dir_founder.path()).await;
    let (zm_joiner, bind_joiner) = make_node(id_joiner, dir_joiner.path()).await;

    // ── Cluster: founder self-elects on a 1-voter zone ───────────────────
    let zone_founder = zm_founder
        .create_zone("sharedzone", vec![format!("{id_founder}@{bind_founder}")])
        .expect("create sharedzone on founder");
    for _ in 0..100 {
        if zone_founder.is_leader() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        zone_founder.is_leader(),
        "founder must self-elect on 1-voter create"
    );

    let endpoint_founder = format!("http://{bind_founder}");
    let endpoint_joiner = format!("http://{bind_joiner}");

    let _zone_joiner_local = zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_founder}@{bind_founder}")],
            /* learner */ true,
        )
        .expect("local join_zone(learner) on joiner");

    let join_resp = call_join_zone_rpc(
        &endpoint_founder,
        "sharedzone",
        id_joiner,
        &endpoint_joiner,
        /* as_learner */ true,
        None,
        30,
    )
    .await
    .expect("JoinZone RPC");
    assert!(
        join_resp.success,
        "JoinZone(learner) must succeed: {:?}",
        join_resp.error
    );

    for _ in 0..50 {
        if zm_founder.cluster_status("sharedzone").applied_index >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let zone_joiner = zm_joiner
        .get_zone("sharedzone")
        .expect("joiner must hold a ZoneHandle for sharedzone");

    // The replica's kernel — a real, standalone `kernel::Kernel`. Its
    // `FileWatchRegistry` is what `sys_watch` parks on and what the wakeup
    // observer must reach. It is deliberately NOT wired to the cluster
    // except through the observer we register in phase 2.
    let kernel_joiner = Arc::new(Kernel::new());

    // ── Phase 1 — negative control: no observer, no wake ─────────────────
    // Park a watcher on the joiner across a replicated apply. The entry
    // must reach the joiner's state machine (proven by `await_stream`), yet
    // the watcher must still time out — apply alone does not wake it.
    let watch_path_1 = "/agents/win-ai/chat-with-me";
    let data_1 = b"phase-1-no-observer".to_vec();

    let watcher_1 = park_watch(Arc::clone(&kernel_joiner), watch_path_1, PHASE1_WATCH_MS);
    // Give the blocking watcher time to actually park on the condvar before
    // the write lands — a notify that races registration is inbox-buffered,
    // but a notify strictly before registration would be missed.
    tokio::time::sleep(Duration::from_millis(150)).await;

    append_on_founder(&zone_founder, watch_path_1, &data_1).await;

    // The entry really did replicate and apply on the joiner — so a
    // "did not wake" below is about the wake path, not a missing write.
    assert_eq!(
        await_stream(&zone_joiner, watch_path_1, Some(&data_1)).await,
        Some(data_1.clone()),
        "the AppendStreamEntry must apply on the joiner's state machine"
    );

    let woke_1 = watcher_1.await.expect("phase-1 watcher task");
    assert_eq!(
        woke_1, None,
        "without the wakeup observer, a replicated AppendStreamEntry must NOT wake a parked sys_watch on the replica"
    );

    // ── Phase 2 — arm the observer; now the same apply must wake ─────────
    // §A identity translation: the test controls the stream key, so the
    // watched path is the key verbatim (§F supplies the real
    // zone-relative → mailbox-path mapping).
    install_stream_wakeup_observer(
        &zone_joiner.consensus_node(),
        Arc::downgrade(&kernel_joiner),
        |key: &str| key.to_string(),
    );

    let watch_path_2 = "/agents/win-ai/inbox";
    let data_2 = b"phase-2-observer-armed".to_vec();

    let watcher_2 = park_watch(Arc::clone(&kernel_joiner), watch_path_2, PHASE2_WATCH_MS);
    tokio::time::sleep(Duration::from_millis(150)).await;

    append_on_founder(&zone_founder, watch_path_2, &data_2).await;

    let woke_2 = watcher_2.await.expect("phase-2 watcher task");
    assert_eq!(
        woke_2.as_deref(),
        Some(watch_path_2),
        "with the observer armed, the replicated AppendStreamEntry must wake the parked sys_watch on the replica"
    );

    // ── Phase 3 — durability: the payload outlives its sender ────────────
    // Drop the founder entirely. The joiner's applied log still holds the
    // DT_STREAM payload — a message stays readable when its sender is gone,
    // which is the whole reason A2A rides the raft log rather than an
    // on-demand file fetch.
    drop(zone_founder);
    drop(zm_founder);

    let reread = zone_joiner
        .consensus_node()
        .with_state_machine({
            let k = watch_path_2.to_string();
            move |sm: &FullStateMachine| sm.get_stream_entry(&k)
        })
        .await
        .expect("re-read stream entry on the joiner after the founder is gone");
    assert_eq!(
        reread,
        Some(data_2),
        "the replica must still serve the DT_STREAM payload after the sender is dropped"
    );
}
