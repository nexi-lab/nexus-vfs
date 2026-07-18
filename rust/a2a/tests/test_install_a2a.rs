//! `install_a2a` composes the two A2A guarantees onto a live cluster:
//! the cross-machine stream-wakeup observer AND the mailbox `from`-stamp
//! hook, in one boot call.
//!
//! The raw stream-wakeup mechanism (and its negative control — apply
//! alone does NOT wake without the observer) is proven in the raft
//! crate's `test_stream_wakeup_replication`. This test proves the
//! composition the profile binary actually calls at boot:
//!
//!   1. **Cross-machine wake.** A real two-node cluster (founder +
//!      learner, same shape as the §A test) with a real `kernel::Kernel`
//!      on the joiner. After `install_a2a` arms the joiner, a
//!      `AppendStreamEntry` proposed on the founder replicates in and
//!      wakes a `sys_watch` parked on the joiner.
//!   2. **Unforgeable `from`.** The same `install_a2a` call registered
//!      the stamp hook on the joiner's kernel. A chat-with-me write
//!      carrying a caller `agent_id` — dispatched through the exact
//!      `dispatch_native_pre_with_replacement` seam `sys_write` uses —
//!      comes back with its envelope `from` rewritten to the caller,
//!      regardless of what the payload claimed.
//!
//! Gated on the `install` feature (the only configuration in which
//! `install_a2a` and the raft dev-dep exist).

#![cfg(feature = "install")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use kernel::core::dispatch::{HookContext, HookIdentity, WriteHookCtx};
use kernel::kernel::Kernel;
use nexus_raft::prelude::{Command, CommandResult, FullStateMachine};
use nexus_raft::transport::call_join_zone_rpc;
use nexus_raft::{ZoneHandle, ZoneManager};
use tempfile::TempDir;

const NODE_ID_FILE: &str = ".node_id";

/// Poll budget for a committed entry to reach the learner's state
/// machine. Generous on purpose so a slow CI box does not flake a real
/// replication assertion.
const REPLICATION_BUDGET: Duration = Duration::from_secs(5);

/// Ceiling for the positive watcher — should wake in well under a second
/// once the observer is armed; this is only a backstop so a broken wake
/// path fails as a timeout rather than hanging the test.
const WATCH_MS: u64 = 15_000;

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
/// `want`, or the budget expires.
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

/// Park a blocking `sys_watch` off the tokio worker pool so it can't
/// starve the runtime. Returns the woken event's path, or `None` on
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
async fn install_a2a_arms_wakeup_and_stamp_hook() {
    let dir_founder = TempDir::new().expect("dir-founder");
    let dir_joiner = TempDir::new().expect("dir-joiner");

    let id_founder = mint_random_id();
    let id_joiner = mint_random_id();
    assert_ne!(id_founder, id_joiner, "two random mints must differ");
    write_node_id(dir_founder.path(), id_founder);
    write_node_id(dir_joiner.path(), id_joiner);

    let (zm_founder, bind_founder) = make_node(id_founder, dir_founder.path()).await;
    let (zm_joiner, bind_joiner) = make_node(id_joiner, dir_joiner.path()).await;

    // ── Cluster: founder self-elects on a 1-voter zone ───────────────
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

    let endpoint_joiner = format!("http://{bind_joiner}");
    let _zone_joiner_local = zm_joiner
        .join_zone(
            "sharedzone",
            vec![format!("{id_founder}@{bind_founder}")],
            /* learner */ true,
        )
        .expect("local join_zone(learner) on joiner");

    let join_resp = call_join_zone_rpc(
        &format!("http://{bind_founder}"),
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

    // The replica's kernel — a real, standalone `kernel::Kernel`, wired
    // to the cluster ONLY through `install_a2a` below.
    let kernel_joiner = Arc::new(Kernel::new());

    // One boot call arms BOTH guarantees on the joiner: the stamp hook
    // (on the kernel) and the stream-wakeup observer (on the consensus).
    a2a::install_a2a(&kernel_joiner, &zone_joiner.consensus_node())
        .expect("install_a2a on the joiner");

    // ── Guarantee 1 — cross-machine wake ─────────────────────────────
    let watch_path = "/agents/win-ai/chat-with-me";
    let data = b"a2a-payload".to_vec();

    let watcher = park_watch(Arc::clone(&kernel_joiner), watch_path, WATCH_MS);
    // Give the blocking watcher time to actually park on the condvar
    // before the write lands (a notify racing registration is
    // inbox-buffered, but one strictly before registration is missed).
    tokio::time::sleep(Duration::from_millis(150)).await;

    append_on_founder(&zone_founder, watch_path, &data).await;

    // The entry really did replicate + apply on the joiner, so a wake
    // below is about the wake path, not a missing write.
    assert_eq!(
        await_stream(&zone_joiner, watch_path, Some(&data)).await,
        Some(data.clone()),
        "the AppendStreamEntry must apply on the joiner's state machine"
    );

    let woke = watcher.await.expect("watcher task");
    assert_eq!(
        woke.as_deref(),
        Some(watch_path),
        "install_a2a must arm the observer so a replicated AppendStreamEntry \
         wakes the parked sys_watch on the replica"
    );

    // ── Guarantee 2 — unforgeable `from` (stamp hook in dispatch) ─────
    // The same install_a2a call registered the stamp hook. Drive the
    // exact pre-write seam sys_write uses: a chat-with-me write whose
    // payload lies about its sender must come back stamped to the real
    // caller `agent_id`.
    let ctx = HookContext::Write(WriteHookCtx {
        path: watch_path.to_string(),
        identity: HookIdentity {
            user_id: "operator".to_string(),
            zone_id: "root".to_string(),
            agent_id: "win-ai".to_string(),
            is_admin: false,
        },
        content: br#"{"from":"impostor","to":"mac-ai","body":"hi"}"#.to_vec(),
        is_new_file: false,
        content_id: None,
        new_version: 0,
        size_bytes: None,
    });
    let replacement = kernel_joiner
        .dispatch_native_pre_with_replacement(&ctx)
        .expect("stamp hook must accept the chat-with-me write")
        .expect("stamp hook must REPLACE the envelope (from was forged)");
    let envelope: serde_json::Value =
        serde_json::from_slice(&replacement).expect("stamped envelope is valid JSON");
    assert_eq!(
        envelope.get("from").and_then(|v| v.as_str()),
        Some("win-ai"),
        "install_a2a's stamp hook must rewrite `from` to the caller agent_id"
    );

    // ── Durability — the payload outlives its sender ─────────────────
    drop(zone_founder);
    drop(zm_founder);
    let reread = zone_joiner
        .consensus_node()
        .with_state_machine({
            let k = watch_path.to_string();
            move |sm: &FullStateMachine| sm.get_stream_entry(&k)
        })
        .await
        .expect("re-read stream entry on the joiner after the founder is gone");
    assert_eq!(
        reread,
        Some(data),
        "the replica must still serve the DT_STREAM payload after the sender is dropped"
    );
}
