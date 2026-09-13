//! Regression gate for #276: a client that talks to `nexusd-cluster` the
//! INSTANT its port accepts must never be answered by a half-wired kernel.
//!
//! The daemon binds early by necessity — the port is the raft data plane and
//! peers must reach it to form the cluster at all — and the VFS service is
//! co-hosted on that same port. So there is a window in which client requests
//! arrive before boot has installed the DistributedCoordinator. Served in that
//! window, a `wal` DT_STREAM (an A2A mailbox) found no zone metastore, fell
//! through its io_profile waterfall to a node-local memory ring of capacity 0,
//! and became a black hole: `create` succeeded, `write` reported offset 0, and
//! every read came back `EMPTY (eof=true, next_offset=0)` forever. Two green
//! RPCs, one lost message, no error anywhere. It reproduced as "flaky CI" —
//! the window is wide exactly when the machine is loaded.
//!
//! This test does the one thing every other e2e test avoids: it waits for the
//! TCP port and NOTHING else, then immediately round-trips a mailbox. The
//! invariant is not "it is fast" but "a reported success is true" — if the
//! create and the append both report success, the frame MUST read back.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs};

const ZONE: &str = "sharedzone";
const BUDGET: Duration = Duration::from_secs(90);
const ENVELOPE: &[u8] = br#"{"from":"win-ai","to":"mac-ai","body":"PING"}"#;

/// Provision a DT_STREAM mailbox, append one envelope, read it back at 0.
/// Every step is asserted to report honestly: the payload comes back, or a
/// step fails loudly. A success that reads back empty is the bug.
async fn mailbox_roundtrip(vfs: &mut Vfs, inbox: &str) {
    vfs.create_stream(inbox, "")
        .await
        .unwrap_or_else(|e| panic!("create_stream({inbox}) in the boot window: {e}"));
    vfs.stream_write(inbox, ENVELOPE, "")
        .await
        .unwrap_or_else(|e| panic!("stream_write({inbox}) in the boot window: {e}"));
    let out = vfs
        .stream_read_at(inbox, 0, "")
        .await
        .unwrap_or_else(|e| panic!("stream_read_at({inbox}) transport: {e}"));
    assert!(
        !out.is_error,
        "stream_read_at({inbox}) kernel error: {:?}",
        out.error_payload
    );
    assert_eq!(
        out.data, ENVELOPE,
        "REGRESSED #276: create + append both reported SUCCESS at {inbox}, but the \
         mailbox reads back empty (eof={}, next_offset={}) — the append was served by \
         a kernel that had no distributed coordinator yet",
        out.eof, out.next_offset
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mailbox_written_the_instant_the_port_opens_reads_back() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let id = tmp.path().join("id");
    let id = id.to_string_lossy();
    let adv = format!("127.0.0.1:{port}");
    let bind = adv.clone();
    let mounts = format!("/agents={ZONE}");
    let env = vec![
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("RUST_LOG", "info,h2=warn,hyper=warn,tower=warn,tonic=warn"),
    ];

    let mut founder = Daemon::spawn(&["--bind-addr", &bind], &env);
    // The earliest moment a client can exist. Deliberately NO `wait_for_log`:
    // every boot marker this test could wait for is logged BEFORE the kernel
    // is fully wired, which is precisely what made #276 look like flakiness.
    founder
        .wait_tcp(port, BUDGET)
        .await
        .expect("founder serves");
    let mut vfs = Vfs::dial_ready(port, BUDGET).await;

    // Root zone (the #276 control) and the federation mount, both from inside
    // the boot window.
    mailbox_roundtrip(&mut vfs, "/rootlocal/mac-ai/chat-with-me").await;
    mailbox_roundtrip(&mut vfs, "/agents/mac-ai/chat-with-me").await;

    assert!(
        founder.log_contains("VFS data plane ready"),
        "the daemon must announce when the data plane opened:\n{}",
        founder.drain()
    );
}
