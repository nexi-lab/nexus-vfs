//! Black-box E2E: an A2A `from` is UNFORGEABLE on the loopback local-agent
//! bind (`--agent-bind-addr`), when auth is on.
//!
//! Spawns the real `nexusd-cluster` binary wired like an Option-X federation
//! node: the token plane on (`NEXUS_API_KEY_SECRET`), `/agents` federated, and
//! a SEPARATE loopback `--agent-bind-addr` for the local agent. mTLS ⊥ token —
//! the two identity planes live on separate binds by audience (auth-doc
//! §3.1 / §4.1); this test drives the token/agent one.
//!
//! It is the auth-ON, over-the-wire complement to the in-process
//! `a2a::stamps_from_on_the_stream_write_path` unit test: it proves the whole
//! gRPC `authenticate → agent_id → sys_write → stamp` seam end to end through
//! the real binary, over a real gRPC channel — the exact path a live forge
//! once bypassed (the stream RPC skipped the hook). The journey:
//!
//!   1. MINT   an `sk-` Agent key for `win-ai` (offline CLI, committed via raft).
//!   2. SERVE  boot the daemon: token plane + `/agents` + `--agent-bind-addr`.
//!   3. AUTH   the AGENT bind authenticates the minted key (token plane up).
//!   4. CREATE `win-ai` creates the recipient mailbox `/agents/mac-ai/chat-with-me`.
//!   5. FORGE  `win-ai` sends an envelope claiming `from":"impostor"`.
//!   6. STAMP  read it back — `from` is `win-ai`; the forgery did not survive.
//!   7. DENY   the same write with an EMPTY token lands nothing.

mod common;

use std::time::Duration;

use common::{free_port, mint_agent_key, Daemon, Vfs};

const SECRET: &str = "e2e-from-stamp-secret";
const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SENDER: &str = "win-ai";
const RECIPIENT: &str = "mac-ai";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_is_unforgeable_on_the_token_authed_agent_bind() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let ident = tmp.path().join("identity");
    let ident = ident.to_string_lossy();
    let port = free_port();
    let agent_port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let mounts = format!("{MOUNT}={ZONE}");

    // Token plane ON and NOT NEXUS_INSECURE_NO_AUTH — auth enforced, which also
    // flips the a2a stamp hook to fail-closed.
    let env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_FEDERATION_ZONES", ZONE),
        ("NEXUS_FEDERATION_MOUNTS", mounts.as_str()),
    ];

    // ── 1. MINT the sender's sk- Agent key (offline; into the data dir) ──
    let key = mint_agent_key(&env, SENDER, &format!("{ZONE}:rw"));

    // ── 2. SERVE: token plane + /agents federated + the loopback agent bind ──
    let bind = format!("127.0.0.1:{port}");
    let agent_bind = format!("127.0.0.1:{agent_port}");
    let _daemon = Daemon::spawn(
        &["--bind-addr", &bind, "--agent-bind-addr", &agent_bind],
        &env,
    );

    let budget = Duration::from_secs(90);

    // ── 3. AUTH: the agent bind authenticating the minted key IS the readiness
    // gate — the daemon spawns the agent bind only after the kernel + root mount
    // are up. No federation gate here: this is a single node (no peers, so the
    // shared zone is moot), and the offline `mint` step's data dir makes the
    // daemon resume (federation env advisory), so `/agents` is served by the
    // root mount. The from-stamp is path+ctx based, so the guarantee holds
    // either way; the real federated mailbox path is covered by `a2a_wakeup`.
    let mut c = Vfs::connect_authenticated(agent_port, &key, budget).await;

    // ── 4. CREATE the recipient mailbox as the authenticated sender ──────
    let mailbox = format!("{MOUNT}/{RECIPIENT}/chat-with-me");
    c.mkdir(&format!("{MOUNT}/{RECIPIENT}"), &key)
        .await
        .expect("mkdir recipient dir");
    c.create_stream(&mailbox, &key)
        .await
        .expect("create mailbox stream");

    // ── 5. FORGE + SEND: authenticated as win-ai, claiming from=impostor ──
    let envelope = format!(r#"{{"from":"impostor","to":"{RECIPIENT}","body":"hi from {SENDER}"}}"#);
    c.stream_write(&mailbox, envelope.as_bytes(), &key)
        .await
        .expect("stream write");

    // ── 6. STAMP: read back — the forged `from` was rewritten to the caller ──
    let got = c.stream_collect_all(&mailbox, &key).await.expect("collect");
    let got = String::from_utf8_lossy(&got);
    assert!(
        got.contains(r#""from":"win-ai""#),
        "`from` must be stamped to the authenticated caller (win-ai); got: {got}"
    );
    assert!(
        !got.contains("impostor"),
        "the forged `from` must not survive anywhere; got: {got}"
    );

    // ── 7. DENY: an empty-token mailbox write lands nothing ──────────────
    let denied = c
        .stream_write(
            &mailbox,
            br#"{"from":"impostor","to":"mac-ai","body":"y"}"#,
            "",
        )
        .await;
    assert!(
        denied.is_err(),
        "an empty-token mailbox write must be refused — an unauthenticated `from` must not land"
    );
}
