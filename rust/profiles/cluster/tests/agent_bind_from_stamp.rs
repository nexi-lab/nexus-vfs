//! Black-box E2E: an A2A `from` is UNFORGEABLE on the loopback local-agent
//! bind (`--agent-bind-addr`), when auth is on.
//!
//! Spawns the real `nexusd-cluster` binary (`CARGO_BIN_EXE_*`) wired like an
//! Option-X federation node: the token plane on (`NEXUS_API_KEY_SECRET`),
//! `/agents` federated, and a SEPARATE loopback `--agent-bind-addr` for the
//! local agent. mTLS ⊥ token — the two identity planes live on separate binds
//! by audience (auth-doc §3.1 / §4.1); this test drives the token/agent one.
//!
//! It is the auth-ON, over-the-wire complement to the in-process
//! `a2a::stamps_from_on_the_stream_write_path` unit test: it proves the whole
//! gRPC `authenticate → agent_id → sys_write → stamp` seam end to end through
//! the real binary, over a real gRPC channel — the exact path a live forge
//! once bypassed (the stream RPC skipped the hook). The journey, each step
//! consuming the previous step's output:
//!
//!   1. MINT   an `sk-` Agent key for `win-ai` (offline CLI, committed via raft).
//!   2. SERVE  boot the daemon: token plane + `/agents` + `--agent-bind-addr`.
//!   3. AUTH   the AGENT bind authenticates the minted key (token plane up).
//!   4. CREATE `win-ai` creates the recipient mailbox `/agents/mac-ai/chat-with-me`.
//!   5. FORGE  `win-ai` sends an envelope claiming `from":"impostor"`.
//!   6. STAMP  read it back — `from` is `win-ai`; the forgery did not survive.
//!   7. DENY   the same write with an EMPTY token lands nothing.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, IpcPathRequest, MkdirRequest, PingRequest,
    ReaddirRequest, SetattrRequest, StreamWriteRequest,
};
use tonic::transport::Channel;

const SECRET: &str = "e2e-from-stamp-secret";
const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const SENDER: &str = "win-ai";
const RECIPIENT: &str = "mac-ai";
const DT_STREAM: i32 = 4;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Apply the shared env used by both the offline `auth mint` and the daemon.
/// Token plane ON and NOT `NEXUS_INSECURE_NO_AUTH` — we want auth enforced,
/// which also flips the a2a stamp hook to fail-closed.
fn base_env(cmd: &mut Command, data: &std::path::Path, ident: &std::path::Path, port: u16) {
    cmd.env("NEXUS_DATA_DIR", data)
        .env("NEXUS_IDENTITY_DIR", ident)
        .env("NEXUS_API_KEY_SECRET", SECRET)
        .env("NEXUS_ADVERTISE_ADDR", format!("127.0.0.1:{port}"))
        .env("NEXUS_NO_TLS", "true")
        .env("NEXUS_FEDERATION_ZONES", ZONE)
        .env("NEXUS_FEDERATION_MOUNTS", format!("{MOUNT}={ZONE}"))
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()),
        );
}

/// Kill-on-drop guard so a panicking assertion never leaks the daemon.
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn dial(port: u16) -> Option<NexusVfsServiceClient<Channel>> {
    let ch = Channel::from_shared(format!("http://127.0.0.1:{port}"))
        .expect("valid uri")
        .connect()
        .await
        .ok()?;
    Some(NexusVfsServiceClient::new(ch))
}

/// Poll the agent bind until it both accepts a connection AND authenticates
/// the minted key (the auth store binds a beat after the socket opens).
async fn await_agent_authenticated(
    port: u16,
    token: &str,
    deadline: Instant,
) -> NexusVfsServiceClient<Channel> {
    loop {
        if let Some(mut c) = dial(port).await {
            if c.ping(PingRequest {
                auth_token: token.to_string(),
            })
            .await
            .is_ok()
            {
                return c;
            }
        }
        assert!(
            Instant::now() < deadline,
            "agent bind never authenticated the minted key on :{port}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Poll until `path` resolves — the federated `/agents` mount is installed.
async fn await_mounted(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    token: &str,
    deadline: Instant,
) {
    loop {
        let ok = c
            .readdir(ReaddirRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                ..Default::default()
            })
            .await
            .map(|r| !r.into_inner().is_error)
            .unwrap_or(false);
        if ok {
            return;
        }
        assert!(Instant::now() < deadline, "{path} never mounted");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_is_unforgeable_on_the_token_authed_agent_bind() {
    let bin = env!("CARGO_BIN_EXE_nexusd-cluster");
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let ident = tmp.path().join("identity");
    let port = free_port();
    let agent_port = free_port();

    // ── 1. MINT the sender's sk- Agent key (offline; into the data dir) ──
    let mut mint = Command::new(bin);
    base_env(&mut mint, &data, &ident, port);
    let out = mint
        .args([
            "auth",
            "mint",
            "--subject-type",
            "agent",
            "--subject-id",
            SENDER,
            "--zone",
            &format!("{ZONE}:rw"),
            "--name",
            "from-stamp-e2e",
        ])
        .output()
        .expect("run `auth mint`");
    assert!(
        out.status.success(),
        "mint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        key.starts_with("sk-") && key.len() >= 32,
        "malformed minted key: {key:?}"
    );

    // ── 2. SERVE: token plane + /agents federated + the loopback agent bind ──
    let mut serve = Command::new(bin);
    base_env(&mut serve, &data, &ident, port);
    serve
        .args([
            "--bind-addr",
            &format!("127.0.0.1:{port}"),
            "--agent-bind-addr",
            &format!("127.0.0.1:{agent_port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _daemon = Daemon(serve.spawn().expect("spawn nexusd-cluster"));

    let deadline = Instant::now() + Duration::from_secs(90);

    // ── 3. AUTH: the agent bind is up and resolves the minted key ────────
    let mut c = await_agent_authenticated(agent_port, &key, deadline).await;
    await_mounted(&mut c, MOUNT, &key, deadline).await;

    // ── 4. CREATE the recipient mailbox as the authenticated sender ──────
    let mailbox = format!("{MOUNT}/{RECIPIENT}/chat-with-me");
    let r = c
        .mkdir(MkdirRequest {
            path: format!("{MOUNT}/{RECIPIENT}"),
            auth_token: key.clone(),
            parents: true,
            exist_ok: true,
        })
        .await
        .expect("mkdir rpc")
        .into_inner();
    assert!(
        !r.is_error,
        "mkdir: {:?}",
        String::from_utf8_lossy(&r.error_payload)
    );
    let r = c
        .setattr(SetattrRequest {
            path: mailbox.clone(),
            auth_token: key.clone(),
            entry_type: DT_STREAM,
            io_profile: "wal,memory".into(),
            ..Default::default()
        })
        .await
        .expect("setattr rpc")
        .into_inner();
    assert!(
        !r.is_error,
        "create_stream: {:?}",
        String::from_utf8_lossy(&r.error_payload)
    );

    // ── 5. FORGE + SEND: authenticated as win-ai, claiming from=impostor ──
    let envelope = format!(r#"{{"from":"impostor","to":"{RECIPIENT}","body":"hi from {SENDER}"}}"#);
    let r = c
        .stream_write_nowait(StreamWriteRequest {
            path: mailbox.clone(),
            data: envelope.into_bytes(),
            auth_token: key.clone(),
        })
        .await
        .expect("stream_write rpc")
        .into_inner();
    assert!(
        !r.is_error,
        "stream_write: {:?}",
        String::from_utf8_lossy(&r.error_payload)
    );

    // ── 6. STAMP: read back — the forged `from` was rewritten to the caller ──
    let r = c
        .stream_collect_all(IpcPathRequest {
            path: mailbox.clone(),
            auth_token: key.clone(),
        })
        .await
        .expect("stream_collect_all rpc")
        .into_inner();
    assert!(
        !r.is_error,
        "stream_collect_all: {:?}",
        String::from_utf8_lossy(&r.error_payload)
    );
    let got = String::from_utf8_lossy(&r.data);
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
        .stream_write_nowait(StreamWriteRequest {
            path: mailbox.clone(),
            data: br#"{"from":"impostor","to":"mac-ai","body":"y"}"#.to_vec(),
            auth_token: String::new(),
        })
        .await;
    let rejected = match denied {
        Err(_) => true,
        Ok(resp) => resp.into_inner().is_error,
    };
    assert!(
        rejected,
        "an empty-token mailbox write must be refused — an unauthenticated `from` must not land"
    );
}
