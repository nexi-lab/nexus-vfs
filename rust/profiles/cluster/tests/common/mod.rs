//! Shared black-box harness for the `nexus-cluster` e2e integration tests.
//!
//! These tests spawn the REAL `nexusd-cluster` binary (via
//! `CARGO_BIN_EXE_nexusd-cluster`) and drive it over a REAL gRPC channel —
//! the Rust replacements for the retired `scripts/e2e_*.py`. A black-box
//! binary+wire test catches what an in-process test structurally can't: clap
//! arg parsing, the boot posture, and the on-the-wire proto contract a foreign
//! client (moss/sudocode) sees. The harness keeps each test a short journey.

#![allow(dead_code)] // each test file uses a different subset

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, IpcPathRequest, MkdirRequest, PingRequest,
    ReadRequest, ReaddirRequest, SetattrRequest, StatRequest, StreamWriteRequest, WatchRequest,
    WriteRequest,
};
use tonic::transport::Channel;

pub const DT_STREAM: i32 = 4;

/// RUST_LOG for daemons whose readiness is gated on a log line (federation
/// tests): INFO so the `Zone '...' registered` line is emitted, with the noisy
/// gRPC-stack crates pinned to warn. Pass via the daemon env (overrides the
/// spawn default). A caller can still override with `NEXUS_E2E_INHERIT_LOGS`.
pub const LOG_FILTER: &str = "info,h2=warn,hyper=warn,tower=warn,tonic=warn";

/// Path to the built binary — Cargo sets this for the crate's integration tests.
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nexusd-cluster")
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// A spawned `nexusd-cluster`, killed on drop. Reader threads capture
/// stdout+stderr into a shared buffer, so `drain()` can read a refusal's prose
/// and `wait_for_log()` can gate on a readiness line — the only RELIABLE
/// "the zone is registered / ready" signal, since `readdir`/`stat` on a mount
/// point do not distinguish a live federation mount from a root-served empty
/// path (`readdir` returns non-error for any path; `stat` returns not-found for
/// a mount point).
pub struct Daemon {
    child: Child,
    log: Arc<Mutex<String>>,
}

/// Drain a child pipe into the shared log buffer on a background thread. The
/// thread exits when the pipe closes (the child is killed on `Daemon` drop).
fn pump(pipe: Option<impl std::io::Read + Send + 'static>, log: Arc<Mutex<String>>) {
    let Some(mut pipe) = pipe else { return };
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => log
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    });
}

impl Daemon {
    /// Spawn the binary with `args` and env overrides. Ambient
    /// `NEXUS_API_KEY_SECRET` / `NEXUS_INSECURE_NO_AUTH` are cleared so a stale
    /// value can't silently change the posture under test; callers add them
    /// back explicitly via `env`.
    ///
    /// `NEXUS_E2E_INHERIT_LOGS=1` streams the daemon's stdout/stderr to the
    /// test's own (for `RUST_LOG=info` debugging); nothing is captured then, so
    /// `drain()` / `wait_for_log()` see nothing.
    pub fn spawn(args: &[&str], env: &[(&str, &str)]) -> Self {
        let inherit = std::env::var("NEXUS_E2E_INHERIT_LOGS").is_ok();
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .env_remove("NEXUS_API_KEY_SECRET")
            .env_remove("NEXUS_INSECURE_NO_AUTH")
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()),
            );
        if inherit {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn nexusd-cluster");
        let log = Arc::new(Mutex::new(String::new()));
        pump(child.stdout.take(), Arc::clone(&log));
        pump(child.stderr.take(), Arc::clone(&log));
        Daemon { child, log }
    }

    /// Poll until the TCP `port` accepts a connection (came up) or the process
    /// exits (refused to boot). `Ok(())` = serving; `Err(output)` = it exited
    /// (with its captured logs) or the budget expired.
    pub async fn wait_tcp(&mut self, port: u16, budget: Duration) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!("exited (status {status}):\n{}", self.drain()));
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Err(format!("timed out without serving:\n{}", self.drain()))
    }

    /// Did the process exit within `budget`? Returns its captured logs if so.
    pub async fn wait_exit(&mut self, budget: Duration) -> Option<String> {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return Some(self.drain());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        None
    }

    /// True if the captured logs so far contain `pat`.
    pub fn log_contains(&self, pat: &str) -> bool {
        self.log.lock().unwrap().contains(pat)
    }

    /// Poll until the captured logs contain `pat` (a readiness line), or the
    /// process dies / the budget expires. This is the deterministic gate for
    /// federation boot ordering: wait for the founder to log its zone
    /// registration before booting a joiner, so the joiner's DiscoverZones
    /// cannot race (and lose to) that registration and come up rootless.
    pub async fn wait_for_log(&mut self, pat: &str, budget: Duration) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        loop {
            if self.log_contains(pat) {
                return Ok(());
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!(
                    "exited (status {status}) before logging {pat:?}:\n{}",
                    self.drain()
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "log never contained {pat:?} within budget:\n{}",
                    self.drain()
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Snapshot of everything the child has written to stdout+stderr so far.
    pub fn drain(&self) -> String {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run the offline `auth mint` subcommand and return the minted `sk-` key.
/// The daemon must NOT be holding the data-dir lock when this runs.
pub fn mint_agent_key(env: &[(&str, &str)], subject_id: &str, zone_rw: &str) -> String {
    let mut cmd = Command::new(bin());
    cmd.args([
        "auth",
        "mint",
        "--subject-type",
        "agent",
        "--subject-id",
        subject_id,
        "--zone",
        zone_rw,
        "--name",
        "e2e",
    ]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run `auth mint`");
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
    key
}

/// Run any offline subcommand; returns (success, stdout, stderr).
pub fn cli(env: &[(&str, &str)], args: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run cli subcommand");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Thin typed wrapper over the VFS gRPC client. Every call carries its bearer
/// token, so a single connection can exercise many identities (the auth test
/// pings with valid / empty / unknown / revoked tokens over one channel).
#[derive(Clone)]
pub struct Vfs {
    c: NexusVfsServiceClient<Channel>,
}

impl Vfs {
    pub async fn dial(port: u16) -> Option<Self> {
        let ch = Channel::from_shared(format!("http://127.0.0.1:{port}"))
            .expect("valid uri")
            .connect()
            .await
            .ok()?;
        Some(Vfs {
            c: NexusVfsServiceClient::new(ch),
        })
    }

    /// Poll until the port accepts a connection AND `Ping(token)` succeeds
    /// (the auth store binds a beat after the socket opens).
    pub async fn connect_authenticated(port: u16, token: &str, budget: Duration) -> Self {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(mut v) = Self::dial(port).await {
                if v.ping(token).await.is_ok() {
                    return v;
                }
            }
            assert!(
                Instant::now() < deadline,
                "port :{port} never authenticated the token within budget"
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Poll until the gRPC socket accepts a connection — the daemon is
    /// serving, whether it answers a bare Ping as admin (NoAuth) or refuses it
    /// (ApiKey). Used by the auth test, which then drives rejection paths that
    /// `connect_authenticated` (which requires a Ping to succeed) can't wait on.
    pub async fn connect_serving(port: u16, budget: Duration) -> Self {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(mut v) = Self::dial(port).await {
                // A gRPC response OR a gRPC status both prove the server is up;
                // only a transport failure (dial None) means not-yet.
                let _ = v.ping("").await;
                return v;
            }
            assert!(
                Instant::now() < deadline,
                "port :{port} never came up within budget"
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    pub async fn ping(&mut self, token: &str) -> Result<(), tonic::Status> {
        self.c
            .ping(PingRequest {
                auth_token: token.to_string(),
            })
            .await
            .map(|_| ())
    }

    pub async fn mkdir(&mut self, path: &str, token: &str) -> Result<(), String> {
        let r = self
            .c
            .mkdir(MkdirRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                parents: true,
                exist_ok: true,
            })
            .await
            .map_err(|e| format!("mkdir rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "mkdir")
    }

    /// Readdir returning the entry names (which are FULL paths, not bare
    /// filenames — a known API wart the moss migration must account for).
    pub async fn readdir_names(&mut self, path: &str, token: &str) -> Result<Vec<String>, String> {
        let r = self
            .c
            .readdir(ReaddirRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                ..Default::default()
            })
            .await
            .map_err(|e| format!("readdir rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "readdir")?;
        Ok(r.entries.into_iter().map(|e| e.name).collect())
    }

    pub async fn create_stream(&mut self, path: &str, token: &str) -> Result<(), String> {
        let r = self
            .c
            .setattr(SetattrRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                entry_type: DT_STREAM,
                io_profile: "wal,memory".into(),
                ..Default::default()
            })
            .await
            .map_err(|e| format!("setattr rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "create_stream")
    }

    pub async fn stream_write(
        &mut self,
        path: &str,
        data: &[u8],
        token: &str,
    ) -> Result<u64, String> {
        let r = self
            .c
            .stream_write_nowait(StreamWriteRequest {
                path: path.to_string(),
                data: data.to_vec(),
                auth_token: token.to_string(),
            })
            .await
            .map_err(|e| format!("stream_write rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "stream_write")?;
        Ok(r.offset)
    }

    pub async fn stream_collect_all(&mut self, path: &str, token: &str) -> Result<Vec<u8>, String> {
        let r = self
            .c
            .stream_collect_all(IpcPathRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
            })
            .await
            .map_err(|e| format!("stream_collect_all rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "stream_collect_all")?;
        Ok(r.data)
    }

    pub async fn write_file(&mut self, path: &str, data: &[u8], token: &str) -> Result<(), String> {
        let r = self
            .c
            .write(WriteRequest {
                path: path.to_string(),
                content: data.to_vec(),
                auth_token: token.to_string(),
            })
            .await
            .map_err(|e| format!("write rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "write")
    }

    pub async fn read_file(&mut self, path: &str, token: &str) -> Result<Vec<u8>, String> {
        let r = self
            .c
            .read(ReadRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                timeout_ms: 5000,
                ..Default::default()
            })
            .await
            .map_err(|e| format!("read rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "read")?;
        Ok(r.content)
    }

    pub async fn stat_found(&mut self, path: &str, token: &str) -> bool {
        self.c
            .stat(StatRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                ..Default::default()
            })
            .await
            .map(|r| r.into_inner().found)
            .unwrap_or(false)
    }

    /// Park a blocking Watch; returns the client so the caller keeps the
    /// channel. `matched` is true if an event arrived before the timeout.
    pub async fn watch(
        &mut self,
        path: &str,
        timeout_ms: u64,
        token: &str,
    ) -> Result<bool, String> {
        let r = self
            .c
            .watch(WatchRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                timeout_ms,
            })
            .await
            .map_err(|e| format!("watch rpc: {e}"))?
            .into_inner();
        Ok(r.matched)
    }
}

fn err_if(is_error: bool, payload: &[u8], what: &str) -> Result<(), String> {
    if is_error {
        Err(format!("{what}: {}", String::from_utf8_lossy(payload)))
    } else {
        Ok(())
    }
}

/// Poll `stat` on `path` until it exists (metadata replicated in).
pub async fn await_replicated(v: &mut Vfs, path: &str, token: &str, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if v.stat_found(path, token).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("{path} never replicated within budget");
}
