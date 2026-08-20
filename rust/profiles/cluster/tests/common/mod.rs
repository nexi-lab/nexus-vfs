//! Shared black-box harness for the `nexus-cluster` e2e integration tests.
//!
//! These tests spawn the REAL `nexusd-cluster` binary (via
//! `CARGO_BIN_EXE_nexusd-cluster`) and drive it over a REAL gRPC channel. A
//! black-box binary+wire test catches what an in-process test structurally
//! can't: clap arg parsing, the boot posture, and the on-the-wire proto
//! contract a foreign client (moss/sudocode) sees. The harness keeps each test
//! a short journey.

#![allow(dead_code)] // each test file uses a different subset

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, IpcPathRequest, MkdirRequest, PingRequest,
    ReadRequest, ReaddirRequest, SetattrRequest, StatRequest, StreamReadAtRequest,
    StreamWriteRequest, WatchRequest, WriteRequest,
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

/// A data-plane port `p` such that `p + 1` is ALSO free — for the enrollment
/// convention (the node-enrollment listener rides one port above the data
/// plane; both sides derive `p + 1`). Returns `p`; probe both, retry on a taken
/// neighbour so the pair is deterministic under random ephemeral allocation.
pub fn free_port_pair() -> u16 {
    for _ in 0..64 {
        let p = free_port();
        if p < u16::MAX && std::net::TcpListener::bind(("127.0.0.1", p + 1)).is_ok() {
            return p;
        }
    }
    panic!("could not find a data/enroll port pair (p, p+1) both free");
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

/// Mint an `sk-` token for a `user` or `service` subject (the token plane).
/// Agents are cert-only — use [`mint_agent_cert`] for those. Returns the key.
/// The daemon must NOT be holding the data-dir lock when this runs.
pub fn mint_token_key(
    env: &[(&str, &str)],
    subject_type: &str,
    subject_id: &str,
    zone_rw: &str,
) -> String {
    let mut cmd = Command::new(bin());
    cmd.args([
        "auth",
        "mint",
        "--subject-type",
        subject_type,
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

/// Mint a cert-agent (`--subject-type agent`) and return its bundle directory
/// (holding `agent.pem` / `agent-key.pem` / `ca.pem`). An agent's one credential
/// is a CA-signed identity cert — [`Vfs::connect_mtls`] presents it. Needs the
/// founder CA at `<data-dir>/tls`; the daemon must NOT hold the data-dir lock.
pub fn mint_agent_cert(env: &[(&str, &str)], subject_id: &str) -> std::path::PathBuf {
    mint_agent_cert_args(env, subject_id, &[])
}

/// Re-mint an EXISTING agent name with `--allow-existing` — the rotation path:
/// the old cert stays revoked (its serial is in the CRL) while this fresh cert
/// (a new serial) works. Returns the new bundle dir.
pub fn mint_agent_cert_allow_existing(
    env: &[(&str, &str)],
    subject_id: &str,
) -> std::path::PathBuf {
    mint_agent_cert_args(env, subject_id, &["--allow-existing"])
}

fn mint_agent_cert_args(
    env: &[(&str, &str)],
    subject_id: &str,
    extra: &[&str],
) -> std::path::PathBuf {
    let mut cmd = Command::new(bin());
    cmd.args([
        "auth",
        "mint",
        "--subject-type",
        "agent",
        "--subject-id",
        subject_id,
        "--name",
        "e2e",
    ]);
    cmd.args(extra);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run `auth mint` (agent cert)");
    assert!(
        out.status.success(),
        "agent cert mint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let dir = std::path::PathBuf::from(dir);
    assert!(
        dir.join("agent.pem").exists() && dir.join("agent-key.pem").exists(),
        "mint did not write a cert bundle at {dir:?}"
    );
    dir
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

/// Write a TLS bundle (a shared CA + a fresh node cert with loopback SANs) plus
/// the persisted `node_id` into `data_dir`, so `bootstrap_tls` finds the bundle
/// present and reuses it (TLS on, no self-generated CA). One shared CA is what
/// lets nodes verify each other's client certs — cluster membership — and is
/// also what an offline `auth mint --subject-type agent` reads to sign the cert.
pub fn write_tls_bundle(
    data_dir: &std::path::Path,
    node_id: u64,
    ca: &[u8],
    ca_key: &[u8],
    token_hash: &str,
) {
    use nexus_raft::transport::generate_node_cert;
    let tls = data_dir.join("tls");
    std::fs::create_dir_all(&tls).expect("mkdir tls");
    let (cert, key) =
        generate_node_cert(node_id, "root", ca, ca_key, &[], Some("localhost")).expect("node cert");
    std::fs::write(tls.join("ca.pem"), ca).unwrap();
    std::fs::write(tls.join("ca-key.pem"), ca_key).unwrap();
    std::fs::write(tls.join("node.pem"), cert).unwrap();
    std::fs::write(tls.join("node-key.pem"), key).unwrap();
    std::fs::write(tls.join("join-token-hash"), token_hash).unwrap();
    // read_or_mint_node_id reads an 8-byte big-endian u64 (matches the cert's
    // node/{id} identity SAN so the running node and its cert agree).
    std::fs::write(data_dir.join(".node_id"), node_id.to_be_bytes()).unwrap();
}

/// Decoded `StreamReadAt` outcome — success bytes plus the raw error surface so
/// a caller can assert on the wire error (e.g. the `OffsetOutOfRange` message
/// for a retention-trimmed offset), not just on `data`.
pub struct StreamReadOutcome {
    pub data: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
    pub is_error: bool,
    /// `error_payload` decoded as UTF-8 (the JSON `{"code":…,"message":…}`).
    pub error_payload: String,
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

    /// Dial the mTLS plane presenting a client identity cert — an agent's
    /// `agent.pem` / `agent-key.pem` bundle (as `auth mint --subject-type agent` writes),
    /// chaining to `ca_pem`. The daemon authenticates the caller from the
    /// client certificate (the peer plane), so calls carry an EMPTY token.
    /// Polls until the TLS handshake + a bare `Ping` both succeed — the cert
    /// authenticating IS the readiness gate.
    pub async fn connect_mtls(
        port: u16,
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        budget: Duration,
    ) -> Self {
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca_pem))
            .identity(Identity::from_pem(client_cert_pem, client_key_pem))
            .domain_name(lib::transport_primitives::TlsConfig::CLUSTER_SERVER_NAME);
        let deadline = Instant::now() + budget;
        loop {
            let connected = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
                .expect("valid uri")
                .tls_config(tls.clone())
                .expect("tls config")
                .connect()
                .await;
            if let Ok(ch) = connected {
                let mut v = Vfs {
                    c: NexusVfsServiceClient::new(ch),
                };
                if v.ping("").await.is_ok() {
                    return v;
                }
            }
            assert!(
                Instant::now() < deadline,
                "port :{port} never authenticated the client cert within budget"
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
        self.create_stream_cap(path, 0, token).await
    }

    /// Create a wal DT_STREAM with a retention budget: `capacity` bytes of cold
    /// storage (`0` = keep-forever, as `create_stream`). Once sealed cold storage
    /// exceeds the budget the oldest segments are trimmed and `earliest` advances
    /// (Kafka retention). Same `wal,memory` io_profile as `create_stream`.
    pub async fn create_stream_cap(
        &mut self,
        path: &str,
        capacity: u64,
        token: &str,
    ) -> Result<(), String> {
        let r = self
            .c
            .setattr(SetattrRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                entry_type: DT_STREAM,
                io_profile: "wal,memory".into(),
                capacity,
                ..Default::default()
            })
            .await
            .map_err(|e| format!("setattr rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "create_stream_cap")
    }

    /// Non-blocking `StreamReadAt`, returning the decoded outcome (data /
    /// next_offset / eof / error) so a caller can assert on the error CODE —
    /// e.g. `OffsetOutOfRange` for an offset trimmed by retention — not just on
    /// success bytes. Transport failures surface as `Err`.
    pub async fn stream_read_at(
        &mut self,
        path: &str,
        offset: u64,
        token: &str,
    ) -> Result<StreamReadOutcome, String> {
        let r = self
            .c
            .stream_read_at(StreamReadAtRequest {
                path: path.to_string(),
                offset,
                blocking: false,
                timeout_ms: 0,
                auth_token: token.to_string(),
            })
            .await
            .map_err(|e| format!("stream_read_at rpc: {e}"))?
            .into_inner();
        Ok(StreamReadOutcome {
            data: r.data,
            next_offset: r.next_offset,
            eof: r.eof,
            is_error: r.is_error,
            error_payload: String::from_utf8_lossy(&r.error_payload).into_owned(),
        })
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
