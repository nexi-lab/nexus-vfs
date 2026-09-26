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
    nexus_vfs_service_client::NexusVfsServiceClient, CallRequest, IpcPathRequest, MkdirRequest,
    PingRequest, ReadRequest, ReaddirRequest, SetattrRequest, StatRequest, StreamReadAtRequest,
    StreamWriteRequest, WatchRequest, WriteRequest,
};
use lib::transport_primitives::{AgentCredential, LoadedCredential};
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
    /// Handles of the two pipe-reader threads, so a caller that has seen the
    /// child exit can wait for them to finish draining — see [`Daemon::drain_settled`].
    pumps: Vec<std::thread::JoinHandle<()>>,
}

/// Strip ANSI SGR sequences (`ESC [ ... m`) from captured daemon output.
///
/// The daemon writes COLOURED logs, and the colouring lands INSIDE a structured
/// line: `tracing`'s formatter wraps a field name, its `=` and its value in
/// separate escapes, so the bytes between `voter_count` and `2` are not `=`.
/// A gate like `wait_for_log("voter_count=2")` then never matches a line the
/// eye can plainly read in the failure dump -- the most expensive kind of
/// mismatch, because the dump looks like it proves the gate wrong.
///
/// Stripping once, here, is what lets a gate name a FIELD rather than only a
/// prose message. Only SGR is removed; nothing else in the stream moves.
fn strip_ansi(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // ESC '[' ... 'm' -- consume through the terminator. A truncated tail
        // (the pipe split mid-sequence) simply ends the scan.
        if chars.next() != Some('[') {
            continue;
        }
        for p in chars.by_ref() {
            if p == 'm' {
                break;
            }
        }
    }
    out
}

/// Drain a child pipe into the shared log buffer on a background thread. The
/// thread exits when the pipe closes (the child is killed on `Daemon` drop).
fn pump(
    pipe: Option<impl std::io::Read + Send + 'static>,
    log: Arc<Mutex<String>>,
) -> Option<std::thread::JoinHandle<()>> {
    let pipe = pipe?;
    let mut pipe = pipe;
    Some(std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => log
                    .lock()
                    .unwrap()
                    .push_str(&strip_ansi(&String::from_utf8_lossy(&buf[..n]))),
            }
        }
    }))
}

#[cfg(test)]
mod strip_ansi_tests {
    use super::strip_ansi;

    /// A coloured structured line reads as plain `field=value` afterwards.
    #[test]
    fn sgr_between_a_field_and_its_value_is_removed() {
        let coloured = "\u{1b}[2mvoter_count\u{1b}[0m\u{1b}[2m=\u{1b}[0m2";
        assert_eq!(strip_ansi(coloured), "voter_count=2");
    }

    /// Uncoloured input survives, and a sequence split across a pipe read does
    /// not eat the rest of the buffer.
    #[test]
    fn plain_text_survives_and_a_truncated_sequence_terminates() {
        assert_eq!(
            strip_ansi("raft.conf_change.applied"),
            "raft.conf_change.applied"
        );
        assert_eq!(strip_ansi("a\u{1b}"), "a");
    }
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
        // A daemon with no identity dir falls back to the USER-GLOBAL one
        // (`~/.local/share/nexus/identity.json`). Every test in a binary then
        // shares it, they run concurrently, and the loser of the atomic-rename
        // race dies with `identity persist_peers: ... No such file or
        // directory` — reported as whatever that test was actually asserting.
        // It cost a red CI run diagnosed as a flake before anyone looked at the
        // path in the error. Refusing here makes the whole class impossible
        // rather than remembered, which is the same reason the daemon itself
        // refuses an unauthenticated reachable bind instead of warning about it.
        let has_identity_dir = args
            .iter()
            .any(|a| *a == "--identity-dir" || a.starts_with("--identity-dir="))
            || env.iter().any(|(k, _)| *k == "NEXUS_IDENTITY_DIR");
        assert!(
            has_identity_dir,
            "test daemons must be given their own identity dir (--identity-dir \
             or NEXUS_IDENTITY_DIR). Without one this daemon writes the \
             user-global identity.json that every concurrent test shares, and \
             the failure surfaces as an unrelated assertion. args: {args:?}"
        );
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
        let pumps = [
            pump(child.stdout.take(), Arc::clone(&log)),
            pump(child.stderr.take(), Arc::clone(&log)),
        ]
        .into_iter()
        .flatten()
        .collect();
        Daemon { child, log, pumps }
    }

    /// Poll until the TCP `port` accepts a connection (came up) or the process
    /// exits (refused to boot). `Ok(())` = serving; `Err(output)` = it exited
    /// (with its captured logs) or the budget expired.
    pub async fn wait_tcp(&mut self, port: u16, budget: Duration) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!(
                    "exited (status {status}):\n{}",
                    self.drain_settled()
                ));
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
                return Some(self.drain_settled());
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
                    self.drain_settled()
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

    /// Like [`wait_for_log`], but wait until `pat` has appeared at least `count`
    /// times — the readiness gate for an N-voter group, where a per-node event
    /// (e.g. "learner promoted to voter") must fire once per joiner before the
    /// cluster is quorum-stable. `wait_for_log` re-scans the whole buffer, so it
    /// cannot distinguish the k-th occurrence on its own.
    pub async fn wait_for_log_count(
        &mut self,
        pat: &str,
        count: usize,
        budget: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        loop {
            if self.log.lock().unwrap().matches(pat).count() >= count {
                return Ok(());
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!(
                    "exited (status {status}) before logging {pat:?} ×{count}:\n{}",
                    self.drain_settled()
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "log never contained {pat:?} ×{count} within budget:\n{}",
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

    /// Everything the child wrote, after its pipes have been fully drained.
    ///
    /// Call this INSTEAD of [`Daemon::drain`] once `try_wait` has reported the
    /// child exited. `try_wait` observes process death, which says nothing
    /// about the reader threads: the pipes still hold whatever the child wrote
    /// on its way out, and `drain` would snapshot a buffer those threads have
    /// not finished filling. The faster the child dies, the emptier the
    /// snapshot — so the tests most likely to lose their output are exactly
    /// the ones asserting on a refusal, which is the earliest exit there is.
    ///
    /// That is not theoretical: `zone_id_refused_at_boot` failed twice on main
    /// this way, reporting `exited (status 1):` with nothing after the colon
    /// and an assertion complaining the id was missing from the logs.
    ///
    /// Only safe once the child is gone. While it lives its pipes never reach
    /// EOF, so the reader threads never return and this would block until the
    /// test's own timeout — which is why the budget-expired paths keep using
    /// plain `drain`.
    pub fn drain_settled(&mut self) -> String {
        for pump in std::mem::take(&mut self.pumps) {
            let _ = pump.join();
        }
        self.drain()
    }

    /// The daemon's OS process id — for tests that measure the process itself
    /// (e.g. how much CPU it burns while idle) rather than its wire behaviour.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// CPU seconds (user + system) this daemon has consumed since it started.
    ///
    /// Read from `/proc/<pid>/stat` fields 14/15, which are in clock ticks;
    /// `sysconf(_SC_CLK_TCK)` is 100 on every Linux target we build for, and a
    /// wrong constant would only scale the ratio a test compares against its
    /// own budget.  Linux-only: it backs the idle-cost gate, which runs on the
    /// Linux CI (and in the Docker bench) where the daemon actually ships.
    #[cfg(target_os = "linux")]
    pub fn cpu_seconds(&self) -> f64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid()))
            .expect("read /proc/<pid>/stat");
        // The comm field can contain spaces and parens; everything after the
        // final ')' is fixed-width, so index from there.
        let tail = &stat[stat.rfind(')').expect("stat comm field") + 2..];
        let fields: Vec<&str> = tail.split_whitespace().collect();
        let utime: u64 = fields[11].parse().expect("utime");
        let stime: u64 = fields[12].parse().expect("stime");
        (utime + stime) as f64 / 100.0
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

/// Read a minted bundle as the ONE credential it is — the PEMs plus the TLS server
/// name to verify — through the same loader a client outside this repo uses.
///
/// Tests go through this rather than reading `agent.pem` and friends by name, for the
/// reason the credential format exists: a filename or a server name spelled a second
/// time is a copy that can disagree with the mint. Because every mTLS test dials this
/// way, a manifest that stopped matching what the mint writes fails the suite loudly
/// instead of only failing the clients we do not test here.
pub fn agent_credential(bundle_dir: &std::path::Path) -> LoadedCredential {
    AgentCredential::load(bundle_dir)
        .unwrap_or_else(|e| panic!("load the credential at {}: {e}", bundle_dir.display()))
}

/// Mint a cert-agent (`--subject-type agent`) and return its bundle directory — the
/// whole credential (see [`agent_credential`]). An agent's one credential is a
/// CA-signed identity cert; [`Vfs::connect_as_agent`] presents it. Needs the founder
/// CA at `<data-dir>/tls`; the daemon must NOT hold the data-dir lock.
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

    /// [`dial`], but poll until the gRPC connect succeeds or `budget` expires.
    /// A one-shot [`dial`] right after a raft membership change (e.g. dialing a
    /// freshly-promoted voter mid-formation) can lose the HTTP/2 handshake to
    /// transient CPU contention even though the port already accepts TCP — this
    /// is the connect-side analogue of [`connect_authenticated`]'s poll.
    pub async fn dial_ready(port: u16, budget: Duration) -> Self {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(v) = Self::dial(port).await {
                return v;
            }
            if Instant::now() >= deadline {
                panic!("dial(127.0.0.1:{port}) never connected within budget");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
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

    /// Dial as an agent with its credential and NOTHING else — the shape a client
    /// outside this repo has: one directory from `auth mint`, one endpoint.
    ///
    /// Every value comes from the credential, the server name included, so this
    /// proves the manifest is sufficient rather than assuming it. Calls then carry an
    /// EMPTY token, because a verified agent cert is the whole authentication.
    pub async fn connect_as_agent(port: u16, cred: &LoadedCredential, budget: Duration) -> Self {
        Self::connect_mtls_named(
            port,
            &cred.ca_pem,
            &cred.cert_pem,
            &cred.key_pem,
            &cred.server_name,
            budget,
        )
        .await
    }

    /// Dial the mTLS plane presenting a client identity cert chaining to `ca_pem`,
    /// verifying the server as the cluster's fixed name. For a NODE cert or raw PEMs;
    /// an agent has a credential, so it uses [`Self::connect_as_agent`].
    pub async fn connect_mtls(
        port: u16,
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        budget: Duration,
    ) -> Self {
        Self::connect_mtls_named(
            port,
            ca_pem,
            client_cert_pem,
            client_key_pem,
            lib::transport_primitives::TlsConfig::CLUSTER_SERVER_NAME,
            budget,
        )
        .await
    }

    /// The one dial: polls until the TLS handshake AND a bare `Ping` both succeed —
    /// the cert authenticating IS the readiness gate.
    async fn connect_mtls_named(
        port: u16,
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        server_name: &str,
        budget: Duration,
    ) -> Self {
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca_pem))
            .identity(Identity::from_pem(client_cert_pem, client_key_pem))
            .domain_name(server_name);
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

    /// The generic service RPC: `Call("<service>.<method>", json)`.
    ///
    /// This is the path a registered Rust service is reached on, and the one
    /// that carries the caller's resolved identity — so it is how a test drives
    /// a service *as somebody*, with the daemon deciding who that is from the
    /// credential this connection presented.
    ///
    /// Returns the response payload as a UTF-8 string, or the error payload as
    /// `Err` — the daemon reports service-level refusals in-band (`is_error`),
    /// not as a gRPC status.
    pub async fn call(&mut self, method: &str, json: &str, token: &str) -> Result<String, String> {
        let r = self
            .c
            .call(CallRequest {
                method: method.to_string(),
                payload: json.as_bytes().to_vec(),
                auth_token: token.to_string(),
            })
            .await
            .map_err(|e| format!("call rpc: {e}"))?
            .into_inner();
        let payload = String::from_utf8_lossy(&r.payload).to_string();
        if r.is_error {
            return Err(payload);
        }
        Ok(payload)
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
    /// Create a DT_MOUNT with a constructed backend — the production path an
    /// operator takes to mount a connector, `backend_type` + `backend_params`
    /// straight through to the `ObjectStoreProvider` arm.
    pub async fn mount_backend(
        &mut self,
        path: &str,
        backend_type: &str,
        params: &[(&str, &str)],
        token: &str,
    ) -> Result<(), String> {
        const DT_MOUNT: i32 = 2;
        let r = self
            .c
            .setattr(SetattrRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                entry_type: DT_MOUNT,
                backend_type: backend_type.to_string(),
                backend_name: backend_type.to_string(),
                backend_params: params
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                ..Default::default()
            })
            .await
            .map_err(|e| format!("setattr rpc: {e}"))?
            .into_inner();
        err_if(r.is_error, &r.error_payload, "mount_backend")
    }

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

    /// The zone `path` ROUTED to, as the server resolved it — `None` if the
    /// path does not exist.
    ///
    /// `stat_found` answers "is it there", which cannot distinguish a
    /// replicated federation mount from the node-local `root` fallback: both
    /// answer yes. Only the resolved zone separates them, and that difference
    /// is the whole of "does this path replicate cross-machine".
    pub async fn stat_zone(&mut self, path: &str, token: &str) -> Option<String> {
        let r = self
            .c
            .stat(StatRequest {
                path: path.to_string(),
                auth_token: token.to_string(),
                ..Default::default()
            })
            .await
            .ok()?
            .into_inner();
        r.found.then_some(r.zone_id)
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
