//! Black-box E2E: `sk-` API-key authentication actually gates the daemon.
//!
//! Drives the real thing — a real `nexusd-cluster`, real key minting through
//! raft, real gRPC — because the unit tests can all pass while the provider is
//! never wired, the store never bound, or the boot order leaves an empty slot;
//! only running the binary catches that (the first live run died on a rootless
//! boot no unit test could have seen). Rust replacement for the retired
//! `scripts/e2e_api_key_auth.py`. The journey, each step consuming the last:
//!
//!   1. MINT   an agent key (offline CLI, committed through raft).
//!   2. LIST   read it back from a SEPARATE process — durable state, not memory.
//!   3. SERVE  boot the daemon against that data dir.
//!   4. AUTH   Ping with the minted key → authenticated.
//!   5. DENY   Ping with an EMPTY token → UNAUTHENTICATED (the security win).
//!   6. DENY   Ping with a well-formed but UNKNOWN key → UNAUTHENTICATED.
//!   7. REVOKE revoke the key, boot again → the same key is now refused.

mod common;

use std::time::Duration;

use common::{cli, free_port, mint_agent_key, Daemon, Vfs};
use tonic::Code;

const SECRET: &str = "e2e-api-key-secret";
const AGENT: &str = "mac-ai";
const ZONE: &str = "sharedzone";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sk_api_key_gates_the_daemon() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let ident = tmp.path().join("identity");
    let ident = ident.to_string_lossy();

    // Auth gating needs no federation — just the token plane on loopback.
    let env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_NO_TLS", "true"),
    ];
    let budget = Duration::from_secs(90);

    // ── 1. MINT ───────────────────────────────────────────────────────
    let key = mint_agent_key(&env, AGENT, &format!("{ZONE}:rw"));

    // ── 2. LIST from a separate process — the record is durable state ───
    let (ok, stdout, stderr) = cli(&env, &["auth", "list"]);
    assert!(ok, "auth list failed: {stderr}");
    assert!(
        stdout.contains(&format!("agent:{AGENT}")),
        "minted key not in the store:\n{stdout}"
    );
    assert!(
        !stdout.contains(&key),
        "the clear-text key must never appear in the store"
    );

    // ── 3-4. SERVE + the minted key authenticates ──────────────────────
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let d = Daemon::spawn(&["--bind-addr", &bind, "--no-tls"], &env);
    let mut c = Vfs::connect_serving(port, budget).await;
    c.ping(&key)
        .await
        .expect("the minted key must authenticate");

    // ── 5. An empty token is nobody (a bare cluster answers this as admin) ──
    assert_eq!(
        c.ping("")
            .await
            .expect_err("empty token must be refused")
            .code(),
        Code::Unauthenticated,
        "empty token must be UNAUTHENTICATED, not silently admitted"
    );

    // ── 6. A well-formed but unknown key is nobody (the store is consulted) ──
    let unknown = format!("sk-{}", "0".repeat(40));
    assert_eq!(
        c.ping(&unknown)
            .await
            .expect_err("unknown key must be refused")
            .code(),
        Code::Unauthenticated,
    );

    // ── 7. REVOKE: stop, revoke, boot again → the same key is refused ───
    drop(d); // kill + release the data-dir lock before the offline revoke
    let (ok, out, err) = cli(&env, &["auth", "revoke", "--key", &key]);
    assert!(ok && out.contains("revoked"), "revoke failed:\n{out}{err}");

    let port2 = free_port();
    let bind2 = format!("127.0.0.1:{port2}");
    let _d2 = Daemon::spawn(&["--bind-addr", &bind2, "--no-tls"], &env);
    let mut c2 = Vfs::connect_serving(port2, budget).await;
    assert!(
        c2.ping(&key).await.is_err(),
        "a revoked key must be refused after reboot — revocation did not propagate"
    );
}
