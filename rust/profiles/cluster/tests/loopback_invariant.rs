//! Black-box E2E: no-auth is legal only on loopback, and the DAEMON enforces
//! it (not just the `auth_posture` decision fn the unit tests pin).
//!
//! Serving without authentication is a trusted-local-backend on 127.0.0.1
//! (how moss runs it) but an open door on 0.0.0.0 — and the two are one config
//! line apart. This pins the process: it actually refuses to come up on a
//! reachable bind with no auth, the refusal names a remedy, and the shape moss
//! depends on still boots with zero flags. Rust replacement for the retired
//! `scripts/e2e_loopback_invariant.py`.
//!
//!   1. loopback  + --no-tls + no secret   → boots (moss's shape; zero flags)
//!   2. 0.0.0.0   + --no-tls + no secret   → REFUSES, and names every way out
//!   3. 0.0.0.0   + --no-tls + --insecure  → boots (already-open CI cluster)
//!   4. 0.0.0.0   + --no-tls + secret      → boots (authenticating callers)
//!   5. serve-local --port                 → boots (the embedders' shorthand)

mod common;

use std::time::Duration;

use common::{free_port, Daemon};

const BUDGET: Duration = Duration::from_secs(75);

fn dirs(tmp: &std::path::Path, tag: &str) -> (String, String) {
    let d = tmp.join(format!("{tag}-data"));
    let i = tmp.join(format!("{tag}-id"));
    (
        d.to_string_lossy().into_owned(),
        i.to_string_lossy().into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_auth_is_legal_only_on_loopback() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // ── 1. moss's shape: loopback + no-tls + no secret → boots, zero flags ──
    {
        let (data, id) = dirs(tmp.path(), "c1");
        let port = free_port();
        let bind = format!("127.0.0.1:{port}");
        let mut d = Daemon::spawn(
            &["--bind-addr", &bind, "--no-tls"],
            &[("NEXUS_DATA_DIR", &data), ("NEXUS_IDENTITY_DIR", &id)],
        );
        d.wait_tcp(port, BUDGET)
            .await
            .expect("loopback + no-tls + no secret must boot with no flags");
    }

    // ── 2. the open door: 0.0.0.0 + no-tls + no secret → REFUSES ───────────
    {
        let (data, id) = dirs(tmp.path(), "c2");
        let port = free_port();
        let bind = format!("0.0.0.0:{port}");
        let mut d = Daemon::spawn(
            &["--bind-addr", &bind, "--no-tls"],
            &[("NEXUS_DATA_DIR", &data), ("NEXUS_IDENTITY_DIR", &id)],
        );
        let out = d
            .wait_exit(BUDGET)
            .await
            .expect("an unauthenticated daemon on 0.0.0.0 MUST refuse to boot");
        assert!(
            out.contains("refusing to start"),
            "the refusal must say it is refusing; got:\n{out}"
        );
        // A refusal that does not name a remedy is a wall, not a guard.
        for remedy in [
            "NEXUS_API_KEY_SECRET",
            "--insecure-no-auth",
            "loopback",
            "--no-tls",
        ] {
            assert!(
                out.contains(remedy),
                "the refusal must mention {remedy:?}; got:\n{out}"
            );
        }
    }

    // ── 3. the escape hatch: 0.0.0.0 + --insecure-no-auth → boots, loudly ──
    {
        let (data, id) = dirs(tmp.path(), "c3");
        let port = free_port();
        let bind = format!("0.0.0.0:{port}");
        let mut d = Daemon::spawn(
            &["--bind-addr", &bind, "--no-tls", "--insecure-no-auth"],
            &[("NEXUS_DATA_DIR", &data), ("NEXUS_IDENTITY_DIR", &id)],
        );
        d.wait_tcp(port, BUDGET)
            .await
            .expect("--insecure-no-auth must still allow a reachable bind");
    }

    // ── 4. authenticating: 0.0.0.0 + NEXUS_API_KEY_SECRET → boots ──────────
    {
        let (data, id) = dirs(tmp.path(), "c4");
        let port = free_port();
        let bind = format!("0.0.0.0:{port}");
        let mut d = Daemon::spawn(
            &["--bind-addr", &bind, "--no-tls"],
            &[
                ("NEXUS_DATA_DIR", &data),
                ("NEXUS_IDENTITY_DIR", &id),
                ("NEXUS_API_KEY_SECRET", "e2e-loopback-invariant"),
            ],
        );
        d.wait_tcp(port, BUDGET)
            .await
            .expect("a credential policy must permit a reachable bind");
    }

    // ── 5. serve-local shorthand == loopback + no-tls, no flags → boots ────
    {
        let (data, id) = dirs(tmp.path(), "c5");
        let port = free_port();
        let p = port.to_string();
        let mut d = Daemon::spawn(
            &["serve-local", "--port", &p],
            &[("NEXUS_DATA_DIR", &data), ("NEXUS_IDENTITY_DIR", &id)],
        );
        d.wait_tcp(port, BUDGET)
            .await
            .expect("serve-local must boot on loopback with no flags");
    }
}
