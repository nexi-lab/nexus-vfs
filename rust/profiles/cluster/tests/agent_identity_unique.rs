//! Black-box E2E: an agent identity is unique cluster-wide.
//!
//! `subject_id` becomes the `agent_id` the mailbox hook stamps into an
//! envelope's `from`; if two credentials could claim one subject, either
//! holder could author the other's mail. `auth mint` enforces uniqueness at
//! mint time against the durable, raft-committed store, with `--allow-existing`
//! as the deliberate escape for key rotation. Offline-only — no daemon, just
//! the real CLI against a real committed store (the unit tests cover the policy
//! in isolation; this proves the flag is wired and the store is consulted end
//! to end). The journey, each step consuming the last:
//!
//!   1. MINT   agent "dup-agent" → succeeds, cert bundle captured.
//!   2. LIST   it is in the durable store, read from a SEPARATE process.
//!   3. CLASH  mint "dup-agent" AGAIN → refused, and the refusal names it.
//!   4. ROTATE mint "dup-agent" --allow-existing → succeeds (a 2nd live cert).
//!   5. OTHER  a different subject_id still mints freely.
//!
//! Agents are cert-only, so the offline mint reads the founder CA — the test
//! bootstraps one into the data dir. Uniqueness is enforced the same way for a
//! cert as for an sk- token (the shared mint-layer `find_active_subject` gate).

mod common;

use common::{cli, mint_agent_cert, write_tls_bundle};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

const SECRET: &str = "e2e-identity-unique-secret";

fn mint_args(subject_id: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "auth".to_string(),
        "mint".to_string(),
        "--subject-type".to_string(),
        "agent".to_string(),
        "--subject-id".to_string(),
        subject_id.to_string(),
        "--name".to_string(),
        "e2e".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

#[test]
fn agent_identity_is_unique_cluster_wide() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_path = tmp.path().join("data");
    std::fs::create_dir_all(&data_path).unwrap();
    // Cert-agent mint reads the founder CA at <data>/tls — bootstrap one.
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");
    write_tls_bundle(&data_path, 1, &ca, &ca_key, &hash);
    let data = data_path.to_string_lossy();
    let ident = tmp.path().join("identity");
    let ident = ident.to_string_lossy();
    let env = [
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
    ];

    // ── 1. MINT ─────────────────────────────────────────────────────────
    let first = mint_agent_cert(&env, "dup-agent");

    // ── 2. LIST — durable, read back from a separate process ────────────
    let (ok, stdout, stderr) = cli(&env, &["auth", "list"]);
    assert!(ok, "auth list failed: {stderr}");
    assert!(
        stdout.contains("agent:dup-agent"),
        "minted subject not in the store:\n{stdout}"
    );

    // ── 3. CLASH — a second credential for the same subject is refused ──
    let clash = mint_args("dup-agent", &[]);
    let clash: Vec<&str> = clash.iter().map(String::as_str).collect();
    let (ok, _out, err) = cli(&env, &clash);
    assert!(!ok, "a duplicate subject must be refused, not minted");
    assert!(
        err.contains("already has an active credential") && err.contains("dup-agent"),
        "the refusal must name the clash: {err}"
    );

    // ── 4. ROTATE — --allow-existing is the deliberate escape ───────────
    let rotate = mint_args("dup-agent", &["--allow-existing"]);
    let rotate: Vec<&str> = rotate.iter().map(String::as_str).collect();
    let (ok, _out, err) = cli(&env, &rotate);
    assert!(ok, "--allow-existing must permit rotation:\n{err}");

    // ── 5. OTHER — a different identity is unaffected ───────────────────
    let second = mint_agent_cert(&env, "other-agent");
    assert_ne!(first, second, "distinct subjects get distinct bundles");
}
