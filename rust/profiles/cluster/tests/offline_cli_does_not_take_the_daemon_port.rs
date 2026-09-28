//! Regression test for nexi-lab/nexus-vfs#346 — a one-shot subcommand must not
//! claim the daemon's raft port.
//!
//! `auth mint` needs a raft node, because a credential is replicated state and the
//! write goes through consensus. It does not need to be REACHABLE: the zone it
//! writes is solo (per-node `root` under `--no-tls`, or the founder's sole-voter
//! control zone, with enrolled joiners refused). But a `ZoneManager` binds the
//! configured address, so the mint took `0.0.0.0:2126` for the second it ran.
//!
//! On a machine already hosting a node that failed with
//! `bind 0.0.0.0:2126 … os error 10048` plus a daemon log, which reads as "the mint
//! is broken" rather than "something else holds the port". It also meant
//! `cargo test --workspace` could not pass on any developer box running a node,
//! because `tests/common/mod.rs::mint_agent_cert` shells out to this subcommand —
//! which is how it was found.
//!
//! The test states the property rather than the symptom: with the configured bind
//! port already held by someone else, the mint still succeeds.
//!
//! It takes TWO fixes, and the second one this test found. The squatter here accepts
//! connections and answers nothing, which is what a wedged daemon or an empty
//! port-forward looks like — and an enrolled node's mint dials its own daemon first.
//! `connect_timeout` bounds the TCP connect, `timeout` bounds a request, and the TLS
//! handshake in between was bounded by neither, so that dial parked forever instead
//! of failing over to the offline path after its stated 15 seconds. `create_channel`
//! now bounds the whole establishment, which is why this test spends ~15s in that
//! failover rather than hanging.

/// This test's cluster secret. A credential is looked up by its HMAC under this, so
/// it only has to be consistent within the test.
const SECRET: &str = "e2e-offline-port-secret";

mod common;

use std::net::TcpListener;

use common::{cli, free_port, mint_agent_cert};
use nexus_raft::transport::{generate_join_token, generate_zone_ca};

/// Bootstrap the founder CA the cert-agent mint reads at `<data>/tls`.
fn founder_data_dir(root: &std::path::Path) -> std::path::PathBuf {
    let data = root.join("data");
    std::fs::create_dir_all(&data).expect("create data dir");
    let (ca, ca_key) = generate_zone_ca("root").expect("gen CA");
    let (_token, hash) = generate_join_token(&ca).expect("join token");
    common::write_tls_bundle(&data, 1, &ca, &ca_key, &hash);
    data
}

#[test]
fn a_mint_succeeds_while_another_process_holds_the_configured_port() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = founder_data_dir(tmp.path());
    let ident = tmp.path().join("identity");

    // Hold the port the mint is configured to bind, for the whole command. A real
    // daemon on this machine is the production version of this listener; a band
    // port keeps the test off whatever else the box is running.
    let port = free_port();
    let squatter = TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("hold 127.0.0.1:{port}: {e}"));

    let bind = format!("0.0.0.0:{port}");
    let data_s = data.to_string_lossy();
    let ident_s = ident.to_string_lossy();
    let env = [
        ("NEXUS_DATA_DIR", data_s.as_ref()),
        ("NEXUS_IDENTITY_DIR", ident_s.as_ref()),
        ("NEXUS_API_KEY_SECRET", SECRET),
        ("NEXUS_BIND_ADDR", bind.as_str()),
    ];

    // The assertion: this used to fail with os error 10048.
    let bundle = mint_agent_cert(&env, "port-squatted-agent");
    assert!(
        bundle.join("credential.json").exists(),
        "mint produced no credential at {}",
        bundle.display()
    );

    // And the record is really in the store — a mint that "succeeded" without
    // committing through consensus would be the other way to pass this test.
    let (ok, stdout, stderr) = cli(&env, &["auth", "list"]);
    assert!(ok, "auth list failed: {stderr}");
    assert!(
        stdout.contains("agent:port-squatted-agent"),
        "minted subject missing from the store:\n{stdout}"
    );

    // Held until here on purpose: dropping it earlier would free the port and let a
    // regression pass.
    drop(squatter);
}
