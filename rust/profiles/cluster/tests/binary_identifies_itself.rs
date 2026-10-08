//! Black-box: `--version` names the binary you ran, and says what it is made of.
//!
//! `nexusd-cohost` is the same daemon with one service declaration swapped, and it
//! reported itself as `nexusd-cluster` because the clap `name` lived in the library
//! rather than with whoever ships the executable. The two fail identically when the
//! wrong one is deployed — sessions sit in `warming_up`, since the binary that hosts
//! agents is the other one — so the first question an incident asks ("which binary is
//! this pod running?") had no answer. This pins that it now does.

mod common;

use common::bin;
use std::process::Command;
use std::time::Duration;

/// The daemon's own `--version` names it and carries what decides plugin loading.
#[test]
fn version_names_this_binary_and_its_abi() {
    let out = Command::new(bin())
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(out.status.success(), "--version must succeed");
    let said = String::from_utf8_lossy(&out.stdout).trim().to_string();

    assert!(
        said.starts_with("nexusd-cluster "),
        "--version must lead with the binary's own name; got {said:?}"
    );
    // The ABI version is the number that decides whether a plugin dylib can load at
    // all, which is why it belongs in the answer an operator can reach without the
    // wire.
    assert!(
        said.contains("plugin-abi "),
        "--version must report the plugin ABI; got {said:?}"
    );
    // And it must not be the bare name with no build in it — the shape that read as an
    // answer while telling an upgrader nothing.
    assert_ne!(said, "nexusd-cluster", "a name alone is not a version");
}

/// Usage errors name the binary too, since that is the line a confused operator reads.
#[test]
fn a_bad_flag_names_this_binary() {
    let out = Command::new(bin())
        .arg("--definitely-not-a-flag")
        .output()
        .expect("run with a bad flag");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("nexusd-cluster"),
        "a usage error must name the program; got {said:?}"
    );
}

/// The daemon says at boot whether it can actually HOST an agent.
///
/// `--version` above answers "which binary is this?". This answers the question
/// that follows and used to have no answer: "can it run an agent loop?"
///
/// They are different questions with the same symptom. `start_session_v1`
/// succeeds on this binary — it registers identity, ownership and the `/proc`
/// subtree, which are real and separately tested — but it cannot run the agent
/// loop, because `nexusd-cluster` cannot embed the sudocode runtime (the
/// dependency edge is one-way: sudocode → nexus-vfs). The caller sees
/// `session_endpoint: None`, `os_pid: null`, and a session that never leaves
/// WARMING_UP. Nothing in that set says "wrong binary", and a cross-machine
/// bring-up spent a debugging cycle looking for the fault in its own call.
///
/// Gated on the log rather than on a `start_session` round trip on purpose: the
/// capability is a property of the BUILD, settled before any request arrives, so
/// asserting it needs no session and no auth posture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_says_whether_this_build_can_host_an_agent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let port = common::free_port();
    let data = tmp.path().join("data");
    let data = data.to_string_lossy();
    let id = tmp.path().join("id");
    let id = id.to_string_lossy();
    let adv = format!("127.0.0.1:{port}");

    let env = vec![
        ("NEXUS_DATA_DIR", data.as_ref()),
        ("NEXUS_IDENTITY_DIR", id.as_ref()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", common::LOG_FILTER),
    ];

    let mut daemon = common::Daemon::spawn(&["--bind-addr", &adv], &env);

    // This build ships no in-process provider, so the refusal half is what must
    // appear. The assertion names the capability, not the binary: a build that
    // DOES wire one logs the WIRED line instead and would fail here, which is
    // the correct failure — it would mean this test is running against a
    // different build than it claims.
    daemon
        .wait_for_log("NO in-process runtime provider", Duration::from_secs(90))
        .await
        .expect(
            "a build without an agent runtime must say so at boot — otherwise the \
             only symptom is a session stuck in WARMING_UP",
        );

    let said = daemon.drain();
    assert!(
        said.contains("start_session_v1"),
        "the line must name the RPC that is affected, so a reader does not have \
         to guess which call degrades: {said}"
    );
}
