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
