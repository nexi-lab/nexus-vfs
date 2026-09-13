//! Black-box E2E gate: a malformed `--cluster-init` zone id stops the daemon
//! before anything is created from it, and says why.
//!
//! The rule itself is unit-tested in `contracts::zone_id`. What this covers is
//! the part a unit test cannot: that the check is actually *reached* on the boot
//! path. A validator nothing calls is the same as no validator, and that is not
//! a hypothetical failure mode here — the format was documented for a long time
//! while `parse_zones_str` split on commas and `create_zone` took the id as an
//! opaque `&str`.
//!
//! The second case is the one worth arguing about. A zone id is the first path
//! segment of everything in its zone, so it cannot be renamed: pointing
//! `--cluster-init` at a different id creates a NEW empty zone and abandons the
//! old one, silently, at every layer. That is why the id is refused up front —
//! and equally why a node that ALREADY has state must not start refusing on an
//! upgrade. Turning a new lint into an outage for a deployment that has been
//! running for months is a worse failure than the one being prevented.

mod common;

use common::{cli, Daemon};
use std::time::Duration;

/// Ids covering one violation each, so a failure names which rule broke rather
/// than "something was rejected".
const MALFORMED: &[(&str, &str)] = &[
    ("ab", "shorter than the minimum"),
    ("-leading", "leading hyphen"),
    ("trailing-", "trailing hyphen"),
    ("Has-Upper", "uppercase"),
    ("has_underscore", "character outside the set"),
];

#[tokio::test]
async fn malformed_cluster_init_zone_id_refuses_to_boot() {
    for (zone, why) in MALFORMED {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = common::free_port();
        let mut daemon = Daemon::spawn(
            &[
                "serve-local",
                "--port",
                &port.to_string(),
                "--data-dir",
                dir.path().to_str().expect("utf-8 tempdir"),
                // `--cluster-init=<id>`, not `--cluster-init <id>`: an id starting
                // with a hyphen is otherwise eaten by clap as a short flag, and
                // the daemon refuses for the wrong reason — which would leave
                // this test green while proving nothing about the zone rule.
                &format!("--cluster-init={zone}"),
            ],
            &[],
        );

        let outcome = daemon.wait_tcp(port, Duration::from_secs(20)).await;
        let logs = match outcome {
            Ok(()) => panic!("daemon served with a malformed zone id ({why}): {zone:?}"),
            Err(output) => output,
        };

        // The operator has to be able to act on this. "invalid" alone would send
        // them to the wrong place — the id is unchangeable after creation, so
        // the message has to say that too.
        assert!(
            logs.contains(zone),
            "refusal for {why} must name the offending id {zone:?}:\n{logs}"
        );
        assert!(
            logs.contains("--cluster-init"),
            "refusal for {why} must name the flag that carried it:\n{logs}"
        );
    }
}

#[tokio::test]
async fn a_conforming_zone_id_still_boots() {
    // The half that keeps the test above honest: "refuses everything" would
    // satisfy it just as well as "refuses the malformed ones".
    let dir = tempfile::tempdir().expect("tempdir");
    let port = common::free_port();
    let mut daemon = Daemon::spawn(
        &[
            "serve-local",
            "--port",
            &port.to_string(),
            "--data-dir",
            dir.path().to_str().expect("utf-8 tempdir"),
            "--cluster-init",
            "cloud-user-1001",
        ],
        &[],
    );

    daemon
        .wait_tcp(port, Duration::from_secs(30))
        .await
        .expect("a conforming zone id must still found a cluster");
}

/// `share` is the other way an operator NAMES a new zone, and it was the gap
/// the boot check left: a flag refused at startup says nothing about an id
/// chosen later from the command line.
///
/// Same rule, same reason, different door — and the refusal has to carry the
/// "cannot be changed afterwards" part here too, because that is what makes a
/// wrong id expensive rather than annoying.
#[tokio::test]
async fn share_refuses_a_malformed_new_zone_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().to_str().expect("utf-8 tempdir").to_string();

    for (zone, why) in MALFORMED {
        // `--zone-id=<id>`, not `--zone-id <id>`: an id starting with a hyphen
        // is otherwise eaten by clap as a short flag and the CLI refuses for the
        // wrong reason — green test, nothing proven. Same trap the boot case
        // above documents.
        let (ok, out, err) = cli(
            &[("NEXUS_DATA_DIR", data.as_str())],
            &["share", &format!("--zone-id={zone}"), "/some/subtree"],
        );
        assert!(
            !ok,
            "share must refuse a {why} zone id ({zone:?}).
stdout: {out}
stderr: {err}"
        );
        let said = format!("{out}{err}");
        assert!(
            said.contains(zone),
            "the refusal for {why} must name the offending id {zone:?}: {said}"
        );
        assert!(
            said.contains("cannot be changed"),
            "the refusal for {why} must say the id is permanent, or it reads as              a style complaint: {said}"
        );
    }
}
