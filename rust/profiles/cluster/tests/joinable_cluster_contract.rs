//! Black-box E2E: a REACHABLE founder is not a JOINABLE one, and the operator must be
//! able to tell the difference from the logs alone.
//!
//! This is the gap a cross-machine bring-up fell into. A founder was up, a second
//! machine reached its gRPC endpoint, `DiscoverZones` answered with zero zones, and the
//! joiner retried for its whole budget and exited. Everything the joiner's guidance
//! named was already true — founder started, past its topology gate, address correct —
//! because the one thing that was false (no path had been mounted at a zone, so there
//! was no federation zone to discover) appeared in no message on either side. The
//! `share` that would have fixed it then reported success after copying nothing, and
//! could not run at all while the daemon held the data dir.
//!
//! What these tests pin is the pair of facts an operator needs:
//!
//! * a node SAYS what it publishes, and "nothing" is stated as such (the same read
//!   `DiscoverZones` answers from, so the log and the wire cannot disagree);
//! * `share` refuses to publish an empty subtree, and refuses without creating a zone.
//!
//! Every assertion here is on observable output of the real binary — boot logs, exit
//! status, and what is on disk afterwards.

mod common;

use std::time::Duration;

use common::{cli, free_port, Daemon, LOG_FILTER};

const BUDGET: Duration = Duration::from_secs(90);
const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";

/// The line that answers "is your zone up?" — stated once at the convergence gate.
const PUBLISHES_NOTHING: &str = "this node publishes NO federation zone";
const PUBLISHES_SOMETHING: &str = "federation zone(s) — a joiner pointed here";

fn env<'a>(data: &'a str, id: &'a str, adv: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ]
}

/// A plain daemon — no `--cluster-init*` — must say it publishes nothing.
///
/// This is the state that looked healthy: root bootstrapped, "Static topology applied:
/// 0 mounts", data plane ready, and a joiner pointed here would discover nothing. Note
/// the boot log is asserted to name the REMEDY too: an operator reading it should not
/// have to know that `DiscoverZones` serves the root zone's DT_MOUNT entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_with_no_mounts_says_it_publishes_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    let mut d = Daemon::spawn(&["--bind-addr", &adv], &env(&data, &id, &adv));
    d.wait_for_log(PUBLISHES_NOTHING, BUDGET)
        .await
        .expect("a daemon publishing no federation zone must say so at boot");

    let log = d.drain();
    assert!(
        log.contains("--cluster-init-mount"),
        "the line must carry the no-downtime remedy, not just the diagnosis:\n{log}"
    );
    assert!(
        !log.contains(PUBLISHES_SOMETHING),
        "a node with no mounts must not also claim to publish zones:\n{log}"
    );
}

/// A founder that DID declare a mount must report exactly what it publishes.
///
/// The counterpart assertion: the "nothing" line above is only useful if the positive
/// case is distinguishable, and the count comes from the same accessor `DiscoverZones`
/// answers from — so this also pins that a declared mount really is discoverable by the
/// time boot says the data plane is ready.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_founder_with_a_mount_reports_what_it_publishes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let mounts = format!("{MOUNT}={ZONE}");
    let mut e = env(&data, &id, &adv);
    e.push(("NEXUS_CLUSTER_INIT", ZONE));
    e.push(("NEXUS_CLUSTER_INIT_MOUNTS", &mounts));

    let mut d = Daemon::spawn(&["--bind-addr", &adv], &e);
    d.wait_for_log(PUBLISHES_SOMETHING, BUDGET)
        .await
        .expect("a founder with a declared mount must report it as published");

    let log = d.drain();
    assert!(
        log.contains(&format!("{MOUNT}={ZONE}")),
        "the report must name the mount an operator can hand to a joiner:\n{log}"
    );
    assert!(
        !log.contains(PUBLISHES_NOTHING),
        "a founder that publishes a zone must not say it publishes none:\n{log}"
    );
}

/// `share` of a path that holds nothing is refused, and refused BEFORE it creates
/// anything.
///
/// Copying zero entries is almost always a wrong path — a typo, the wrong parent zone,
/// or a shell that rewrote the argument (Git Bash turns a leading-slash `/conversations`
/// into `C:/Program Files/Git/conversations`). Reporting success there leaves a zone
/// whose root path does not exist, mounted, and looking published. The refusal must also
/// come before `create_zone`: a failed share that still leaves a raft group behind is
/// the mess this guards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_refuses_an_empty_subtree_and_creates_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_path = tmp.path().join("data");
    let data = data_path.to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let e = env(&data, &id, &adv);

    // A data dir with a root zone and nothing in it: boot once, then stop, because
    // `share` is offline and needs the lock.
    {
        let mut d = Daemon::spawn(&["--bind-addr", &adv], &e);
        d.wait_for_log("VFS data plane ready", BUDGET)
            .await
            .expect("daemon boots and creates the root zone");
    }

    let (ok, out, err) = cli(&e, &["share", "/nothing-here", "--zone-id", "probe-zone"]);
    assert!(
        !ok,
        "sharing a path that holds nothing must fail:\nstdout:{out}\nstderr:{err}"
    );
    assert!(
        !err.to_lowercase().contains("panic"),
        "the refusal must be an error, not a panic:\n{err}"
    );
    assert!(
        err.contains("/nothing-here"),
        "the refusal must show the path AS RECEIVED — that is where a shell-rewritten \
         argument becomes visible:\n{err}"
    );
    assert!(
        err.contains("--allow-empty"),
        "the refusal must name the way to say 'I meant it':\n{err}"
    );
    assert!(
        !data_path.join("probe-zone").exists(),
        "a refused share must leave no zone behind; found {:?}",
        data_path.join("probe-zone"),
    );

    // The opt-out works, and what it creates really is publishable: with --mount-at,
    // the next boot reports the zone as discoverable. That closes the loop the refusal
    // protects — refusing an accident without blocking the deliberate case.
    let (ok, out, err) = cli(
        &e,
        &[
            "share",
            "/nothing-here",
            "--zone-id",
            "probe-zone",
            "--mount-at",
            "/nothing-here",
            "--allow-empty",
        ],
    );
    assert!(
        ok,
        "--allow-empty must permit a deliberate empty share:\nstdout:{out}\nstderr:{err}"
    );

    let mut d = Daemon::spawn(&["--bind-addr", &adv], &e);
    d.wait_for_log(PUBLISHES_SOMETHING, BUDGET)
        .await
        .expect("the zone created by an explicit empty share is published at the next boot");
    assert!(
        d.drain().contains("/nothing-here=probe-zone"),
        "the published mount must be the one that was shared"
    );
}

/// An offline subcommand against a data dir the daemon holds must explain itself.
///
/// `share` opens the store directly, so a running daemon blocks it — and what redb says
/// ("Database already open. Cannot acquire lock.") is no help unless you already knew
/// this was an offline tool. The guidance has to name the data dir, the fact that
/// another process holds it, and the no-downtime alternative for the thing the operator
/// was almost certainly trying to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_against_a_running_daemon_explains_itself() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let e = env(&data, &id, &adv);

    let mut d = Daemon::spawn(&["--bind-addr", &adv], &e);
    d.wait_tcp(port, BUDGET)
        .await
        .expect("daemon serves (holds the data-dir lock)");

    let (ok, out, err) = cli(&e, &["share", MOUNT, "--zone-id", ZONE]);
    assert!(
        !ok,
        "an offline share against a running daemon must fail:\nstdout:{out}\nstderr:{err}"
    );
    assert!(
        !err.to_lowercase().contains("panic"),
        "it must fail with the reason, not a panic over it:\n{err}"
    );
    assert!(
        err.contains(&data),
        "the error must name the data dir that is held:\n{err}"
    );
    assert!(
        err.contains("--cluster-init-mount") && err.contains("stop the daemon"),
        "it must offer both the no-downtime path and the offline one:\n{err}"
    );
}
