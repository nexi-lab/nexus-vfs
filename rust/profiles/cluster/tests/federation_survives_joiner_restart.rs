//! Regression: a joiner must be able to READ through its `/agents` federation
//! mount after any restart — including a restart that interrupted the original
//! join before the mount was durable.
//!
//! Root cause (code + experiment): `join_zones_for_boot` joins the zone (logs
//! "Zone registered") FIRST, then wires the `/agents → sharedzone` mount via a
//! separate `mount_async` to the per-node SOLO root. The two commit to
//! different raft groups, so they cannot be atomic. A joiner dropped in that
//! window resumes with the zone fully replicated (raft is fine) yet the mount
//! MISSING — because the mount is LOCAL DERIVED state cached from the peer's
//! `DiscoverZones` topology, not raft state, and `BootAction::Resume` used to
//! trust on-disk state as complete. So `/agents/*` was permanently unroutable
//! (`readdir /agents` → NotMounted) despite the data being present.
//!
//! Fix: `Resume` re-derives federation mounts from peers every boot (the
//! `mount -a` model), idempotently. These tests drive `--no-tls` so a plaintext
//! client verifies the REAL read path (stat + read content), not just a log.

mod common;

use std::time::Duration;

use common::{await_replicated, free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(90);

fn founder_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    mounts: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_FEDERATION_ZONES", ZONE),
        ("NEXUS_FEDERATION_MOUNTS", mounts),
        ("RUST_LOG", LOG_FILTER),
    ]
}

fn joiner_env<'a>(
    data: &'a str,
    id: &'a str,
    adv: &'a str,
    peers: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_PEERS", peers),
        ("RUST_LOG", LOG_FILTER),
    ]
}

/// Boot a 2-node federation, verify baseline replication, restart the joiner,
/// and return whether the founder's post-restart write reaches AND resolves on
/// the joiner (deep read path) — plus read-path evidence for diagnosis.
async fn replication_survives_restart(confirm_baseline: bool) -> (bool, String) {
    let zone_registered = format!("Zone '{ZONE}' registered");
    let tmp = tempfile::tempdir().expect("tempdir");
    let fport = free_port();
    let jport = free_port();
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = fadv.clone();

    let mut founder = Daemon::spawn(
        &["--bind-addr", &fadv],
        &founder_env(&fdata, &fid, &fadv, &mounts),
    );
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms + persists sharedzone mount");
    let mut fc = Vfs::dial(fport).await.expect("dial founder");

    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jadv],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner joins sharedzone");
    let mut jc = Vfs::dial(jport).await.expect("dial joiner");

    // Baseline: replication works. Skipping this (confirm_baseline=false) drops
    // the joiner right after it *registered* the zone locally — possibly BEFORE
    // the founder's `[1,2]` ConfChange has replicated + persisted onto it, which
    // is the mid-join window from_stamp's dance hits.
    if confirm_baseline {
        let before = format!("{MOUNT}/before.txt");
        fc.write_file(&before, b"before", "")
            .await
            .expect("founder write #1");
        await_replicated(&mut jc, &before, "", BUDGET).await;
    }

    // Restart the joiner.
    drop(jc);
    drop(joiner);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut joiner = Daemon::spawn(
        &["--bind-addr", &jadv],
        &joiner_env(&jdata, &jid, &jadv, &peers),
    );
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("restarted joiner re-registers sharedzone");
    let mut jc = Vfs::dial(jport).await.expect("re-dial joiner");

    // After: does the founder's write reach the joiner AND resolve through the
    // `/agents` mount? Deep read-path — stat (mount routes + entry visible) THEN
    // read (content replicated). A joiner that lost its `/agents → sharedzone`
    // mount on restart fails this even though sharedzone is fully raft-replicated
    // (the mount, not raft, is the gap this test guards).
    let after = format!("{MOUNT}/after.txt");
    fc.write_file(&after, b"after", "")
        .await
        .expect("founder write #2");
    let deadline = std::time::Instant::now() + BUDGET;
    let mut replicated = false;
    while std::time::Instant::now() < deadline {
        if jc.stat_found(&after, "").await {
            if let Ok(v) = jc.read_file(&after, "").await {
                if v.as_slice() == b"after" {
                    replicated = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // On failure, surface the read-path evidence: raft may be fully replicated
    // on the joiner yet `/agents/after.txt` not resolve if the
    // `/agents → sharedzone` mount was not re-established after the restart.
    let f_agents = fc.readdir_names(MOUNT, "").await;
    let j_agents = jc.readdir_names(MOUNT, "").await;
    let j_read = jc.read_file(&after, "").await;
    let both = format!(
        "founder readdir({MOUNT})={f_agents:?}\njoiner readdir({MOUNT})={j_agents:?}\n\
         joiner read({after})={j_read:?}"
    );
    drop(joiner);
    drop(founder);
    (replicated, both)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replication_survives_a_plain_joiner_restart() {
    let (ok, tail) = replication_survives_restart(true).await;
    assert!(
        ok,
        "plain restart lost replication.\n--- restarted joiner tail ---\n{tail}"
    );
}

/// The pinned root cause: a joiner dropped right after local zone registration
/// (`confirm_baseline=false`) — i.e. BEFORE `mount_async` durably wired the
/// `/agents → sharedzone` mount — must still self-heal on restart. Before the
/// fix it resumed with the zone replicated but the mount missing, so
/// `/agents/after.txt` was unroutable forever. The fix re-derives federation
/// mounts from peers on every Resume (the `mount -a` model).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replication_survives_a_joiner_dropped_before_the_mount_is_durable() {
    let (ok, evidence) = replication_survives_restart(false).await;
    assert!(
        ok,
        "a joiner dropped mid-join (before its `/agents → sharedzone` mount was durable) came \
         back unable to READ `/agents/after.txt` — sharedzone is raft-replicated, but the mount \
         was not re-established on Resume so the path is unroutable.\n{evidence}"
    );
}
