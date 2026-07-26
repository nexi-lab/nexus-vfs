//! Black-box E2E regression: a founder whose `root` ALREADY exists on disk —
//! so `plan_boot_action` returns `Resume`, SKIPPING the `StaticFounder` arm —
//! must STILL establish its own declared `--cluster-init` topology (found
//! `sharedzone`, mount it at `/agents`) from its OWN SSOT, peer-independent.
//! Otherwise `/agents/*` silently falls back to node-local root, and an A2A
//! mailbox there never replicates cross-machine.
//!
//! Deterministic trigger for the live `auth mint`-before-boot cause (mint
//! creates `root` before the first daemon boot, forcing `Resume`): here the
//! founder is booted ONCE rootless (no `--cluster-init`, so only `root` lands
//! on disk and `sharedzone` is NEVER founded), then RE-booted WITH
//! `--cluster-init sharedzone` + `--cluster-init-mount /agents=sharedzone`. The
//! second boot takes `Resume` (root-on-disk wins over `--cluster-init` in
//! `plan_boot_action`), so only the Resume-founds-declared-topology fix makes
//! `sharedzone` appear.
//!
//! Proof is end-to-end over a REAL two-node federation: a joiner reaches
//! `sharedzone` purely via DiscoverZones and reads back a byte the founder
//! wrote under `/agents`. Without the fix the founder never founds/registers
//! `sharedzone`, the joiner comes up rootless, and nothing replicates.

mod common;

use std::time::Duration;

use common::{await_replicated, free_port, Daemon, Vfs, LOG_FILTER};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(90);

/// Base env for a loopback, auth-off, no-TLS node — the founder adds
/// `--cluster-init*` on its second boot; the joiner adds `NEXUS_PEERS`.
fn base_env<'a>(data: &'a str, id: &'a str, adv: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("NEXUS_DATA_DIR", data),
        ("NEXUS_IDENTITY_DIR", id),
        ("NEXUS_ADVERTISE_ADDR", adv),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn founder_resume_founds_its_declared_topology_then_replicates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fport = free_port();
    let jport = free_port();

    let fdata = tmp.path().join("f-data");
    let fdata = fdata.to_string_lossy();
    let fid = tmp.path().join("f-id");
    let fid = fid.to_string_lossy();
    let jdata = tmp.path().join("j-data");
    let jdata = jdata.to_string_lossy();
    let jid = tmp.path().join("j-id");
    let jid = jid.to_string_lossy();

    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");
    let fbind = format!("127.0.0.1:{fport}");
    let jbind = format!("127.0.0.1:{jport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let peers = format!("127.0.0.1:{fport}");
    let zone_registered = format!("Zone '{ZONE}' registered");

    // ── 1. Boot the founder ROOTLESS once (no --cluster-init) so `root` lands
    //       on disk WITHOUT `sharedzone` ever being founded. Then kill it. ──
    {
        let mut f0 = Daemon::spawn(&["--bind-addr", &fbind], &base_env(&fdata, &fid, &fadv));
        f0.wait_tcp(fport, BUDGET)
            .await
            .expect("rootless founder serves (boot 1)");
        // Root is founded before the gRPC server starts, so serving ⇒ root is
        // committed; a short beat covers redb fsync before the kill.
        tokio::time::sleep(Duration::from_secs(1)).await;
    } // drop → SIGKILL: `root` persisted, `sharedzone` never existed.

    // ── 2. Re-boot the SAME founder WITH its declared topology. `root` on disk
    //       ⇒ plan_boot_action = Resume ⇒ the StaticFounder arm is SKIPPED, so
    //       only the Resume-founds-declared-topology fix founds `sharedzone`. ──
    let mut founder_env = base_env(&fdata, &fid, &fadv);
    founder_env.push(("NEXUS_CLUSTER_INIT", ZONE));
    founder_env.push(("NEXUS_CLUSTER_INIT_MOUNTS", &mounts));
    let mut founder = Daemon::spawn(&["--bind-addr", &fbind], &founder_env);
    founder
        .wait_tcp(fport, BUDGET)
        .await
        .expect("founder serves (boot 2 / resume)");
    // THE REGRESSION GATE: without the fix, Resume ignores --cluster-init and
    // `sharedzone` is never founded, so this log never appears and the test
    // fails right here.
    founder.wait_for_log(&zone_registered, BUDGET).await.expect(
        "founder MUST found+register `sharedzone` on Resume from its own \
             --cluster-init SSOT (root pre-existed, so StaticFounder was skipped)",
    );

    // ── 3. Boot the joiner; it reaches `sharedzone` purely via DiscoverZones. ─
    let mut joiner_env = base_env(&jdata, &jid, &jadv);
    joiner_env.push(("NEXUS_PEERS", &peers));
    let mut joiner = Daemon::spawn(&["--bind-addr", &jbind], &joiner_env);
    joiner.wait_tcp(jport, BUDGET).await.expect("joiner serves");
    joiner
        .wait_for_log(&zone_registered, BUDGET)
        .await
        .expect("joiner MUST join `sharedzone` (only possible if the founder registered it)");

    // ── 4. End-to-end: founder writes under /agents, joiner reads it back —
    //       proves /agents routes to the REPLICATED sharedzone, not node-local
    //       root (a root-bound mount would never reach the joiner). ──
    let mut fc = Vfs::dial(fport).await.expect("dial founder");
    let mut jc = Vfs::dial(jport).await.expect("dial joiner");
    let probe = format!("{MOUNT}/health.txt");
    let payload = b"resume-founds-topology-v1";
    fc.write_file(&probe, payload, "")
        .await
        .expect("founder writes under /agents");
    await_replicated(&mut jc, &probe, "", BUDGET).await;
    let got = jc.read_file(&probe, "").await.expect("joiner reads");
    assert_eq!(
        got, payload,
        "joiner must read the founder's /agents bytes back — proves the \
         Resume-founded `sharedzone` is mounted at /agents and replicates"
    );
}
