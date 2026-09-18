//! Black-box E2E (acceptance 2/4, R7/R9/R10): the typed ZoneRuntime surface
//! returns REAL receipts — physical read-back facts, not phantom success —
//! and a join never degrades into a create.
//!
//!   1. CREATE on the founder: `outcome=CREATED`, cluster facts with
//!      `commit_index > 0` and `voter_count >= 1` (the raft really formed),
//!      the operation id echoed back.
//!   2. MOUNT: `outcome=MOUNTED` with the DT_MOUNT read-back facts (the
//!      parent's state machine actually holds the entry, `i_links_count`
//!      moved to 1).
//!   3. BYTES: a real typed Write/Read round-trip THROUGH the mounted zone
//!      — the zone is a physical filesystem, not a metadata illusion.
//!   4. JOIN on a second node: `outcome=JOINED` (never CREATED — R9), the
//!      joiner's status answers RESIDENT with live cluster facts.
//!   5. JOIN of a zone that does not exist: the joiner must NOT bootstrap
//!      it into existence (no founder fallback on the typed path).

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;

const ZONE: &str = "tenant-a";
const GHOST: &str = "zone-never-existed";
const BUDGET: Duration = Duration::from_secs(120);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_zone_lifecycle_returns_real_receipts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();

    let fport = free_port();
    let jport = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");

    // ── Founder (NoAuth loopback: every caller is the single trust domain) ──
    let fenv = env(&fdata, &fid, &fadv);
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv, "--no-tls"], &fenv);
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("boot must wire the typed zone runtime surface (journal zone bound)");
    let mut f_rt = ZoneRuntime::dial_ready(fport, BUDGET).await;

    // ── 1. CREATE: a receipt with real raft facts, outcome explicit ──
    let receipt = f_rt
        .zone_create(ZONE, &[], "op-create-tenant-a-0001", "")
        .await
        .expect("typed ZoneCreate must succeed on the founder");
    assert_eq!(receipt.outcome, "CREATED", "a fresh create says CREATED");
    assert_eq!(receipt.operation_id, "op-create-tenant-a-0001");
    assert_eq!(receipt.zone_id, ZONE);
    assert!(!receipt.replayed, "first execution is not a replay");
    let facts = receipt
        .cluster
        .expect("create receipt carries cluster facts");
    assert!(facts.has_store, "the new zone has a real raft store");
    assert!(
        facts.commit_index > 0,
        "commit_index must be past zero (raft formed): {facts:?}"
    );
    assert!(facts.voter_count >= 1, "the founder is a voter: {facts:?}");
    assert!(facts.term >= 1, "a term was won: {facts:?}");

    // ── 2. MOUNT: DT_MOUNT read-back facts in the receipt ──
    let mount = f_rt
        .zone_mount("root", "/tenant-a", ZONE, "op-mount-tenant-a-0002", "")
        .await
        .expect("typed ZoneMount must succeed");
    assert_eq!(mount.outcome, "MOUNTED");
    let mf = mount.mount.expect("mount receipt carries mount facts");
    assert_eq!(mf.mount_path, "/tenant-a");
    assert_eq!(mf.target_zone_id, ZONE);
    assert_eq!(mf.i_links_count, 1, "the target's i_links must read back 1");

    // ── 3. BYTES: typed Write → Read through the mounted zone ──
    let mut vfs = Vfs::dial_ready(fport, BUDGET).await;
    let payload = b"zone-runtime-bytes-roundtrip-payload".to_vec();
    vfs.mkdir("/tenant-a", "").await.expect("mkdir under mount");
    vfs.write_file("/tenant-a/hello.txt", &payload, "")
        .await
        .expect("typed Write through the mounted zone");
    let back = vfs
        .read_file("/tenant-a/hello.txt", "")
        .await
        .expect("typed Read back through the mounted zone");
    assert_eq!(back, payload, "physical bytes must round-trip");

    // ── 4. JOIN on a second node: JOINED, never CREATED (R9) ──
    let jenv_join = {
        let mut e = env(&jdata, &jid, &jadv);
        e.push(("NEXUS_PEERS", fadv.as_str()));
        e
    };
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv, "--no-tls"], &jenv_join);
    joiner
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("joiner boots its typed surface too");
    let mut j_rt = ZoneRuntime::dial_ready(jport, BUDGET).await;

    let joined = j_rt
        .zone_join(ZONE, &[fadv.clone()], false, "op-join-tenant-a-0003", "")
        .await
        .expect("typed ZoneJoin must reach the founder");
    assert_eq!(
        joined.outcome, "JOINED",
        "the receipt must say JOINED — a join may never masquerade as a create"
    );
    // The joiner now sees the zone as RESIDENT with live facts.
    let j_status = j_rt.zone_status(ZONE, "").await.expect("joiner status");
    assert_eq!(j_status.presence, i32::from(Presence::Resident));

    // ── 5. JOIN of a nonexistent zone must NOT bootstrap it (R9) ──
    // The typed path has no founder fallback: the joiner may hold a local
    // learner runtime WAITING for a leader's snapshot, but it must never
    // SELF-FOUND — no voters, no committed log, no leader elected.
    let _ = j_rt
        .zone_join(GHOST, &[fadv.clone()], true, "op-join-ghost-0004", "")
        .await;
    let ghost_status = j_rt
        .zone_status(GHOST, "")
        .await
        .expect("status of the never-created zone");
    let ghost_facts = ghost_status
        .cluster
        .as_ref()
        .expect("a local learner runtime reports its (empty) facts");
    assert_eq!(
        ghost_facts.voter_count, 0,
        "a join must not self-found: the ghost zone has NO voters (R9)"
    );
    assert_eq!(
        ghost_facts.commit_index, 0,
        "nothing was committed — no founder bootstrap happened (R9)"
    );
    assert_eq!(ghost_facts.leader_id, 0, "no leader was ever elected");
}
