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
//!   4. JOIN on a second node: `outcome=JOINED` (never CREATED — R9) only
//!      once the leader committed the membership — the founder's
//!      GetClusterInfo lists the joiner as a voter at its address — and the
//!      joiner's status answers RESIDENT with live cluster facts.
//!   5. JOIN of a zone no leader serves: refused UNAVAILABLE, never JOINED;
//!      the joiner must NOT bootstrap it into existence (no founder fallback
//!      on the typed path) and keeps no replica of it.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;
use nexus_raft::transport::{ClientConfig, RaftApiClient};

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
        .zone_create(ZONE, "op-create-tenant-a-0001", "")
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
        .zone_join(ZONE, false, "op-join-tenant-a-0003", "")
        .await
        .expect("typed ZoneJoin must reach the founder");
    assert_eq!(
        joined.outcome, "JOINED",
        "the receipt must say JOINED — a join may never masquerade as a create"
    );
    assert!(
        joined
            .evidence
            .iter()
            .any(|line| line.contains("as a voter")),
        "the receipt names the committed role: {:?}",
        joined.evidence
    );
    // The leader committed it: its ConfState lists the joiner as a voter,
    // at the address the joiner advertises.
    let info = RaftApiClient::connect(&format!("http://{fadv}"), ClientConfig::default())
        .await
        .expect("raft api on the founder")
        .with_zone_id(ZONE.into())
        .get_cluster_info()
        .await
        .expect("GetClusterInfo on the founder");
    assert!(info.is_leader, "the founder leads {ZONE}");
    let voters: Vec<String> = info
        .config
        .expect("cluster config")
        .voters
        .into_iter()
        .map(|node| node.address)
        .collect();
    assert_eq!(voters.len(), 2, "founder and joiner vote: {voters:?}");
    assert!(
        voters.contains(&format!("http://{jadv}")),
        "the leader lists the joiner: {voters:?}"
    );
    // The joiner now sees the zone as RESIDENT with live facts.
    let j_status = j_rt.zone_status(ZONE, "").await.expect("joiner status");
    assert_eq!(j_status.presence, i32::from(Presence::Resident));

    // ── 5. JOIN of a zone no leader serves: UNAVAILABLE, never JOINED (R9) ──
    // The typed path has no founder fallback, and an unadmitted join keeps
    // nothing: the joiner neither SELF-FOUNDS the zone nor holds a replica of
    // it afterwards.
    let refused = j_rt
        .zone_join(GHOST, true, "op-join-ghost-0004", "")
        .await
        .expect_err("no leader admits a join of a zone nobody serves");
    assert_eq!(
        refused.code(),
        tonic::Code::Unavailable,
        "a join no leader admitted is UNAVAILABLE: {}",
        refused.message()
    );
    let ghost_status = j_rt
        .zone_status(GHOST, "")
        .await
        .expect("status of the never-created zone");
    assert_eq!(
        ghost_status.presence,
        i32::from(Presence::LocalNotFound),
        "no replica and no self-founded zone remain (R9)"
    );
    assert!(ghost_status.cluster.is_none(), "no raft group runs for it");
    assert!(
        !std::path::Path::new(&jdata).join(GHOST).exists(),
        "no zone directory remains"
    );
}
