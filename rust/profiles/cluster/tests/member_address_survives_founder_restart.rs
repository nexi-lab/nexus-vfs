//! Daemon-level regression for member addresses (`docs/member-address.md`):
//! a founder whose log has compacted past its learner's `AddLearnerNode`
//! entry restarts with no peers configured, and the learner still receives
//! the founder's next write. The founder reaches the learner through the
//! zone's replicated member-address record — a learner never sends first,
//! so nothing else could teach a restarted founder where it lives.

mod common;

use std::time::Duration;

use common::{await_replicated, cli, free_port, Daemon, Vfs, ZoneRuntime, LOG_FILTER};
use nexus_raft::transport::{ClientConfig, RaftApiClient};

const ZONE: &str = "sharedzone";
const MOUNT: &str = "/agents";
const BUDGET: Duration = Duration::from_secs(90);
/// The daemons' compaction trigger: a few dozen writes compact past the
/// membership entries.
const SNAPSHOT_THRESHOLD: &str = "16";
const WRITES: usize = 40;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_founder_without_peers_still_replicates_to_its_learner() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = |name: &str| tmp.path().join(name).to_string_lossy().into_owned();
    let (fdata, fid, ldata, lid) = (path("f-data"), path("f-id"), path("l-data"), path("l-id"));
    let (fport, lport) = (free_port(), free_port());
    let faddr = format!("127.0.0.1:{fport}");
    let laddr = format!("127.0.0.1:{lport}");
    let mounts = format!("{MOUNT}={ZONE}");
    let founder_env = [
        ("NEXUS_DATA_DIR", fdata.as_str()),
        ("NEXUS_IDENTITY_DIR", fid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", faddr.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_CLUSTER_INIT", ZONE),
        ("NEXUS_CLUSTER_INIT_MOUNTS", mounts.as_str()),
        ("NEXUS_SC_SNAPSHOT_THRESHOLD", SNAPSHOT_THRESHOLD),
        ("RUST_LOG", LOG_FILTER),
    ];
    // The learner learns its seed from the join below (persisted into its
    // identity), exactly as an operator's `join` does; its daemon then
    // mounts the founder's published `/agents` like every federated node.
    let learner_env = [
        ("NEXUS_DATA_DIR", ldata.as_str()),
        ("NEXUS_IDENTITY_DIR", lid.as_str()),
        ("NEXUS_ADVERTISE_ADDR", laddr.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("NEXUS_SC_SNAPSHOT_THRESHOLD", SNAPSHOT_THRESHOLD),
        ("RUST_LOG", LOG_FILTER),
    ];

    let mut founder = Daemon::spawn(&["--bind-addr", &faddr], &founder_env);
    founder
        .wait_for_log("Static topology applied", BUDGET)
        .await
        .expect("founder forms sharedzone and its mount");
    let (ok, _, err) = cli(
        &learner_env,
        &["join", &faddr, ZONE, "/shared", "--as", "learner"],
    );
    assert!(ok, "learner join: {err}");
    let mut learner = Daemon::spawn(&["--bind-addr", &laddr], &learner_env);
    learner
        .wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("learner serves");

    let mut fc = Vfs::dial_ready(fport, BUDGET).await;
    let mut lc = Vfs::dial_ready(lport, BUDGET).await;
    let first = format!("{MOUNT}/before-0.txt");
    fc.write_file(&first, b"before", "").await.expect("write");
    await_replicated(&mut lc, &first, "", BUDGET).await;
    let membership_commit = ZoneRuntime::dial_ready(fport, BUDGET)
        .await
        .zone_status(ZONE, "")
        .await
        .expect("founder zone status")
        .cluster
        .expect("resident facts")
        .commit_index;
    for i in 1..WRITES {
        fc.write_file(&format!("{MOUNT}/before-{i}.txt"), b"before", "")
            .await
            .expect("write");
    }
    await_replicated(
        &mut lc,
        &format!("{MOUNT}/before-{}.txt", WRITES - 1),
        "",
        BUDGET,
    )
    .await;

    drop(fc);
    drop(founder);
    let retained =
        nexus_raft::raft::RaftStorage::open(tmp.path().join("f-data").join(ZONE).join("raft"))
            .expect("stopped founder's raft storage")
            .first_index_impl()
            .expect("first index");
    assert!(
        retained > membership_commit,
        "the founder's log must be compacted past the learner's membership entry \
         (first retained {retained}, membership committed by {membership_commit})"
    );

    // Same id, data dir and bind; still no peers.
    let founder = Daemon::spawn(&["--bind-addr", &faddr], &founder_env);
    let mut fc = Vfs::dial_ready(fport, BUDGET).await;
    let after = format!("{MOUNT}/after-restart.txt");
    let deadline = std::time::Instant::now() + BUDGET;
    while let Err(error) = fc.write_file(&after, b"after", "").await {
        assert!(
            std::time::Instant::now() < deadline,
            "restarted founder never accepted a write: {error}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    await_replicated(&mut lc, &after, "", BUDGET).await;
    assert_eq!(lc.read_file(&after, "").await.expect("read"), b"after");

    let info = RaftApiClient::connect(&format!("http://{faddr}"), ClientConfig::default())
        .await
        .expect("raft api")
        .with_zone_id(ZONE.into())
        .get_cluster_info()
        .await
        .expect("GetClusterInfo");
    let learners: Vec<String> = info
        .config
        .expect("cluster config")
        .learners
        .into_iter()
        .map(|node| node.address)
        .collect();
    assert_eq!(learners, vec![format!("http://{laddr}")]);
    let facts = ZoneRuntime::dial_ready(lport, BUDGET)
        .await
        .zone_status(ZONE, "")
        .await
        .expect("learner zone status")
        .cluster
        .expect("resident facts");
    assert!(
        facts.leader_contact_age_ms.is_some_and(|age| age < 10_000),
        "the learner hears from its restarted leader: {:?}",
        facts.leader_contact_age_ms
    );
    drop(founder);
    drop(learner);
}
