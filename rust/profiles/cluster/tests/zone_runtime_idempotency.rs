//! Black-box E2E (acceptance 3, R8): a lost response never creates a second
//! zone. The operation journal makes every mutation idempotent per
//! `operation_id`:
//!
//!   1. Same operation_id + same request retried → `replayed=true`, the
//!      ORIGINAL receipt, and still exactly one zone.
//!   2. `GetZoneOperation` answers with the durable COMPLETED record.
//!   3. Same operation_id + a DIFFERENT request → refused
//!      (`FailedPrecondition`): a reused id must not silently merge a new
//!      request.
//!   4. A join no leader admits is UNAVAILABLE and leaves no replica; the
//!      same operation_id, retried once the leader is reachable, joins —
//!      exactly once.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};
use kernel::kernel::vfs_proto::zone_status_response::Presence;
use nexus_raft::transport::{ClientConfig, RaftApiClient};
use tonic::Code;

const ZONE: &str = "idem-zone";
const BUDGET: Duration = Duration::from_secs(120);
const OP: &str = "op-idem-0001";

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
async fn a_lost_response_never_creates_a_second_zone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("id").to_string_lossy().into_owned();

    let port = free_port();
    let adv = format!("127.0.0.1:{port}");
    let e = env(&data, &id, &adv);
    let _d = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &e);
    let mut rt = ZoneRuntime::dial_ready(port, BUDGET).await;

    // ── 1. Execute, then "lose the response" and retry the SAME request ──
    let first = rt.zone_create(ZONE, OP, "").await.expect("first create");
    assert_eq!(first.outcome, "CREATED");
    assert!(!first.replayed);

    let retry = rt
        .zone_create(ZONE, OP, "")
        .await
        .expect("the retry must be answered (replay), not hung");
    assert!(
        retry.replayed,
        "a retried operation_id must answer replayed=true: {retry:?}"
    );
    assert_eq!(retry.outcome, first.outcome);
    assert_eq!(retry.operation_id, OP);
    // The replay is the ORIGINAL receipt: same zone, and it is NOT an
    // ALREADY_PRESENT fresh execution (which would mean the journal missed).
    assert_eq!(retry.zone_id, ZONE);

    // Still exactly one zone — presence answers RESIDENT (not two stores).
    let status = rt.zone_status(ZONE, "").await.expect("status");
    assert_eq!(
        status.presence,
        i32::from(kernel::kernel::vfs_proto::zone_status_response::Presence::Resident),
        "the retried create must not have produced a second/conflicting zone"
    );

    // ── 2. GetZoneOperation returns the durable record + original receipt ──
    let record = rt
        .get_zone_operation(OP, "")
        .await
        .expect("journal lookup for the executed operation");
    assert_eq!(record.operation_id, OP);
    assert_eq!(record.status, "COMPLETED");
    assert_eq!(
        record
            .receipt
            .as_ref()
            .expect("COMPLETED carries the receipt")
            .outcome,
        "CREATED"
    );

    // A journal miss answers NotFound (not an empty phantom record).
    let err = rt
        .get_zone_operation("op-never-issued", "")
        .await
        .expect_err("unknown operation_id");
    assert_eq!(err.code(), Code::NotFound);

    // ── 3. Same operation_id, DIFFERENT request → refused ──
    let err = rt
        .zone_create("other-zone", OP, "")
        .await
        .expect_err("a reused operation_id with a different request must be refused");
    assert_eq!(
        err.code(),
        Code::FailedPrecondition,
        "hash mismatch refusal: {}",
        err.message()
    );

    // And the refused reuse did not corrupt the original record.
    let record2 = rt
        .get_zone_operation(OP, "")
        .await
        .expect("re-read journal");
    assert_eq!(record2.status, "COMPLETED");
    assert_eq!(record2.zone_id, ZONE);

    // ── 4. The journal is DURABLE: the same retry after a full daemon
    // restart (data directory preserved) still replays the ORIGINAL
    // receipt — the record rides the control zone's replicated store, not
    // process memory. A restarted retry that re-EXECUTED the create would
    // answer ALREADY_PRESENT with replayed=false instead.
    drop(rt);
    drop(_d);
    let _d2 = Daemon::spawn(&["--bind-addr", &adv, "--no-tls"], &e);
    let mut rt2 = ZoneRuntime::dial_ready(port, BUDGET).await;
    let restart_retry = rt2
        .zone_create(ZONE, OP, "")
        .await
        .expect("the post-restart retry must be answered (replay), not hung");
    assert!(
        restart_retry.replayed,
        "a retried operation_id after a daemon restart must answer replayed=true: \
         {restart_retry:?}"
    );
    assert_eq!(
        restart_retry.outcome, "CREATED",
        "the replay is the original receipt, not a fresh ALREADY_PRESENT execution"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_retried_after_its_leader_appears_joins_exactly_once() {
    const JOIN_OP: &str = "op-idem-join-0001";
    let tmp = tempfile::tempdir().expect("tempdir");
    let fdata = tmp.path().join("f-data").to_string_lossy().into_owned();
    let fid = tmp.path().join("f-id").to_string_lossy().into_owned();
    let jdata = tmp.path().join("j-data").to_string_lossy().into_owned();
    let jid = tmp.path().join("j-id").to_string_lossy().into_owned();
    let fport = free_port();
    let jport = free_port();
    let fadv = format!("127.0.0.1:{fport}");
    let jadv = format!("127.0.0.1:{jport}");

    // The joiner's seed is the founder, which is not running yet.
    let jenv = {
        let mut e = env(&jdata, &jid, &jadv);
        e.push(("NEXUS_PEERS", fadv.as_str()));
        e
    };
    let mut joiner = Daemon::spawn(&["--bind-addr", &jadv, "--no-tls"], &jenv);
    joiner
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("the joiner serves its typed surface without its seed");
    let mut j_rt = ZoneRuntime::dial_ready(jport, BUDGET).await;

    let refused = j_rt
        .zone_join(ZONE, false, JOIN_OP, "")
        .await
        .expect_err("no leader is reachable");
    assert_eq!(refused.code(), Code::Unavailable, "{}", refused.message());
    let status = j_rt.zone_status(ZONE, "").await.expect("joiner status");
    assert_eq!(
        status.presence,
        i32::from(Presence::LocalNotFound),
        "an unadmitted join leaves no replica behind"
    );
    assert!(
        !std::path::Path::new(&jdata).join(ZONE).exists(),
        "no zone directory remains"
    );

    // The leader appears.
    let fenv = env(&fdata, &fid, &fadv);
    let mut founder = Daemon::spawn(&["--bind-addr", &fadv, "--no-tls"], &fenv);
    founder
        .wait_for_log("ZoneRuntimeService live", BUDGET)
        .await
        .expect("founder up");
    let mut f_rt = ZoneRuntime::dial_ready(fport, BUDGET).await;
    f_rt.zone_create(ZONE, "op-idem-join-create-0002", "")
        .await
        .expect("the founder creates the zone");

    let joined = j_rt
        .zone_join(ZONE, false, JOIN_OP, "")
        .await
        .expect("the same operation id joins once its leader is reachable");
    assert_eq!(joined.outcome, "JOINED");
    assert!(!joined.replayed, "the retry drove the join: {joined:?}");
    let again = j_rt
        .zone_join(ZONE, false, JOIN_OP, "")
        .await
        .expect("a further retry replays");
    assert!(again.replayed, "the join ran once: {again:?}");
    assert_eq!(again.outcome, "JOINED");
    let record = j_rt
        .get_zone_operation(JOIN_OP, "")
        .await
        .expect("journal record");
    assert_eq!(record.status, "COMPLETED");

    let info = RaftApiClient::connect(&format!("http://{fadv}"), ClientConfig::default())
        .await
        .expect("raft api on the founder")
        .with_zone_id(ZONE.into())
        .get_cluster_info()
        .await
        .expect("GetClusterInfo on the founder");
    let voters: Vec<String> = info
        .config
        .expect("cluster config")
        .voters
        .into_iter()
        .map(|node| node.address)
        .collect();
    assert_eq!(voters.len(), 2, "founder and joiner, once each: {voters:?}");
    assert!(voters.contains(&format!("http://{jadv}")), "{voters:?}");
}
