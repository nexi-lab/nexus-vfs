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

mod common;

use std::time::Duration;

use common::{free_port, Daemon, ZoneRuntime, LOG_FILTER};
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
    let first = rt
        .zone_create(ZONE, &[], OP, "")
        .await
        .expect("first create");
    assert_eq!(first.outcome, "CREATED");
    assert!(!first.replayed);

    let retry = rt
        .zone_create(ZONE, &[], OP, "")
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

    // Still exactly one zone — presence answers RESIDENT (not two stores,
    // not a different-membership error).
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
        .zone_create("other-zone", &[], OP, "")
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
}
