use super::*;
use crate::transport::{
    add_revoked_serial, add_revoked_serial_with_expiry, generate_zone_ca, prune_expired_serials,
};
use redb::ReadableDatabase;
use std::sync::{Arc, Barrier};

fn number(bytes: &[u8], ca: &[u8]) -> Vec<u8> {
    verify_signed_crl(bytes, ca).unwrap().number().to_vec()
}

fn stored(issuer: &CrlIssuer) -> Vec<u8> {
    issuer
        .database
        .begin_read()
        .unwrap()
        .open_table(ISSUED)
        .unwrap()
        .get(issuer.authority.as_slice())
        .unwrap()
        .unwrap()
        .value()
        .to_vec()
}

fn replace_receipt(issuer: &CrlIssuer, bytes: &[u8]) {
    let txn = issuer.database.begin_write().unwrap();
    txn.open_table(ISSUED)
        .unwrap()
        .insert(issuer.authority.as_slice(), bytes)
        .unwrap();
    txn.commit().unwrap();
}

#[test]
fn pruning_equal_counts_and_restart_preserve_the_issued_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    let now = time::OffsetDateTime::now_utc();
    add_revoked_serial_with_expiry(&path, b"expired", Some(now.unix_timestamp() - 100)).unwrap();
    add_revoked_serial(&path, b"retained").unwrap();
    let issuer = CrlIssuer::open(&path, &ca, &key).unwrap();
    let first = issuer.issue_at(now).unwrap();
    assert_eq!(number(&first, &ca), FIRST_NUMBER);
    assert_eq!(
        stored(&issuer),
        first,
        "a response has a committed issuance receipt"
    );
    assert_eq!(
        issuer.issue_at(now).unwrap(),
        first,
        "unchanged fresh snapshot reuses exact bytes"
    );
    assert_eq!(
        prune_expired_serials(&path, now.unix_timestamp(), 0).unwrap(),
        1
    );
    let pruned = issuer.issue_at(now).unwrap();
    assert!(
        number(&pruned, &ca) > number(&first, &ca),
        "pruning must advance issuance"
    );
    assert_eq!(
        verify_signed_crl(&pruned, &ca).unwrap().revoked_serials(),
        &[b"retained".to_vec()]
    );
    add_revoked_serial(&path, b"replacement").unwrap();
    let replaced = issuer.issue_at(now).unwrap();
    assert!(
        number(&replaced, &ca) > number(&pruned, &ca),
        "equal historical entry counts cannot reuse a number"
    );
    drop(issuer);
    let reopened = CrlIssuer::open(&path, &ca, &key).unwrap();
    assert_eq!(reopened.issue_at(now).unwrap(), replaced);
    let refreshed = reopened
        .issue_at(now + time::Duration::seconds(REUSE_SECONDS))
        .unwrap();
    assert!(number(&refreshed, &ca) > number(&replaced, &ca));
    assert_eq!(stored(&reopened), refreshed);
}

#[test]
fn concurrent_refreshes_return_one_committed_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    let issuer = Arc::new(CrlIssuer::open(&path, &ca, &key).unwrap());
    let now = time::OffsetDateTime::now_utc();
    let first = issuer.issue_at(now).unwrap();
    add_revoked_serial(&path, b"new").unwrap();
    let ready = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let issuer = Arc::clone(&issuer);
            let ready = Arc::clone(&ready);
            std::thread::spawn(move || {
                ready.wait();
                issuer.issue_at(now).unwrap()
            })
        })
        .collect();
    let snapshots: Vec<_> = handles
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(snapshots.iter().all(|bytes| bytes == &snapshots[0]));
    assert_eq!(
        number(&snapshots[0], &ca),
        next_number(&number(&first, &ca)).unwrap()
    );
    assert_eq!(stored(&issuer), snapshots[0]);
}

#[test]
fn corrupt_authority_and_revocation_state_refuse_without_replacing_the_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    let issuer = CrlIssuer::open(&path, &ca, &key).unwrap();
    let original = issuer.issue().unwrap();
    std::fs::write(&path, "!!!malformed!!!\n").unwrap();
    assert!(issuer
        .issue()
        .unwrap_err()
        .contains("read current revocations"));
    assert_eq!(stored(&issuer), original);
    std::fs::write(&path, "").unwrap();
    replace_receipt(&issuer, b"malformed receipt");
    assert!(issuer.issue().unwrap_err().contains("stored CRL receipt"));
    assert_eq!(stored(&issuer), b"malformed receipt");
    let (other_ca, other_key) = generate_zone_ca("other").unwrap();
    let other = generate_crl_at(
        &[],
        &FIRST_NUMBER,
        &other_ca,
        &other_key,
        time::OffsetDateTime::now_utc(),
    )
    .unwrap();
    replace_receipt(&issuer, &other);
    assert!(issuer.issue().unwrap_err().contains("stored CRL receipt"));
    assert_eq!(stored(&issuer), other);
    replace_receipt(&issuer, &original);
    assert_eq!(issuer.issue().unwrap(), original);
}

#[test]
fn clock_rollback_exhaustion_and_old_count_refuse_without_resigning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    let issuer = CrlIssuer::open(&path, &ca, &key).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let original = issuer.issue_at(now).unwrap();
    assert!(issuer
        .issue_at(now - time::Duration::seconds(2))
        .unwrap_err()
        .contains("clock precedes"));
    assert_eq!(stored(&issuer), original);
    let exhausted = generate_crl_at(&[], &[255; 20], &ca, &key, now).unwrap();
    replace_receipt(&issuer, &exhausted);
    assert!(issuer
        .issue_at(now + time::Duration::seconds(REUSE_SECONDS))
        .unwrap_err()
        .contains("exhausted"));
    assert_eq!(stored(&issuer), exhausted);
    let old = super::super::generate_crl(&[], u64::MAX, &ca, &key).unwrap();
    replace_receipt(&issuer, &old);
    assert!(issuer
        .issue_at(now)
        .unwrap_err()
        .contains("predates durable sequencing"));
    assert_eq!(stored(&issuer), old);
}

#[test]
fn issuer_keys_have_independent_durable_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    let now = time::OffsetDateTime::now_utc();
    let original = {
        let issuer = CrlIssuer::open(&path, &ca, &key).unwrap();
        issuer.issue_at(now).unwrap()
    };
    let (next_ca, next_key) = generate_zone_ca("root").unwrap();
    {
        let next = CrlIssuer::open(&path, &next_ca, &next_key).unwrap();
        assert_eq!(number(&next.issue_at(now).unwrap(), &next_ca), FIRST_NUMBER);
    }
    let original_issuer = CrlIssuer::open(&path, &ca, &key).unwrap();
    assert_eq!(stored(&original_issuer), original);
    assert_eq!(original_issuer.issue_at(now).unwrap(), original);
}

#[test]
fn an_existing_truncated_journal_is_not_initialized_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    std::fs::write(path.with_extension("crl.redb"), []).unwrap();
    assert!(CrlIssuer::open(&path, &ca, &key).is_err());
    assert_eq!(
        std::fs::metadata(path.with_extension("crl.redb"))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn failed_revocation_staging_preserves_the_original_source_and_signed_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let (ca, key) = generate_zone_ca("root").unwrap();
    add_revoked_serial(&path, b"original").unwrap();
    let source = std::fs::read(&path).unwrap();
    let issuer = CrlIssuer::open(&path, &ca, &key).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let receipt = issuer.issue_at(now).unwrap();
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    assert!(add_revoked_serial(&path, b"later").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), source);
    assert_eq!(issuer.issue_at(now).unwrap(), receipt);
}
