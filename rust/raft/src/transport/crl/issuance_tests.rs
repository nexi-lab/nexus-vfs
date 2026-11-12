use super::*;
use std::cell::Cell;

#[test]
fn every_issuance_principal_must_remain_unrevoked() {
    for revoked in [b"controller".as_slice(), b"predecessor".as_slice()] {
        let dir = tempfile::tempdir().unwrap();
        let path = revoked_serials_path(dir.path());
        let principals = [b"controller".as_slice(), b"predecessor".as_slice()];
        let called = Cell::new(0);
        let issue = || {
            called.set(called.get() + 1);
            Ok(73)
        };
        assert_eq!(with_unrevoked_serials(&path, &principals, issue), Ok(73));
        add_revoked_serial(&path, revoked).unwrap();
        assert!(with_unrevoked_serials(&path, &principals, issue)
            .unwrap_err()
            .contains("revoked certificate"));
        assert_eq!(
            called.get(),
            1,
            "no signer executes after either revocation"
        );
        assert!(with_unrevoked_serial(&path, revoked, issue).is_err());
        assert_eq!(called.get(), 1);
    }
}

#[test]
fn issuance_holds_the_existing_revocation_lock_through_the_callback() {
    let dir = tempfile::tempdir().unwrap();
    let path = revoked_serials_path(dir.path());
    let principals = [b"caller".as_slice(), b"holder".as_slice()];
    let result: Result<(), String> = with_unrevoked_serials(&path, &principals, || {
        assert!(matches!(
            SERIALS_WRITE_LOCK.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        Err("original signing failure".into())
    });
    assert_eq!(result.unwrap_err(), "original signing failure");
    add_revoked_serial(&path, b"holder").unwrap();
    assert!(with_unrevoked_serials(&path, &principals, || Ok(())).is_err());
}

#[test]
fn empty_or_unreadable_revocation_inputs_never_invoke_the_signer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let called = Cell::new(false);
    let issue = || {
        called.set(true);
        Ok(())
    };
    assert!(with_unrevoked_serials(&path, &[], issue).is_err());
    assert!(with_unrevoked_serials(&path, &[b""], issue).is_err());
    std::fs::create_dir(&path).unwrap();
    assert!(with_unrevoked_serials(&path, &[b"caller"], issue).is_err());
    assert!(!called.get());
    assert!(path.is_dir());
}

#[test]
fn malformed_revocations_preserve_original_bytes_across_all_mutations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked-serials");
    let original = b"b2xk 1\n!!!malformed!!!\n";
    std::fs::write(&path, original).unwrap();
    assert!(add_revoked_serial(&path, b"new").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(prune_expired_serials(&path, 100_000, 0).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(read_revoked_serials_checked(&path).is_err());
    let called = Cell::new(false);
    assert!(with_unrevoked_serials(&path, &[b"caller", b"holder"], || {
        called.set(true);
        Ok(())
    })
    .is_err());
    assert!(!called.get());
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
