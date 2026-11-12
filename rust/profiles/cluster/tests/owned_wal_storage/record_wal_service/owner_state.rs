//! Restart readback uses the original storage decision without reopening I/O.

use super::{service, Fixture, HISTORY, OWNER};
use kernel::kernel::conditional_content::ConditionalContentResult;
use kernel::kernel::OperationContext;

#[test]
fn kernel_owned_wal_owner_state_keeps_terminal_decision_separate_from_io_drain() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    let first = fixture
        .kernel
        .record_content_owner_state(OWNER, &service())
        .unwrap();
    assert_eq!(first.version, owner);
    assert!(!first.is_retired);
    assert_eq!(
        fixture
            .kernel
            .record_content_owner_state(OWNER, &service())
            .unwrap(),
        first
    );
    let handle = fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .unwrap();
    assert!(fixture
        .kernel
        .record_content_owner_state(HISTORY, &service())
        .is_err());
    let untrusted = OperationContext::new("agent-a", "root", false, None, false);
    assert!(fixture
        .kernel
        .record_content_owner_state(OWNER, &untrusted)
        .is_err());
    let io = fixture.store.begin_record_io(OWNER, &owner).unwrap();
    let terminal = match fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner)
        .unwrap()
    {
        ConditionalContentResult::Committed { version } => version,
        other => panic!("expected terminal revision: {other:?}"),
    };
    let retired = fixture
        .kernel
        .record_content_owner_state(OWNER, &service())
        .unwrap();
    assert!(retired.is_retired);
    assert_eq!(retired.version, terminal);
    assert!(fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap()
        .is_none());
    assert!(handle.read_at(0).is_err());
    drop(io);
    assert!(fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap()
        .is_some());
    drop((handle, fixture));

    let reopened = Fixture::open(directory.path(), true);
    assert_eq!(
        reopened
            .kernel
            .record_content_owner_state(OWNER, &service())
            .unwrap(),
        retired
    );
    for revision in [&owner, &terminal] {
        assert!(reopened
            .kernel
            .open_record_wal(HISTORY, &service(), revision)
            .is_err());
    }
    assert!(reopened
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap()
        .is_some());
}
