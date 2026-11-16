//! Generic paths cannot bypass the enrolled owner's actual I/O lifetime.

use super::{service, Fixture, HISTORY, OWNER};
use backends::storage::cas_local::CasLocalBackend;
use kernel::core::stream::wal::WalStreamCore;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, ReadRequest};
use kernel::stream::StreamBackend;
use std::fmt::Debug;
use std::sync::Arc;

pub(super) fn scoped_refusal<T, E: Debug>(result: Result<T, E>) {
    match result {
        Err(error) => assert!(
            format!("{error:?}").contains("requires the scoped owner handle"),
            "expected the enrolled-owner refusal, received {error:?}"
        ),
        Ok(_) => panic!("generic I/O must not bypass the enrolled owner"),
    }
}

fn request(path: &str, len: Option<u64>) -> ReadRequest {
    ReadRequest {
        path: path.into(),
        offset: 0,
        len,
        timeout_ms: 0,
    }
}

#[test]
fn kernel_owned_wal_excludes_generic_regular_reads_and_keeps_independent_content() {
    const CONTENT: &str = "/sessions/service-session/completion";
    const INDEPENDENT: &str = "/agents/agent-a/independent";
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    let data = b"same immutable bytes with two independent references";
    for path in [CONTENT, INDEPENDENT] {
        KernelSyscall::sys_write(fixture.kernel.as_ref(), path, &service(), data, 0).unwrap();
        assert_eq!(
            KernelSyscall::sys_read(fixture.kernel.as_ref(), path, &service(), 0, 0)
                .unwrap()
                .data,
            Some(data.to_vec())
        );
    }
    fixture
        .kernel
        .protect_record_content(CONTENT, &service())
        .unwrap();
    assert_eq!(
        fixture
            .kernel
            .read_versioned_content(CONTENT, &service())
            .unwrap()
            .unwrap()
            .content,
        data
    );
    fixture
        .kernel
        .bind_record_content_owner(CONTENT, OWNER, &service(), &owner)
        .unwrap();
    fixture
        .kernel
        .mount(
            "/session-view",
            MountOptions::new(&service(), "local")
                .with_backend(Arc::new(
                    CasLocalBackend::new_durable(&directory.path().join("cas")).unwrap(),
                ))
                .with_metastore(Arc::new(
                    fixture
                        ._runtime
                        .store("/session-view", "/sessions/service-session"),
                )),
        )
        .unwrap();
    for path in [CONTENT, "/session-view/completion"] {
        assert_eq!(
            fixture
                .kernel
                .read_guarded_content(path, &service(), &owner)
                .unwrap()
                .unwrap()
                .content,
            data
        );
        scoped_refusal(KernelSyscall::sys_read(
            fixture.kernel.as_ref(),
            path,
            &service(),
            0,
            0,
        ));
        scoped_refusal(fixture.kernel.read_versioned_content(path, &service()));
        let results = Kernel::sys_read(
            fixture.kernel.as_ref(),
            &[
                request(path, None),
                request(path, Some(0)),
                request(INDEPENDENT, None),
            ],
            &service(),
        );
        let mut results = results.into_iter();
        scoped_refusal(results.next().unwrap());
        scoped_refusal(results.next().unwrap());
        assert_eq!(results.next().unwrap().unwrap().data, Some(data.to_vec()));
        let mut results = Kernel::sys_read(
            fixture.kernel.as_ref(),
            &[request(INDEPENDENT, None), request(path, None)],
            &service(),
        )
        .into_iter();
        assert_eq!(results.next().unwrap().unwrap().data, Some(data.to_vec()));
        scoped_refusal(results.next().unwrap());
    }
    scoped_refusal(KernelSyscall::sys_read(
        fixture.kernel.as_ref(),
        OWNER,
        &service(),
        0,
        0,
    ));
    assert_eq!(
        fixture
            .kernel
            .read_guarded_content(OWNER, &service(), &owner)
            .unwrap()
            .unwrap()
            .content,
        b"original lifetime image"
    );
    fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner)
        .unwrap();
    assert!(fixture
        .kernel
        .read_guarded_content(CONTENT, &service(), &owner)
        .is_err());
    scoped_refusal(KernelSyscall::sys_read(
        fixture.kernel.as_ref(),
        CONTENT,
        &service(),
        0,
        0,
    ));
    assert_eq!(
        KernelSyscall::sys_read(fixture.kernel.as_ref(), INDEPENDENT, &service(), 0, 0)
            .unwrap()
            .data,
        Some(data.to_vec())
    );
    drop(fixture);

    let reopened = Fixture::open(directory.path(), true);
    scoped_refusal(KernelSyscall::sys_read(
        reopened.kernel.as_ref(),
        CONTENT,
        &service(),
        0,
        0,
    ));
    scoped_refusal(reopened.kernel.read_versioned_content(CONTENT, &service()));
    assert_eq!(
        KernelSyscall::sys_read(reopened.kernel.as_ref(), INDEPENDENT, &service(), 0, 0)
            .unwrap()
            .data,
        Some(data.to_vec())
    );
}

#[test]
fn kernel_owned_content_refuses_scoped_peer_reads_and_keeps_independent_content() {
    const CONTENT: &str = "/sessions/service-session/completion";
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    for path in [CONTENT, "/ordinary"] {
        KernelSyscall::sys_write(fixture.kernel.as_ref(), path, &service(), b"same bytes", 0)
            .unwrap();
        assert_eq!(
            fixture
                .kernel
                .read_local_zone_content("root", path)
                .unwrap(),
            b"same bytes"
        );
    }
    fixture
        .kernel
        .protect_record_content(CONTENT, &service())
        .unwrap();
    fixture
        .kernel
        .bind_record_content_owner(CONTENT, OWNER, &service(), &owner)
        .unwrap();
    scoped_refusal(fixture.kernel.read_local_zone_content("root", CONTENT));
    assert_eq!(
        fixture
            .kernel
            .read_local_zone_content("root", "/ordinary")
            .unwrap(),
        b"same bytes"
    );
    assert_eq!(
        fixture
            .kernel
            .read_guarded_content(CONTENT, &service(), &owner)
            .unwrap()
            .unwrap()
            .content,
        b"same bytes"
    );
    fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner)
        .unwrap();
    scoped_refusal(fixture.kernel.read_local_zone_content("root", CONTENT));
    assert_eq!(
        fixture
            .kernel
            .read_local_zone_content("root", "/ordinary")
            .unwrap(),
        b"same bytes"
    );
}

#[test]
fn kernel_owned_wal_excludes_retained_unowned_handles_after_binding_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let cached = WalStreamCore::new(fixture.store.clone(), HISTORY.into());
    assert_eq!(cached.read_at(0).unwrap(), None);
    let ordinary = WalStreamCore::new(fixture.store.clone(), "/ordinary-wal".into());
    assert_eq!(ordinary.write_sync(b"ordinary record").unwrap(), 0);
    assert_eq!(
        ordinary.read_at(0).unwrap(),
        Some(b"ordinary record".to_vec())
    );

    let owner = fixture.enroll();
    let owned = fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .unwrap();
    assert_eq!(owned.write_sync(b"owned record").unwrap(), 0);
    assert_eq!(owned.read_at(0).unwrap(), Some(b"owned record".to_vec()));
    scoped_refusal(cached.read_at(0));
    scoped_refusal(cached.write_sync(b"unowned writer"));
    scoped_refusal(StreamBackend::push(&cached, b""));
    let fresh = WalStreamCore::new(fixture.store.clone(), HISTORY.into());
    scoped_refusal(fresh.read_at(0));
    assert_eq!(
        ordinary.read_at(0).unwrap(),
        Some(b"ordinary record".to_vec())
    );
    fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner)
        .unwrap();
    scoped_refusal(cached.read_at(0));
    assert!(owned.read_at(0).is_err());
    drop((owned, cached, fresh, ordinary, fixture));

    let reopened = Fixture::open(directory.path(), true);
    let unowned = WalStreamCore::new(reopened.store.clone(), HISTORY.into());
    scoped_refusal(unowned.read_at(0));
    let independent = WalStreamCore::new(reopened.store.clone(), "/ordinary-wal".into());
    assert_eq!(
        independent.read_at(0).unwrap(),
        Some(b"ordinary record".to_vec())
    );
}
