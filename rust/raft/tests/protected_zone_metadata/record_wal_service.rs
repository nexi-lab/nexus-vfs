//! Trusted Kernel admission over the actual native CAS and persistent Raft store.

use super::*;
use backends::storage::cas_local::CasLocalBackend;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::{Kernel, OperationContext};

#[path = "record_wal_service/global_fallback.rs"]
mod global_fallback;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/after_inode.rs"]
mod after_inode;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/cold_lifetime.rs"]
mod cold_lifetime;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/unscoped_reads.rs"]
mod unscoped_reads;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/owner_state.rs"]
mod owner_state;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/regular_reads.rs"]
mod regular_reads;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/unscoped_cold.rs"]
mod unscoped_cold;

#[cfg(target_os = "linux")]
#[path = "record_wal_service/batch_remount.rs"]
mod batch_remount;

const OWNER: &str = "/sessions/service-session/lifetime";
const HISTORY: &str = "/sessions/service-session/history";

fn service() -> OperationContext {
    OperationContext::new("session-service", "root", true, None, true)
}

struct Fixture {
    kernel: Arc<Kernel>,
    store: Arc<ZoneMetaStore>,
    _runtime: Runtime,
}

impl Fixture {
    fn open(directory: &std::path::Path, durable: bool) -> Self {
        Self::open_with_store(directory, durable, |store| store).0
    }

    fn open_with_store<S: MetaStore + 'static>(
        directory: &std::path::Path,
        durable: bool,
        wrap: impl FnOnce(Arc<ZoneMetaStore>) -> Arc<S>,
    ) -> (Self, Arc<S>) {
        let backend = if durable {
            CasLocalBackend::new_durable(&directory.join("cas")).unwrap()
        } else {
            CasLocalBackend::new(&directory.join("cas"), true).unwrap()
        };
        Self::open_with_components(directory, wrap, Arc::new(backend))
    }

    fn open_with_components<S: MetaStore + 'static>(
        directory: &std::path::Path,
        wrap: impl FnOnce(Arc<ZoneMetaStore>) -> Arc<S>,
        backend: Arc<dyn kernel::abc::object_store::ObjectStore>,
    ) -> (Self, Arc<S>) {
        let runtime = Runtime::open(&directory.join("state"));
        let store = Arc::new(runtime.store("/", "/"));
        let mounted = wrap(Arc::clone(&store));
        let kernel = Arc::new(Kernel::new());
        kernel
            .mount(
                "/",
                MountOptions::new(&service(), "local")
                    .with_backend(backend)
                    .with_metastore(mounted.clone()),
            )
            .unwrap();
        (
            Self {
                kernel,
                store,
                _runtime: runtime,
            },
            mounted,
        )
    }

    #[cfg(target_os = "linux")]
    fn enroll(&self) -> Vec<u8> {
        self.enroll_at(OWNER, self.store.as_ref())
    }

    #[cfg(target_os = "linux")]
    fn enroll_at(&self, path: &str, store: &ZoneMetaStore) -> Vec<u8> {
        KernelSyscall::sys_write(
            self.kernel.as_ref(),
            path,
            &service(),
            b"original lifetime image",
            0,
        )
        .unwrap();
        assert_eq!(
            self.kernel
                .protect_record_content(path, &service())
                .unwrap(),
            RecordProtectionResult::Protected
        );
        let owner = store
            .as_conditional_metadata()
            .unwrap()
            .read_versioned(path)
            .unwrap()
            .unwrap();
        self.kernel
            .admit_record_content_io(path, &service(), &owner.version)
            .unwrap();
        owner.version
    }
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_owned_wal_reopens_and_retires_without_process_exit() {
    use kernel::core::stream::wal::wal_stream_prefix;
    use kernel::kernel::conditional_content::ConditionalContentResult;
    use kernel::stream::StreamBackend;

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    KernelSyscall::sys_write(
        fixture.kernel.as_ref(),
        "/agents/agent-a/info",
        &service(),
        b"persistent agent",
        0,
    )
    .unwrap();
    let first = fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .unwrap();
    let second = fixture
        .kernel
        .open_record_wal(HISTORY, &service(), &owner)
        .unwrap();
    assert_eq!(first.stream_id(), HISTORY);
    assert_eq!(StreamBackend::push(&first, b"first").unwrap(), 0);
    assert_eq!(StreamBackend::push(&second, b"second").unwrap(), 1);
    assert_eq!(first.read_at(1).unwrap(), Some(b"second".to_vec()));
    assert_eq!(second.read_at(0).unwrap(), Some(b"first".to_vec()));
    assert!(fixture
        .store
        .append_stream_entry(&wal_stream_prefix(HISTORY), b"ordinary writer")
        .is_err());
    let terminal = match fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner)
        .unwrap()
    {
        ConditionalContentResult::Committed { version } => version,
        other => panic!("expected committed retirement: {other:?}"),
    };
    for handle in [&first, &second] {
        assert!(handle.write_sync(b"retired writer").is_err());
        assert!(handle.read_at(0).is_err());
    }
    assert!(fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap()
        .is_some());
    assert_eq!(
        KernelSyscall::sys_read(
            fixture.kernel.as_ref(),
            "/agents/agent-a/info",
            &service(),
            0,
            0
        )
        .unwrap()
        .data,
        Some(b"persistent agent".to_vec())
    );
    drop((first, second, fixture));

    let reopened = Fixture::open(directory.path(), true);
    for revision in [&owner, &terminal] {
        assert!(reopened
            .kernel
            .open_record_wal(HISTORY, &service(), revision)
            .is_err());
    }
    assert_eq!(
        reopened
            .store
            .stream_tail(&wal_stream_prefix(HISTORY))
            .unwrap(),
        2
    );
    assert_eq!(
        KernelSyscall::sys_read(
            reopened.kernel.as_ref(),
            "/agents/agent-a/info",
            &service(),
            0,
            0
        )
        .unwrap()
        .data,
        Some(b"persistent agent".to_vec())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_owned_wal_creation_preserves_occupied_and_retained_logs() {
    use kernel::core::stream::wal::wal_stream_prefix;

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    let regular = "/sessions/service-session/regular";
    KernelSyscall::sys_write(
        fixture.kernel.as_ref(),
        regular,
        &service(),
        b"independent content",
        0,
    )
    .unwrap();
    assert!(fixture
        .kernel
        .create_record_wal(regular, OWNER, &service(), &owner)
        .is_err());
    fixture
        .kernel
        .bind_record_content_owner(regular, OWNER, &service(), &owner)
        .unwrap();
    assert!(fixture
        .kernel
        .open_record_wal(regular, &service(), &owner)
        .is_err());

    // Reproduce a former inode's surviving WAL side table. Admission must not
    // treat its absent inode as an empty log or overwrite the retained data.
    let prefix = wal_stream_prefix(HISTORY);
    fixture
        .store
        .append_stream_entry(&prefix, b"prior lifetime")
        .unwrap();
    assert!(fixture.store.get(HISTORY).unwrap().is_none());
    assert!(fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), &owner)
        .is_err());
    assert!(fixture.store.get(HISTORY).unwrap().is_none());
    assert_eq!(fixture.store.stream_tail(&prefix).unwrap(), 1);
    assert!(fixture
        .store
        .append_stream_entry(&prefix, b"late ordinary write")
        .is_err());
    assert!(fixture
        .kernel
        .open_record_wal(HISTORY, &service(), &owner)
        .is_err());
    assert!(fixture
        .kernel
        .create_record_wal("/sessions/service-session/fresh", OWNER, &service(), &owner)
        .is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_owned_wal_uses_one_canonical_log_through_two_mounts() {
    use kernel::core::stream::wal::wal_stream_prefix;
    use kernel::stream::StreamBackend;

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    for alias in ["/view-a", "/view-b"] {
        fixture
            .kernel
            .mount(
                alias,
                MountOptions::new(&service(), "local")
                    .with_backend(Arc::new(
                        CasLocalBackend::new_durable(&directory.path().join("cas")).unwrap(),
                    ))
                    .with_metastore(Arc::new(
                        fixture._runtime.store(alias, "/sessions/service-session"),
                    )),
            )
            .unwrap();
    }
    let first = fixture
        .kernel
        .create_record_wal("/view-a/history", "/view-a/lifetime", &service(), &owner)
        .unwrap();
    let second = fixture
        .kernel
        .open_record_wal("/view-b/history", &service(), &owner)
        .unwrap();
    assert_eq!(first.stream_id(), HISTORY);
    assert_eq!(second.stream_id(), HISTORY);
    assert_eq!(StreamBackend::push(&first, b"from a").unwrap(), 0);
    assert_eq!(StreamBackend::push(&second, b"from b").unwrap(), 1);
    assert_eq!(second.read_at(0).unwrap(), Some(b"from a".to_vec()));
    assert_eq!(first.read_at(1).unwrap(), Some(b"from b".to_vec()));
    for alias in ["/view-a/history", "/view-b/history"] {
        assert_eq!(
            fixture
                .store
                .stream_tail(&wal_stream_prefix(alias))
                .unwrap(),
            0
        );
    }
    fixture
        .kernel
        .retire_record_content_owner("/view-b/lifetime", &service(), &owner)
        .unwrap();
    for handle in [&first, &second] {
        assert!(handle.read_at(0).is_err());
        assert!(handle.write_sync(b"retired mounted writer").is_err());
    }
    assert_eq!(
        fixture
            .store
            .stream_tail(&wal_stream_prefix(HISTORY))
            .unwrap(),
        2
    );
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_owned_wal_refuses_nonservice_wrong_revision_and_cross_mount_owner() {
    use kernel::core::stream::wal::wal_stream_prefix;
    use kernel::kernel::conditional_content::ConditionalContentError;
    use kernel::stream::StreamBackend;

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), true);
    let owner = fixture.enroll();
    let caller = OperationContext::new("ordinary-agent", "root", false, None, false);
    assert!(fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &caller, &owner)
        .is_err());
    assert!(fixture
        .kernel
        .create_record_wal(HISTORY, OWNER, &service(), b"wrong revision")
        .is_err());
    assert!(fixture.store.get(HISTORY).unwrap().is_none());

    let other = Arc::new(fixture._runtime.store("/other", "/other"));
    fixture
        .kernel
        .mount(
            "/other",
            MountOptions::new(&service(), "local")
                .with_backend(Arc::new(
                    CasLocalBackend::new_durable(&directory.path().join("other-cas")).unwrap(),
                ))
                .with_metastore(other.clone()),
        )
        .unwrap();
    let other_owner_path = "/other/lifetime";
    let other_owner = fixture.enroll_at(other_owner_path, other.as_ref());
    let control = "/other/control-history";
    let other_writer = fixture
        .kernel
        .create_record_wal(control, other_owner_path, &service(), &other_owner)
        .unwrap();
    let other_reader = fixture
        .kernel
        .open_record_wal(control, &service(), &other_owner)
        .unwrap();
    assert_eq!(
        StreamBackend::push(&other_writer, b"valid other owner").unwrap(),
        0
    );
    assert_eq!(
        other_reader.read_at(0).unwrap(),
        Some(b"valid other owner".to_vec())
    );
    let before = other
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(other_owner_path)
        .unwrap()
        .unwrap();
    // Both views share the real root zone. Without the pair-route guard this
    // owner/revision is live even when accessed through the target's store.
    assert!(matches!(
        fixture
            .kernel
            .create_record_wal(HISTORY, other_owner_path, &service(), &other_owner),
        Err(ConditionalContentError::Unsupported)
    ));
    assert!(fixture.store.get(HISTORY).unwrap().is_none());
    assert_eq!(
        fixture
            .store
            .stream_tail(&wal_stream_prefix(HISTORY))
            .unwrap(),
        0
    );
    let after = other
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(other_owner_path)
        .unwrap()
        .unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.metadata, before.metadata);
    assert_eq!(
        other_reader.read_at(0).unwrap(),
        Some(b"valid other owner".to_vec())
    );
    // A refusal before binding must not publish a new protected path.
    fixture.store.put(HISTORY, image("still ordinary")).unwrap();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn kernel_owned_wal_refuses_unqualified_namespace_durability() {
    use kernel::kernel::conditional_content::ConditionalContentError;

    let directory = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(directory.path(), false);
    assert!(matches!(
        fixture
            .kernel
            .create_record_wal(HISTORY, OWNER, &service(), b"unqualified"),
        Err(ConditionalContentError::Unsupported)
    ));
    assert!(matches!(
        fixture
            .kernel
            .open_record_wal(HISTORY, &service(), b"unqualified"),
        Err(ConditionalContentError::Unsupported)
    ));
    assert!(fixture.store.get(HISTORY).unwrap().is_none());
    assert!(fixture.store.get(OWNER).unwrap().is_none());
}
