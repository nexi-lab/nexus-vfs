//! Exercise the trusted service boundary with actual Kernel/CAS/actor storage.

use super::*;

const OWNER: &str = "/state/owner";
const RECORD: &str = "/state/register";

fn service() -> OperationContext {
    OperationContext::new("alice", "root", true, None, false)
}

fn prepare(fixture: &Fixture) -> Vec<u8> {
    fixture.replace(OWNER, b"immutable owner payload", None);
    fixture
        .kernel
        .protect_record_content(OWNER, &service())
        .unwrap();
    let version = fixture
        .kernel
        .read_versioned_content(OWNER, &service())
        .unwrap()
        .unwrap()
        .version;
    fixture
        .kernel
        .admit_record_content_io(OWNER, &service(), &version)
        .unwrap();
    version
}

struct ParkPostWrite(Arc<Barrier>);

impl NativeInterceptHook for ParkPostWrite {
    fn name(&self) -> &str {
        "owner-control-real-io"
    }

    fn on_pre(&self, _context: &HookContext) -> Result<HookOutcome, String> {
        Ok(HookOutcome::Pass)
    }

    fn on_post(&self, context: &HookContext) {
        if matches!(context, HookContext::Write(write) if write.path == RECORD) {
            self.0.wait();
            self.0.wait();
        }
    }
}

#[test]
fn service_retirement_drains_actual_kernel_io_while_the_process_stays_alive() {
    let fixture = Fixture::open();
    let owner = prepare(&fixture);
    fixture
        .kernel
        .bind_record_content_owner(RECORD, OWNER, &service(), &owner)
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let hook_service = fixture
        .kernel
        .enlist_hook_only_service("owner-control")
        .unwrap();
    fixture
        .kernel
        .register_service_hook(&hook_service, Box::new(ParkPostWrite(barrier.clone())));
    let writer = {
        let kernel = fixture.kernel.clone();
        let owner = owner.clone();
        std::thread::spawn(move || {
            kernel.replace_guarded_content(RECORD, &context(), b"actual content", None, &owner)
        })
    };
    barrier.wait();
    let retired = fixture
        .kernel
        .retire_record_content_owner(OWNER, &service(), &owner);
    // Release the test worker even if a control assertion fails.
    let excluded = retired.as_ref().ok().and_then(|result| {
        if let ConditionalContentResult::Committed { version } = result {
            Some(
                fixture
                    .kernel
                    .try_exclude_retired_content_io(OWNER, &service(), version),
            )
        } else {
            None
        }
    });
    barrier.wait();
    assert!(matches!(
        writer.join().unwrap().unwrap(),
        ConditionalContentResult::Committed { .. }
    ));
    assert!(matches!(excluded, Some(Ok(None))));
    let terminal = committed(retired.unwrap());
    let exclusion = fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &service(), &terminal)
        .unwrap();
    assert!(exclusion.is_some());
    assert!(fixture
        .kernel
        .read_guarded_content(RECORD, &context(), &owner)
        .is_err());
    assert!(fixture
        .kernel
        .replace_guarded_content(RECORD, &context(), b"late", None, &owner)
        .is_err());
    assert!(!fixture
        .backend
        .as_cas()
        .unwrap()
        .content_exists(&lib::hash::hash_content(b"late")));
    // Ownership retirement changes its revision and permanent marker, not a
    // second application payload that could disagree with that decision.
    let visible = fixture
        .kernel
        .record_content_owner_state(OWNER, &service())
        .unwrap();
    assert_eq!(visible.version, terminal);
    assert!(visible.is_retired);
    assert!(fixture
        .kernel
        .read_versioned_content(OWNER, &context())
        .is_err());
    let image = fixture
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(OWNER)
        .unwrap()
        .unwrap();
    assert_eq!(image.version, terminal);
    assert_eq!(
        fixture
            .backend
            .as_cas()
            .unwrap()
            .read_content(image.metadata.content_id.as_deref().unwrap())
            .unwrap(),
        b"immutable owner payload"
    );
}

#[test]
fn service_controls_keep_original_permissions_and_recheck_directory_links() {
    let fixture = Fixture::open();
    let owner = prepare(&fixture);
    assert!(fixture
        .kernel
        .admit_record_content_io(OWNER, &context(), &owner)
        .is_err());
    assert!(fixture
        .kernel
        .bind_record_content_owner(RECORD, OWNER, &context(), &owner)
        .is_err());
    assert!(fixture
        .kernel
        .retire_record_content_owner(OWNER, &context(), &owner)
        .is_err());
    assert!(fixture
        .kernel
        .try_exclude_retired_content_io(OWNER, &context(), &owner)
        .is_err());
    fixture
        .store
        .put(
            "/state/private",
            FileMetadata {
                path: "/state/private".into(),
                entry_type: DT_LINK,
                link_target: Some("/alias".into()),
                ..Default::default()
            },
        )
        .unwrap();
    fixture
        .kernel
        .set_permission_provider(Arc::new(Box::new(DenyTarget)));
    for path in ["/alias/owner", "/state/private/owner"] {
        assert!(matches!(
            fixture
                .kernel
                .admit_record_content_io(path, &service(), &owner),
            Err(ConditionalContentError::Failed(
                KernelError::PermissionDenied(_)
            ))
        ));
        assert!(matches!(
            fixture
                .kernel
                .retire_record_content_owner(path, &service(), &owner),
            Err(ConditionalContentError::Failed(
                KernelError::PermissionDenied(_)
            ))
        ));
        assert!(matches!(
            fixture
                .kernel
                .try_exclude_retired_content_io(path, &service(), &owner),
            Err(ConditionalContentError::Failed(
                KernelError::PermissionDenied(_)
            ))
        ));
        assert!(matches!(
            fixture
                .kernel
                .bind_record_content_owner(RECORD, path, &service(), &owner),
            Err(ConditionalContentError::Failed(
                KernelError::PermissionDenied(_)
            ))
        ));
    }
    assert!(matches!(
        fixture.kernel.bind_record_content_owner(
            "/state/private/register",
            OWNER,
            &service(),
            &owner
        ),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
    // Failed control requests neither retired the owner nor enrolled the child.
    fixture.replace(RECORD, b"still ordinary", None);
}

#[test]
fn binding_refuses_mixed_mount_authority_and_unqualified_content() {
    let fixture = Fixture::open();
    let owner = prepare(&fixture);
    assert!(matches!(
        fixture
            .kernel
            .bind_record_content_owner("/alias/register", OWNER, &service(), &owner),
        Err(ConditionalContentError::Unsupported)
    ));
    let first = fixture.replace(RECORD, b"still writable", None);
    fixture
        .kernel
        .bind_record_content_owner("/alias/register", "/alias/owner", &service(), &owner)
        .unwrap();
    let bound = fixture
        .kernel
        .read_guarded_content(RECORD, &context(), &owner)
        .unwrap()
        .unwrap();
    assert_eq!(bound.content, b"still writable");
    assert_ne!(bound.version, first);
    assert!(fixture
        .kernel
        .replace_content_if_version(RECORD, &context(), b"unguarded", Some(&bound.version))
        .is_err());

    let invalid = "/state/missing-content";
    fixture
        .store
        .put(
            invalid,
            FileMetadata {
                path: invalid.into(),
                content_id: Some(lib::hash::hash_content(b"absent blob")),
                size: 11,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(fixture
        .kernel
        .bind_record_content_owner(invalid, OWNER, &service(), &owner)
        .is_err());
    // No owner policy was committed for the unqualified image.
    fixture.store.delete(invalid).unwrap();
}

#[test]
fn terminal_readback_and_refusal_survive_restart_without_reclaiming_other_objects() {
    let fixture = Fixture::open();
    fixture.replace(OWNER, b"immutable owner payload", None);
    fixture
        .kernel
        .protect_record_content(OWNER, &service())
        .unwrap();
    let version = fixture
        .kernel
        .read_versioned_content(OWNER, &service())
        .unwrap()
        .unwrap()
        .version;
    assert!(fixture
        .kernel
        .admit_record_content_io(OWNER, &service(), b"stale owner")
        .is_err());
    fixture
        .kernel
        .admit_record_content_io(OWNER, &service(), &version)
        .unwrap();
    fixture
        .kernel
        .bind_record_content_owner(RECORD, OWNER, &service(), &version)
        .unwrap();
    fixture
        .kernel
        .replace_guarded_content(RECORD, &context(), b"retained data", None, &version)
        .unwrap();
    let terminal = committed(
        fixture
            .kernel
            .retire_record_content_owner(OWNER, &service(), &version)
            .unwrap(),
    );
    let root = fixture._root.clone();
    drop(fixture);
    let reopened = Fixture::open_root(root);
    // Readback after a lost reply uses the actual terminal revision and native
    // exclusion operation, which verifies the permanent retirement marker.
    let snapshot = reopened
        .kernel
        .record_content_owner_state("/alias/owner", &service())
        .unwrap();
    assert_eq!(snapshot.version, terminal);
    assert!(snapshot.is_retired);
    assert!(reopened
        .kernel
        .read_versioned_content("/alias/owner", &context())
        .is_err());
    assert!(reopened
        .kernel
        .try_exclude_retired_content_io("/alias/owner", &service(), &snapshot.version)
        .unwrap()
        .is_some());
    for version in [&version, &terminal] {
        assert!(reopened
            .kernel
            .admit_record_content_io(OWNER, &service(), version)
            .is_err());
        assert!(reopened
            .kernel
            .bind_record_content_owner("/state/late", OWNER, &service(), version)
            .is_err());
        assert!(reopened
            .kernel
            .read_guarded_content(RECORD, &context(), version)
            .is_err());
    }
    assert!(reopened.store.delete(OWNER).is_err());
    // This control boundary does not run GC or remove independent Agent data.
    let independent = reopened.replace("/state/independent", b"independent data", None);
    assert_eq!(
        reopened
            .kernel
            .read_versioned_content("/state/independent", &context())
            .unwrap()
            .unwrap()
            .version,
        independent
    );
    assert!(reopened.store.get(RECORD).unwrap().is_some());
}
