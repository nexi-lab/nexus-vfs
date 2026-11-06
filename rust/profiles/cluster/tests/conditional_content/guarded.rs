//! Actual Kernel, native CAS and actor composition for admitted content I/O.

use super::*;
use kernel::meta_store::ConditionalMetadataResult;

pub(super) const OWNER: &str = "/state/lifetime";
pub(super) const RECORD: &str = "/state/register";

pub(super) fn admit(fixture: &Fixture) -> Vec<u8> {
    fixture.replace(OWNER, b"live storage incarnation", None);
    let service = OperationContext::new("alice", "root", true, None, false);
    fixture
        .kernel
        .protect_record_content(OWNER, &service)
        .unwrap();
    let owner = fixture
        .store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(OWNER)
        .unwrap()
        .unwrap();
    let records = fixture.store.as_guarded_records().unwrap();
    records
        .bind_record_guard(RECORD, None, OWNER, &owner.version)
        .unwrap();
    records
        .admit_record_io_owner(OWNER, &owner.version)
        .unwrap();
    owner.version
}

pub(super) fn retire(store: &dyn MetaStore, handle: &[u8]) -> Vec<u8> {
    let image = store
        .as_conditional_metadata()
        .unwrap()
        .read_versioned(OWNER)
        .unwrap()
        .unwrap()
        .metadata;
    match store
        .as_guarded_records()
        .unwrap()
        .retire_record_guard(OWNER, image, handle)
        .unwrap()
    {
        ConditionalMetadataResult::Committed { version } => version,
        result => panic!("expected retirement: {result:?}"),
    }
}

fn assert_not_published(fixture: &Fixture, content: &[u8]) {
    assert!(!fixture
        .backend
        .as_cas()
        .unwrap()
        .content_exists(&lib::hash::hash_content(content)));
}

#[test]
fn guarded_content_keeps_hooks_and_aliases_then_refuses_retired_io_across_restart() {
    let fixture = Fixture::open();
    let handle = admit(&fixture);
    let posts = Arc::new(Mutex::new(Vec::new()));
    let service = fixture
        .kernel
        .enlist_hook_only_service("guarded-write")
        .unwrap();
    fixture
        .kernel
        .register_service_hook(&service, Box::new(RewriteHook(posts.clone())));
    let version = committed(
        fixture
            .kernel
            .replace_guarded_content(RECORD, &context(), b"input", None, &handle)
            .unwrap(),
    );
    let read = fixture
        .kernel
        .read_guarded_content("/alias/register", &context(), &handle)
        .unwrap()
        .unwrap();
    assert_eq!(read.version, version);
    assert_eq!(read.content, b"policy replacement");
    assert!(matches!(
        fixture
            .kernel
            .replace_guarded_content(RECORD, &context(), b"conflict", None, &handle)
            .unwrap(),
        ConditionalContentResult::Conflict { .. }
    ));
    assert_eq!(*posts.lock().unwrap(), [RECORD]);
    let terminal = retire(fixture.store.as_ref(), &handle);
    assert!(fixture
        .kernel
        .read_guarded_content(RECORD, &context(), &handle)
        .is_err());
    let root = fixture._root.clone();
    drop(fixture);
    let fixture = Fixture::open_root(root);
    assert!(fixture
        .kernel
        .replace_guarded_content(
            "/alias/register",
            &context(),
            b"retired payload",
            Some(&version),
            &handle
        )
        .is_err());
    assert_not_published(&fixture, b"retired payload");
    assert!(fixture
        .kernel
        .read_guarded_content(RECORD, &context(), &terminal)
        .is_err());
    assert!(fixture
        .store
        .as_guarded_records()
        .unwrap()
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_some());
}

#[test]
fn a_wrong_owner_handle_cannot_publish_immutable_bytes() {
    let fixture = Fixture::open();
    let handle = admit(&fixture);
    let other = fixture.replace("/state/another-owner", b"another owner", None);
    assert!(fixture
        .kernel
        .replace_guarded_content(RECORD, &context(), b"wrong owner payload", None, &other)
        .is_err());
    assert_not_published(&fixture, b"wrong owner payload");
    assert!(fixture
        .kernel
        .read_guarded_content(RECORD, &context(), &other)
        .is_err());
    assert!(fixture
        .kernel
        .read_guarded_content(RECORD, &context(), &handle)
        .unwrap()
        .is_none());
}

#[test]
fn guarded_directory_links_recheck_the_target_permission_without_publishing() {
    let fixture = Fixture::open();
    let handle = admit(&fixture);
    fixture
        .store
        .put(
            "/state/shortcut",
            FileMetadata {
                path: "/state/shortcut".into(),
                entry_type: DT_LINK,
                link_target: Some("/alias".into()),
                ..Default::default()
            },
        )
        .unwrap();
    fixture
        .kernel
        .set_permission_provider(Arc::new(Box::new(DenyTarget)));
    assert!(matches!(
        fixture.kernel.replace_guarded_content(
            "/state/shortcut/register",
            &context(),
            b"denied guarded payload",
            None,
            &handle
        ),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
    assert_not_published(&fixture, b"denied guarded payload");
    assert!(matches!(
        fixture
            .kernel
            .read_guarded_content("/state/shortcut/register", &context(), &handle),
        Err(ConditionalContentError::Failed(
            KernelError::PermissionDenied(_)
        ))
    ));
}

struct RetireHook {
    store: Arc<dyn MetaStore>,
    handle: Vec<u8>,
    terminal: Arc<Mutex<Option<Vec<u8>>>>,
    before: bool,
}

impl NativeInterceptHook for RetireHook {
    fn name(&self) -> &str {
        "retire-during-content-write"
    }

    fn on_pre(&self, context: &HookContext) -> Result<HookOutcome, String> {
        if self.before && matches!(context, HookContext::Write(_)) {
            *self.terminal.lock().unwrap() = Some(retire(self.store.as_ref(), &self.handle));
        }
        Ok(HookOutcome::Pass)
    }

    fn on_post(&self, context: &HookContext) {
        assert!(
            !self.before || !matches!(context, HookContext::Write(_)),
            "a refused write cannot publish a completion notification"
        );
        if !self.before && matches!(context, HookContext::Write(_)) {
            let terminal = retire(self.store.as_ref(), &self.handle);
            assert!(
                self.store
                    .as_guarded_records()
                    .unwrap()
                    .try_exclude_retired_record_io(OWNER, &terminal)
                    .unwrap()
                    .is_none(),
                "the actual Kernel write retains its I/O handle through post-commit work"
            );
            *self.terminal.lock().unwrap() = Some(terminal);
        }
    }
}

#[test]
fn retirement_from_a_pre_hook_refuses_bytes_and_completion_notification() {
    let fixture = Fixture::open();
    let handle = admit(&fixture);
    let terminal = Arc::new(Mutex::new(None));
    let service = fixture
        .kernel
        .enlist_hook_only_service("retire-before-write")
        .unwrap();
    fixture.kernel.register_service_hook(
        &service,
        Box::new(RetireHook {
            store: fixture.store.clone(),
            handle: handle.clone(),
            terminal: terminal.clone(),
            before: true,
        }),
    );
    assert!(fixture
        .kernel
        .replace_guarded_content(
            RECORD,
            &context(),
            b"pre-hook retired payload",
            None,
            &handle
        )
        .is_err());
    assert_not_published(&fixture, b"pre-hook retired payload");
    assert!(terminal.lock().unwrap().is_some());
    assert!(fixture.store.get(RECORD).unwrap().is_none());
}

#[test]
fn kernel_io_handle_outlives_real_content_publication_and_post_commit_work() {
    let fixture = Fixture::open();
    let handle = admit(&fixture);
    let terminal = Arc::new(Mutex::new(None));
    let service = fixture
        .kernel
        .enlist_hook_only_service("retire-after-write")
        .unwrap();
    fixture.kernel.register_service_hook(
        &service,
        Box::new(RetireHook {
            store: fixture.store.clone(),
            handle: handle.clone(),
            terminal: terminal.clone(),
            before: false,
        }),
    );
    committed(
        fixture
            .kernel
            .replace_guarded_content(
                RECORD,
                &context(),
                b"committed before retirement",
                None,
                &handle,
            )
            .unwrap(),
    );
    assert_eq!(
        fixture
            .backend
            .as_cas()
            .unwrap()
            .read_content(&lib::hash::hash_content(b"committed before retirement"))
            .unwrap(),
        b"committed before retirement"
    );
    let terminal = terminal.lock().unwrap().clone().unwrap();
    assert!(fixture
        .store
        .as_guarded_records()
        .unwrap()
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_some());
}
