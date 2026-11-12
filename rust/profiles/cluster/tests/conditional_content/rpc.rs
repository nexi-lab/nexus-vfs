//! Exercise both typed operations and a lost response against the real actor/store.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use kernel::kernel::conditional_content::{ConditionalContentError, ConditionalContentResult};
use kernel::kernel::{Kernel, KernelError, OperationContext};
use kernel::rpc_transport::RpcTransport;
use kernel::{HookContext, NativeInterceptHook, Permission, PermissionProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;
use transport::auth::{AuthCredentials, AuthProvider};

use super::{committed, Fixture};

struct Identity;

impl AuthProvider for Identity {
    fn resolve(&self, credentials: &AuthCredentials<'_>) -> Result<OperationContext, Status> {
        match credentials.token {
            "alice" | "bob" => Ok(OperationContext::new(
                credentials.token,
                "root",
                false,
                None,
                false,
            )),
            _ => Err(Status::unauthenticated("unknown fixture identity")),
        }
    }
}

struct OwnerOnly;

impl PermissionProvider for OwnerOnly {
    fn check(
        &self,
        _: &str,
        _: Option<&kernel::vfs_router::RouteResult>,
        _: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        if ctx.user_id == "alice" {
            Ok(())
        } else {
            Err(KernelError::PermissionDenied("private owner".into()))
        }
    }
}

struct Server {
    endpoint: String,
    runtime: Arc<tokio::runtime::Runtime>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Server {
    fn open(fixture: &Fixture) -> Self {
        fixture
            .kernel
            .set_permission_provider(Arc::new(Box::new(OwnerOnly)));
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let routes = transport::grpc::build_vfs_routes(
            fixture.kernel.clone(),
            Arc::new(Identity),
            Arc::new(std::sync::OnceLock::new()),
            transport::grpc::DataPlaneReady::open(),
            64 * 1024 * 1024,
            "conditional-fixture",
        );
        let (endpoint, shutdown, task) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (shutdown, stopped) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_routes(routes)
                    .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
            (endpoint, shutdown, task)
        });
        Self {
            endpoint,
            runtime,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    fn client(&self, token: &str) -> RpcTransport {
        RpcTransport::new(
            self.runtime.clone(),
            &self.endpoint,
            token,
            None,
            Duration::from_secs(10),
        )
        .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        self.runtime.block_on(self.task.take().unwrap()).unwrap();
    }
}

#[test]
fn enrolled_owner_excludes_generic_rpc_reads_and_materialization() {
    use super::guarded::{admit, install_stream_coordinator, OWNER, RECORD};
    use super::{context, FileMetadata, MANAGED};
    let fixture = Fixture::open();
    for mount in ["/state", "/alias"] {
        fixture.kernel.vfs_router_arc().add_federation_mount(
            mount,
            "root",
            Some(fixture.backend.clone()),
            "root",
            MANAGED,
            false,
        );
    }
    let owner = admit(&fixture);
    let service = OperationContext::new("alice", "root", true, None, false);
    let history = "/state/history";
    let owned = fixture
        .kernel
        .create_record_wal(history, OWNER, &service, &owner)
        .unwrap();
    owned.write_sync(b"scoped history").unwrap();
    assert_eq!(owned.read_at(0).unwrap(), Some(b"scoped history".to_vec()));
    fixture
        .store
        .put(
            "/state/public",
            FileMetadata {
                entry_type: kernel::meta_store::DT_STREAM,
                ..Default::default()
            },
        )
        .unwrap();
    install_stream_coordinator(&fixture);
    let server = Server::open(&fixture);
    let alice = server.client("alice");
    let bob = server.client("bob");
    assert_eq!(
        alice
            .stream_write_nowait("/state/public", b"ordinary stream")
            .unwrap(),
        0
    );
    assert_eq!(
        alice
            .stream_read_at("/alias/public", 0, false, 0)
            .unwrap()
            .data,
        b"ordinary stream"
    );
    assert!(bob.stream_read_at("/state/public", 0, false, 0).is_err());
    assert!(!fixture.kernel.has_stream(history));
    // A tail probe enters the actual miss-materializer without content-read
    // admission. It must not publish a generic handle for the enrolled WAL.
    assert!(fixture.kernel.stream_tail(history).is_err());
    assert!(!fixture.kernel.has_stream(history));
    // Explicit reopening shares the same factory admission as a tail miss.
    assert_generic_wal_reopen_refused(&fixture.kernel, history);
    for path in [history, "/alias/history"] {
        let error = match alice.stream_read_at(path, 0, false, 0) {
            Err(error) => error,
            Ok(_) => panic!("generic RPC must refuse the enrolled history"),
        };
        assert!(
            error.contains("requires the scoped owner handle"),
            "{error}"
        );
        assert!(!fixture.kernel.has_stream(path));
        let error = fixture
            .kernel
            .sys_stream_collect_all(path, &context())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires the scoped owner handle"));
        assert!(!fixture.kernel.has_stream(path));
    }
    committed(
        alice
            .write_guarded(RECORD, b"scoped regular data", None, &owner)
            .unwrap(),
    );
    assert_eq!(
        alice.read_guarded(RECORD, &owner).unwrap().unwrap().content,
        b"scoped regular data"
    );
    assert!(alice.read_versioned(RECORD).is_err());
    assert!(bob.read_guarded(RECORD, &owner).is_err());
    fixture.replace("/state/independent", b"independent file", None);
    let terminal = committed(
        fixture
            .kernel
            .retire_record_content_owner(OWNER, &service, &owner)
            .unwrap(),
    );
    assert!(alice.read_guarded(RECORD, &owner).is_err());
    assert!(alice.stream_read_at(history, 0, false, 0).is_err());
    assert!(owned.read_at(0).is_err());
    assert_eq!(
        alice
            .read_versioned("/state/independent")
            .unwrap()
            .unwrap()
            .content,
        b"independent file"
    );
    let state = fixture
        .kernel
        .record_content_owner_state(OWNER, &service)
        .unwrap();
    assert_eq!(state.version, terminal);
    assert!(state.is_retired);
}

fn assert_generic_wal_reopen_refused(kernel: &Kernel, path: &str) {
    assert!(kernel
        .sys_setattr(
            path,
            &OperationContext::new("alice", "root", true, None, false),
            i32::from(kernel::meta_store::DT_STREAM),
            "",
            None,
            None,
            None,
            "wal",
            "root",
            false,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .is_err());
    assert!(!kernel.has_stream(path));
}

struct IndependentStreamStores {
    owned: kernel::core::stream::wal::WalStreamCore,
    unowned: kernel::core::stream::wal::WalStreamCore,
    mounted: Fixture,
    coordinator: Fixture,
}

impl IndependentStreamStores {
    fn open() -> Self {
        use super::guarded::{admit, OWNER};
        use super::{FileMetadata, MANAGED};
        use kernel::core::stream::wal::WalStreamCore;

        let mounted = Fixture::open();
        let coordinator = Fixture::open();
        let owner = admit(&mounted);
        let service = OperationContext::new("alice", "root", true, None, false);
        let owned = mounted
            .kernel
            .create_record_wal("/state/history", OWNER, &service, &owner)
            .unwrap();
        owned.write_sync(b"owned store A").unwrap();
        coordinator
            .store
            .put(
                "/state/history",
                FileMetadata {
                    entry_type: kernel::meta_store::DT_STREAM,
                    ..Default::default()
                },
            )
            .unwrap();
        let canonical = format!("{MANAGED}/history");
        let unowned = WalStreamCore::new(coordinator.store.clone(), canonical.clone());
        unowned.write_sync(b"unowned store B").unwrap();
        assert_eq!(
            unowned.read_at(0).unwrap(),
            Some(b"unowned store B".to_vec())
        );
        coordinator
            .store
            .as_guarded_records()
            .unwrap()
            .check_unscoped_io(&canonical)
            .unwrap();
        Self::install_coordinator(&mounted, &coordinator);
        Self {
            mounted,
            coordinator,
            owned,
            unowned,
        }
    }

    fn mount_view(&self, source: &Fixture) {
        Self::mount_view_on(&self.mounted.kernel, source);
    }

    fn install_coordinator(receiver: &Fixture, source: &Fixture) {
        let ops = Arc::new(transport::federation::FederationClient::new(
            receiver.kernel.runtime().handle().clone(),
            None,
        ));
        Arc::new(nexus_raft::distributed_coordinator::RaftDistributedCoordinator::new())
            .install_with_kernel(
                source.manager.clone(),
                source.manager.runtime_handle(),
                "127.0.0.1:0",
                &receiver.kernel,
                ops,
            );
    }

    fn mount_view_on(target: &Kernel, source: &Fixture) {
        use super::{ZoneMetaStore, MANAGED};
        for mount in ["/state", "/alias"] {
            target.vfs_router_arc().add_federation_mount(
                mount,
                "root",
                Some(source.backend.clone()),
                "root",
                MANAGED,
                false,
            );
            target.install_mount_metastore(
                Kernel::canonical_mount_key(mount, "root"),
                Arc::new(ZoneMetaStore::new_with_subtree(
                    source
                        .manager
                        .get_zone("root")
                        .unwrap()
                        .consensus_node()
                        .clone(),
                    source.manager.runtime_handle(),
                    mount.into(),
                    MANAGED.into(),
                )),
            );
        }
    }

    fn assert_original_payloads(&self) {
        assert_eq!(
            self.owned.read_at(0).unwrap(),
            Some(b"owned store A".to_vec())
        );
        assert_eq!(
            self.unowned.read_at(0).unwrap(),
            Some(b"unowned store B".to_vec())
        );
    }
}

#[test]
fn mounted_owner_refuses_fresh_tail_materialization_from_unowned_coordinator() {
    let stores = IndependentStreamStores::open();
    stores.mount_view(&stores.mounted);
    for path in ["/state/history", "/alias/history"] {
        assert!(!stores.mounted.kernel.has_stream(path));
        // This metadata probe reaches the actual generic miss-materializer.
        // A's inode cannot authorize constructing/registering B's valid WAL.
        assert!(stores.mounted.kernel.stream_tail(path).is_err());
        assert!(!stores.mounted.kernel.has_stream(path));
        assert_generic_wal_reopen_refused(&stores.mounted.kernel, path);
    }
    stores.assert_original_payloads();
    // Reverse the stores on a separate, still-empty registry: the ordinary
    // mounted B inode cannot authorize opening the enrolled coordinator A WAL.
    IndependentStreamStores::install_coordinator(&stores.coordinator, &stores.mounted);
    IndependentStreamStores::mount_view_on(&stores.coordinator.kernel, &stores.coordinator);
    for path in ["/state/history", "/alias/history"] {
        assert!(!stores.coordinator.kernel.has_stream(path));
        assert!(stores.coordinator.kernel.stream_tail(path).is_err());
        assert!(!stores.coordinator.kernel.has_stream(path));
        assert_generic_wal_reopen_refused(&stores.coordinator.kernel, path);
    }
    stores.assert_original_payloads();
    // The same materializer must still open the genuinely ordinary B view.
    stores.mount_view(&stores.coordinator);
    assert_eq!(
        stores.mounted.kernel.stream_tail("/state/history").unwrap(),
        1
    );
    assert_eq!(
        stores
            .mounted
            .kernel
            .stream_read_at("/alias/history", 0)
            .unwrap()
            .expect("ordinary B materialization must retain its payload")
            .0,
        b"unowned store B"
    );
    stores.assert_original_payloads();
}

#[test]
fn mounted_owner_refuses_generic_reads_when_coordinator_has_an_unowned_same_key() {
    let stores = IndependentStreamStores::open();
    let fixture = &stores.mounted;
    stores.mount_view(&stores.coordinator);
    let server = Server::open(fixture);
    let alice = server.client("alice");
    assert!(!fixture.kernel.has_stream("/state/history"));
    assert_eq!(fixture.kernel.stream_tail("/state/history").unwrap(), 1);
    assert_eq!(
        alice
            .stream_read_at("/alias/history", 0, false, 0)
            .unwrap()
            .data,
        b"unowned store B"
    );
    assert!(fixture.kernel.has_stream("/state/history"));
    // Keep the original B handle registered while the mounted view becomes A.
    // Content-entry controls must refuse without relying on fresh materialization.
    stores.mount_view(&stores.mounted);
    for path in ["/state/history", "/alias/history"] {
        let error = match alice.stream_read_at(path, 0, false, 0) {
            Err(error) => error,
            Ok(_) => panic!("coordinator store B must not authorize the mounted owner A"),
        };
        assert!(
            error.contains("requires the scoped owner handle"),
            "{error}"
        );
        assert!(fixture.kernel.stream_read_at(path, 0).is_err());
        assert!(fixture.kernel.stream_read_batch(path, 0, 1).is_err());
        assert!(fixture.kernel.stream_collect_all(path).is_err());
        assert!(fixture.kernel.stream_read_at_blocking(path, 0, 0).is_err());
        assert!(
            fixture.kernel.has_stream(path),
            "the ordinary B handle remains the independent control"
        );
    }
    stores.assert_original_payloads();
}

#[test]
fn guarded_rpc_keeps_owner_permissions_and_refuses_retired_publication() {
    use super::guarded::{admit, retire, OWNER, RECORD};
    let fixture = Fixture::open();
    let handle = admit(&fixture);
    let server = Server::open(&fixture);
    let alice = server.client("alice");
    let bob = server.client("bob");
    let version = committed(
        alice
            .write_guarded(RECORD, b"guarded RPC content", None, &handle)
            .unwrap(),
    );
    let snapshot = alice
        .read_guarded("/alias/register", &handle)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.content, b"guarded RPC content");
    assert_eq!(snapshot.version, version);
    assert!(matches!(
        bob.read_guarded(RECORD, &handle),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(matches!(
        bob.write_guarded(RECORD, b"denied RPC payload", Some(&version), &handle),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(matches!(
        alice.write_guarded(RECORD, b"empty owner", Some(&version), &[]),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(matches!(
        alice.write_guarded(RECORD, b"empty expected version", Some(&[]), &handle),
        Err(ConditionalContentError::Failed(_))
    ));
    let terminal = retire(fixture.store.as_ref(), &handle);
    assert!(matches!(
        alice.write_guarded(RECORD, b"retired RPC payload", Some(&version), &handle),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(alice.read_guarded(RECORD, &terminal).is_err());
    use kernel::abc::object_store::ObjectStore;
    for content in [
        b"denied RPC payload".as_slice(),
        b"empty owner",
        b"empty expected version",
        b"retired RPC payload",
    ] {
        assert!(!fixture
            .backend
            .as_cas()
            .unwrap()
            .content_exists(&lib::hash::hash_content(content)));
    }
    assert!(fixture
        .store
        .as_guarded_records()
        .unwrap()
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_some());
}

#[test]
fn cancelled_guarded_rpc_keeps_its_blocking_worker_io_until_completion() {
    use super::guarded::{admit, retire, OWNER, RECORD};
    use kernel::kernel::vfs_proto::{
        nexus_vfs_service_client::NexusVfsServiceClient, WriteGuardedRequest,
    };
    use std::sync::{mpsc, Mutex};

    struct Completion {
        entered: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }
    impl NativeInterceptHook for Completion {
        fn name(&self) -> &str {
            "guarded-rpc-completion"
        }
        fn on_post(&self, context: &HookContext) {
            if matches!(context, HookContext::Write(_)) {
                self.entered.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
        }
    }

    let fixture = Fixture::open();
    let handle = admit(&fixture);
    let server = Server::open(&fixture);
    let (entered, admission) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let service = fixture
        .kernel
        .enlist_hook_only_service("guarded-rpc-completion")
        .unwrap();
    fixture.kernel.register_service_hook(
        &service,
        Box::new(Completion {
            entered,
            resume: Mutex::new(resumed),
        }),
    );
    let endpoint = server.endpoint.clone();
    let owner_version = handle.clone();
    let request = server.runtime.spawn(async move {
        NexusVfsServiceClient::connect(endpoint)
            .await
            .unwrap()
            .write_guarded(WriteGuardedRequest {
                path: RECORD.into(),
                content: b"real content before reply cancellation".to_vec(),
                auth_token: "alice".into(),
                expected_version: None,
                owner_version,
            })
            .await
    });
    admission.recv_timeout(Duration::from_secs(10)).unwrap();
    request.abort();
    assert!(server.runtime.block_on(request).unwrap_err().is_cancelled());
    let terminal = retire(fixture.store.as_ref(), &handle);
    let records = fixture.store.as_guarded_records().unwrap();
    assert!(records
        .try_exclude_retired_record_io(OWNER, &terminal)
        .unwrap()
        .is_none());
    resume.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let _exclusion = loop {
        if let Some(guard) = records
            .try_exclude_retired_record_io(OWNER, &terminal)
            .unwrap()
        {
            break guard;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the completed worker retained its native I/O handle"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(server
        .client("alice")
        .write_guarded(RECORD, b"late completion", None, &handle)
        .is_err());
}

#[test]
fn metadata_mutation_authorization_is_shared_by_native_and_rpc_entrypoints() {
    use kernel::kernel::vfs_proto::{
        nexus_vfs_service_client::NexusVfsServiceClient, SetattrRequest,
    };

    struct MetadataOwner;
    impl PermissionProvider for MetadataOwner {
        fn check(
            &self,
            _: &str,
            _: Option<&kernel::vfs_router::RouteResult>,
            _: Permission,
            ctx: &OperationContext,
        ) -> Result<(), KernelError> {
            if ctx.user_id == "alice" && ctx.zone_id == "root" {
                Ok(())
            } else {
                Err(KernelError::PermissionDenied(
                    "private metadata owner".into(),
                ))
            }
        }
    }

    let fixture = Fixture::open();
    let server = Server::open(&fixture);
    fixture
        .kernel
        .set_permission_provider(Arc::new(Box::new(MetadataOwner)));
    let alice = server.client("alice");
    let first = committed(
        alice
            .write_if_version("/state/register", b"owner bytes", None)
            .unwrap(),
    );
    let cases = [
        (0, "/state/register"),
        (0, "/state/denied-file"),
        (1, "/state/denied-dir"),
        (2, "/state/denied-mount"),
        (3, "/state/denied-pipe"),
        (4, "/state/denied-stream"),
        (6, "/state/denied-link"),
    ];
    server.runtime.block_on(async {
        let mut client = NexusVfsServiceClient::connect(server.endpoint.clone())
            .await
            .unwrap();
        for (entry_type, path) in cases {
            let response = client
                .setattr(SetattrRequest {
                    path: path.into(),
                    auth_token: "bob".into(),
                    entry_type,
                    zone_id: "root".into(),
                    mime_type: Some("text/plain".into()),
                    io_profile: "memory".into(),
                    capacity: 4096,
                    link_target: Some("/state/register".into()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            assert!(
                response.is_error,
                "RPC metadata operation {entry_type} must refuse bob"
            );
            let error: serde_json::Value = serde_json::from_slice(&response.error_payload).unwrap();
            assert!(
                [
                    transport::grpc::RpcErrorCode::PermissionError as i64,
                    transport::grpc::RpcErrorCode::AccessDenied as i64
                ]
                .contains(&error["code"].as_i64().unwrap()),
                "RPC metadata operation {entry_type} must report authorization failure: {error}"
            );
        }
    });
    let native = |path: &str, entry_type, ctx: &OperationContext, zone: &str| {
        fixture.kernel.sys_setattr(
            path,
            ctx,
            entry_type,
            "",
            None,
            None,
            None,
            "memory",
            zone,
            false,
            4096,
            None,
            None,
            Some("text/plain"),
            None,
            None,
            None,
            None,
            None,
            Some("/state/register"),
            None,
            None,
        )
    };
    let bob = OperationContext::new("bob", "root", false, None, false);
    for (entry_type, path) in cases {
        let result = native(path, entry_type, &bob, "root");
        assert!(
            matches!(&result, Err(KernelError::PermissionDenied(_))),
            "native metadata operation {entry_type} must refuse bob: {result:?}"
        );
    }
    let after = alice.read_versioned("/state/register").unwrap().unwrap();
    assert_eq!(after.content, b"owner bytes");
    assert_eq!(after.version, first);
    for (_, path) in &cases[1..] {
        assert!(
            fixture.store.get(path).unwrap().is_none(),
            "denied create left {path}"
        );
    }
    // An explicit metadata zone selects the same view for authorization and
    // mutation. Omitting it retains the authenticated caller's zone.
    let elsewhere = OperationContext::new("alice", "other-zone", false, None, false);
    assert!(matches!(
        native("/state/register", 0, &elsewhere, ""),
        Err(KernelError::PermissionDenied(_))
    ));
    native("/state/register", 0, &elsewhere, "root").unwrap();
    let owner = OperationContext::new("alice", "root", false, None, false);
    for path in ["/__sys__", "/__sys__/private-metadata"] {
        assert!(
            matches!(
                native(path, 0, &owner, "root"),
                Err(KernelError::PermissionDenied(_))
            ),
            "native metadata must protect the system namespace: {path}"
        );
        server.runtime.block_on(async {
            let mut client = NexusVfsServiceClient::connect(server.endpoint.clone())
                .await
                .unwrap();
            let response = client
                .setattr(SetattrRequest {
                    path: path.into(),
                    auth_token: "alice".into(),
                    zone_id: "root".into(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            assert!(response.is_error, "RPC must protect the system namespace");
            let error: serde_json::Value = serde_json::from_slice(&response.error_payload).unwrap();
            assert_eq!(
                error["code"].as_i64().unwrap(),
                transport::grpc::RpcErrorCode::PermissionError as i64
            );
        });
        assert!(
            kernel::kernel::syscall::KernelSyscall::sys_stat(&*fixture.kernel, path, "root")
                .is_none()
        );
    }
    native("/state/owner-directory", 1, &owner, "").unwrap();
    assert_eq!(
        fixture
            .store
            .get("/state/register")
            .unwrap()
            .unwrap()
            .mime_type
            .as_deref(),
        Some("text/plain")
    );
    assert_eq!(
        alice
            .read_versioned("/state/register")
            .unwrap()
            .unwrap()
            .content,
        b"owner bytes"
    );
    assert!(fixture
        .store
        .get("/state/owner-directory")
        .unwrap()
        .is_some());
}

#[test]
fn typed_rpc_preserves_atomic_images_conflicts_and_authenticated_ownership() {
    let fixture = Fixture::open();
    let server = Server::open(&fixture);
    let alice = Arc::new(server.client("alice"));
    assert!(matches!(
        alice.write_if_version("/state/register", b"invalid token", Some(b"")),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(alice.read_versioned("/state/register").unwrap().is_none());
    let first = committed(
        alice
            .write_if_version("/state/register", b"", None)
            .unwrap(),
    );
    let empty = alice.read_versioned("/alias/register").unwrap().unwrap();
    assert!(empty.content.is_empty());
    assert_eq!(empty.version, first);
    let barrier = Arc::new(Barrier::new(2));
    let writers: Vec<_> = [b"second".as_slice(), b"third".as_slice()]
        .into_iter()
        .map(|bytes| {
            let (client, barrier, first) = (alice.clone(), barrier.clone(), first.clone());
            std::thread::spawn(move || {
                barrier.wait();
                client
                    .write_if_version("/alias/register", bytes, Some(&first))
                    .unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, ConditionalContentResult::Committed { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, ConditionalContentResult::Conflict { .. }))
            .count(),
        1
    );
    let image = alice.read_versioned("/state/register").unwrap().unwrap();
    assert!(image.content == b"second" || image.content == b"third");
    assert_ne!(image.version, first);
    let bob = server.client("bob");
    assert!(matches!(
        bob.read_versioned("/state/register"),
        Err(ConditionalContentError::Failed(_))
    ));
    assert!(matches!(
        bob.write_if_version("/state/register", b"foreign", Some(&image.version)),
        Err(ConditionalContentError::Failed(_))
    ));
    let after = alice.read_versioned("/state/register").unwrap().unwrap();
    assert_eq!(after.content, image.content);
    assert_eq!(after.version, image.version);
    assert!(matches!(
        alice.read_versioned("/unsupported"),
        Err(ConditionalContentError::Unsupported)
    ));
    assert!(matches!(
        alice.write_if_version("/unsupported", b"refused", None),
        Err(ConditionalContentError::Unsupported)
    ));
}

struct CommitCount(Arc<AtomicUsize>);

impl NativeInterceptHook for CommitCount {
    fn name(&self) -> &str {
        "conditional-response-loss"
    }
    fn on_post(&self, context: &HookContext) {
        if matches!(context, HookContext::Write(_)) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn a_lost_real_write_reply_is_unknown_without_replaying_the_committed_image() {
    let fixture = Fixture::open();
    let commits = Arc::new(AtomicUsize::new(0));
    let handle = fixture
        .kernel
        .enlist_hook_only_service("response-loss")
        .unwrap();
    fixture
        .kernel
        .register_service_hook(&handle, Box::new(CommitCount(commits.clone())));
    let server = Server::open(&fixture);
    let target = server.endpoint.trim_start_matches("http://").to_owned();
    let observed = commits.clone();
    let (endpoint, proxy) = server.runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let proxy = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
            let (mut client_read, mut client_write) = client.split();
            let (mut server_read, mut server_write) = upstream.split();
            let requests = async { tokio::io::copy(&mut client_read, &mut server_write).await };
            let responses = async {
                let mut buffer = [0_u8; 8192];
                loop {
                    let count = server_read.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0, "the real server must answer");
                    if observed.load(Ordering::SeqCst) > 0 { break; }
                    client_write.write_all(&buffer[..count]).await.unwrap();
                }
            };
            tokio::select! { _ = requests => panic!("client closed before the committed response"), _ = responses => {} }
        });
        (endpoint, proxy)
    });
    let remote = RpcTransport::new(
        server.runtime.clone(),
        &endpoint,
        "alice",
        None,
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(matches!(
        remote.write_if_version("/state/register", b"durable fence", None),
        Err(ConditionalContentError::Unknown(_))
    ));
    server.runtime.block_on(proxy).unwrap();
    assert_eq!(commits.load(Ordering::SeqCst), 1);
    let committed = server
        .client("alice")
        .read_versioned("/state/register")
        .unwrap()
        .unwrap();
    assert_eq!(committed.content, b"durable fence");
    assert!(!committed.version.is_empty());
}
