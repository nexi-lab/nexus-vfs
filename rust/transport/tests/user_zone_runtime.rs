//! Authenticated owner zone operations over real mTLS and a durable root journal.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use auth::ApiKeyAuthProvider;
use kernel::kernel::vfs_proto::{zone_runtime_service_client::ZoneRuntimeServiceClient, *};
use kernel::kernel::Kernel;
use lib::transport_primitives::{SharedTlsConfig, TlsPolicy};
use nexus_raft::transport::{
    generate_node_cert, generate_session_agent_cert, generate_zone_ca, TlsConfig,
};
use nexus_raft::{ZoneManager, ZoneRuntimeBackend, ZoneRuntimeError};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Code, Status};
use transport::auth::{AuthCredentials, AuthProvider};
use transport::grpc::DataPlaneReady;
use transport::runtime_scope::RuntimeScope;
use transport::zone_runtime::{
    build_user_zone_runtime_routes, ZoneRuntimeCapabilities, ZoneRuntimeOps,
};

#[derive(Default)]
struct Cut {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
}
impl Cut {
    fn hold(&self) {
        self.entered.notify_one();
        let released = self.released.lock().unwrap();
        let (released, limit) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(10), |value| !*value)
            .unwrap();
        assert!(
            *released && !limit.timed_out(),
            "fixture cut was not released"
        );
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
    async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.entered.notified())
            .await
            .unwrap();
    }
}

#[derive(Default)]
struct AuthCut {
    calls: AtomicUsize,
    selected: Mutex<Option<(usize, Arc<Cut>)>>,
}

struct CountingAuth {
    cut: Arc<AuthCut>,
    inner: Arc<ApiKeyAuthProvider>,
    resolved: Arc<tokio::sync::Notify>,
}
impl AuthProvider for CountingAuth {
    fn resolve(
        &self,
        credentials: &AuthCredentials<'_>,
    ) -> Result<kernel::kernel::OperationContext, Status> {
        let result = self.inner.resolve(credentials);
        let call = self.cut.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let pause = {
            let mut selected = self.cut.selected.lock().unwrap();
            if selected.as_ref().is_some_and(|(at, _)| *at == call) {
                selected.take().map(|(_, cut)| cut)
            } else {
                None
            }
        };
        if let Some(cut) = pause {
            cut.hold();
        }
        self.resolved.notify_one();
        result
    }
}

struct ObservedBackend {
    inner: Arc<ZoneRuntimeBackend>,
    calls: AtomicUsize,
    after_unmount: Mutex<Option<Arc<Cut>>>,
    after_read: Mutex<Option<Arc<Cut>>>,
}
impl ObservedBackend {
    fn entered(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}
macro_rules! delegate {
    ($name:ident, $req:ty, $res:ty) => {
        fn $name(&self, request: &$req) -> Result<$res, ZoneRuntimeError> {
            self.entered();
            self.inner.$name(request)
        }
    };
}
impl ZoneRuntimeOps for ObservedBackend {
    fn is_local_root(&self) -> bool {
        self.inner.is_local_root()
    }
    delegate!(zone_create, ZoneCreateRequest, ZoneReceipt);
    delegate!(zone_join, ZoneJoinRequest, ZoneReceipt);
    delegate!(zone_mount, ZoneMountRequest, ZoneReceipt);
    delegate!(zone_remove_replica, ZoneRemoveReplicaRequest, ZoneReceipt);
    delegate!(zone_deprovision, ZoneDeprovisionRequest, ZoneReceipt);
    delegate!(
        get_zone_operation,
        GetZoneOperationRequest,
        ZoneOperationRecord
    );
    fn zone_unmount(&self, req: &ZoneUnmountRequest) -> Result<ZoneReceipt, ZoneRuntimeError> {
        self.entered();
        let result = self.inner.zone_unmount(req);
        if let Some(cut) = self.after_unmount.lock().unwrap().take() {
            cut.hold();
        }
        result
    }
    fn zone_status(&self, req: &ZoneStatusRequest) -> Result<ZoneStatusResponse, ZoneRuntimeError> {
        self.entered();
        let result = self.inner.zone_status(req);
        if let Some(cut) = self.after_read.lock().unwrap().take() {
            cut.hold();
        }
        result
    }
}

struct Fixture {
    kernel: Arc<Kernel>,
    auth_cut: Arc<AuthCut>,
    manager: Arc<ZoneManager>,
    backend: Arc<ObservedBackend>,
    directory: tempfile::TempDir,
    ca: Vec<u8>,
    ca_key: Vec<u8>,
    tls: TlsConfig,
    identity: SharedTlsConfig,
    auth: Arc<ApiKeyAuthProvider>,
    resolved: Arc<tokio::sync::Notify>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_operator_backend(false)
    }
    fn with_operator_backend(operator: bool) -> Self {
        lib::transport_primitives::ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let manager = ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
        let root = manager.create_zone(contracts::ROOT_ZONE_ID).unwrap();
        assert!(root.wait_for_leader(Duration::from_secs(10)));
        let backend = Arc::new(ObservedBackend {
            inner: Arc::new(if operator {
                ZoneRuntimeBackend::new(
                    Arc::clone(&manager),
                    nexus_raft::zone_op_journal::ZoneOpJournal::new(
                        root.consensus_node(),
                        root.runtime_handle(),
                    ),
                    Arc::new(
                        nexus_raft::zone_deletion_registry::ZoneDeletionRegistry::new(
                            root.consensus_node(),
                            root.runtime_handle(),
                            manager.node_id(),
                        ),
                    ),
                )
            } else {
                ZoneRuntimeBackend::for_local_root(Arc::clone(&manager)).unwrap()
            }),
            calls: AtomicUsize::new(0),
            after_unmount: Mutex::new(None),
            after_read: Mutex::new(None),
        });
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let (cert_pem, key_pem) = generate_node_cert(2, "root", &ca, &ca_key, &[], None).unwrap();
        let tls = TlsConfig {
            cert_pem,
            key_pem,
            ca_pem: ca.clone(),
        };
        Self {
            kernel: Arc::new(Kernel::new()),
            auth_cut: Arc::new(AuthCut::default()),
            manager,
            backend,
            directory,
            identity: SharedTlsConfig::new(Some(tls.clone())),
            tls,
            ca,
            ca_key,
            auth: Arc::new(ApiKeyAuthProvider::cert_identity_only()),
            resolved: Arc::new(tokio::sync::Notify::new()),
        }
    }
    async fn serve(&self) -> Listener {
        let ops = Arc::new(OnceLock::new());
        let observed: Arc<dyn ZoneRuntimeOps> = self.backend.clone();
        assert!(ops.set(observed).is_ok());
        let capabilities = Arc::new(OnceLock::new());
        assert!(capabilities
            .set(Arc::new(ZoneRuntimeCapabilities {
                node_id: self.manager.node_id().to_string(),
                auth_armed: true,
                auth_mode: "certificate".into(),
                permission_provider_armed: false,
                journal_zone: "root".into(),
                deletion_protection: false,
                capabilities: vec!["owner-local-zone-runtime".into()],
            }))
            .is_ok());
        let routes = build_user_zone_runtime_routes(
            Arc::new(CountingAuth {
                cut: Arc::clone(&self.auth_cut),
                inner: Arc::clone(&self.auth),
                resolved: Arc::clone(&self.resolved),
            }),
            ops,
            DataPlaneReady::open(),
            Arc::clone(&self.kernel),
            capabilities,
            Arc::new(OnceLock::new()),
            RuntimeScope::new("alice".into(), [])
                .unwrap()
                .with_server_identity(self.identity.clone()),
            contracts::MAX_GRPC_MESSAGE_BYTES,
        );
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(&self.tls.cert_pem, &self.tls.key_pem))
                    .client_ca_root(Certificate::from_pem(&self.ca)),
            )
            .unwrap()
            .add_routes(routes.into());
        let task = tokio::spawn(server.serve_with_incoming_shutdown(
            TcpListenerStream::new(socket),
            async {
                let _ = stopped.await;
            },
        ));
        Listener {
            address: format!("https://{address}"),
            stop,
            task,
        }
    }
    async fn client(
        &self,
        server: &Listener,
        owner: &str,
    ) -> (ZoneRuntimeServiceClient<Channel>, Vec<u8>) {
        let (cert, key) = generate_session_agent_cert(
            &format!("session-{owner}"),
            owner,
            300,
            &self.ca,
            &self.ca_key,
        )
        .unwrap();
        let channel = self.channel(server, &cert, &key).await;
        (ZoneRuntimeServiceClient::new(channel), cert)
    }
    async fn channel(&self, server: &Listener, cert: &[u8], key: &[u8]) -> Channel {
        Endpoint::from_shared(server.address.clone())
            .unwrap()
            .timeout(Duration::from_secs(10))
            .tls_config(
                ClientTlsConfig::new()
                    .domain_name(TlsConfig::CLUSTER_SERVER_NAME)
                    .ca_certificate(Certificate::from_pem(&self.ca))
                    .identity(Identity::from_pem(cert, key)),
            )
            .unwrap()
            .connect()
            .await
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.manager.shutdown();
        assert!(self.directory.path().exists());
    }
}
struct Listener {
    address: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}
impl Listener {
    async fn close(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap().unwrap();
    }
}
fn request(id: &str) -> ZoneUnmountRequest {
    ZoneUnmountRequest {
        parent_zone_id: "root".into(),
        mount_path: "/missing".into(),
        mutation: Some(ZoneMutationHeader {
            operation_id: id.into(),
            request_hash: 0,
        }),
        ..Default::default()
    }
}
fn status() -> ZoneStatusRequest {
    ZoneStatusRequest {
        zone_id: "root".into(),
        ..Default::default()
    }
}
fn run(test: impl AsyncFnOnce(&Fixture)) {
    let fixture = Fixture::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
        .block_on(test(&fixture));
}

#[test]
fn owner_zone_rpc_preserves_scope_and_original_journal() {
    run(async |fixture| {
        let server = fixture.serve().await;
        let (mut alice, _) = fixture.client(&server, "alice").await;
        let observed = alice.zone_status(status()).await.unwrap().into_inner();
        assert!(observed.cluster.is_none());
        let (mut bob, _) = fixture.client(&server, "bob").await;
        assert_eq!(
            bob.zone_status(status()).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        let mut node = ZoneRuntimeServiceClient::new(
            fixture
                .channel(&server, &fixture.tls.cert_pem, &fixture.tls.key_pem)
                .await,
        );
        assert_eq!(
            node.zone_status(status()).await.unwrap_err().code(),
            Code::PermissionDenied
        );
        let before = fixture.backend.calls.load(Ordering::SeqCst);
        assert_eq!(
            alice
                .zone_create(ZoneCreateRequest {
                    zone_id: "data".into(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        assert_eq!(
            alice
                .zone_deprovision(ZoneDeprovisionRequest {
                    zone_id: "data".into(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), before);
        assert_eq!(
            alice
                .zone_unmount(request("original"))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        let record = alice
            .get_zone_operation(GetZoneOperationRequest {
                operation_id: "original".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(record.operation_id, "original");
        assert!(!record.error.is_empty());
        server.close().await;
    });
}

#[test]
fn queued_owner_operation_rechecks_receiver_before_journal() {
    run(async |fixture| {
        let server = fixture.serve().await;
        let (mut alice, _) = fixture.client(&server, "alice").await;
        let cut = Arc::new(Cut::default());
        let worker = Arc::clone(&cut);
        let blocking = tokio::task::spawn_blocking(move || worker.hold());
        cut.entered().await;
        let pending = tokio::spawn(async move { alice.zone_unmount(request("queued")).await });
        tokio::time::timeout(Duration::from_secs(10), fixture.resolved.notified())
            .await
            .unwrap();
        fixture.identity.replace(TlsPolicy::Rejected("withdrawn"));
        cut.release();
        blocking.await.unwrap();
        assert_eq!(
            pending.await.unwrap().unwrap_err().code(),
            Code::Unavailable
        );
        assert_eq!(
            fixture.backend.calls.load(Ordering::SeqCst),
            0,
            "retired receiver reached the backend"
        );
        fixture
            .identity
            .replace(TlsPolicy::Configured(fixture.tls.clone()));
        let (mut current, _) = fixture.client(&server, "alice").await;
        assert_eq!(
            current
                .get_zone_operation(GetZoneOperationRequest {
                    operation_id: "queued".into(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        current.zone_status(status()).await.unwrap();
        server.close().await;
    });
}

#[test]
fn replaced_receiver_withholds_completed_mutation_and_preserves_readback() {
    run(async |fixture| {
        let server = fixture.serve().await;
        let (mut alice, _) = fixture.client(&server, "alice").await;
        let cut = Arc::new(Cut::default());
        *fixture.backend.after_unmount.lock().unwrap() = Some(Arc::clone(&cut));
        let pending = tokio::spawn(async move { alice.zone_unmount(request("committed")).await });
        cut.entered().await;
        // Identical bytes are a new installation and cannot release the old call.
        fixture
            .identity
            .replace(TlsPolicy::Configured(fixture.tls.clone()));
        cut.release();
        assert_eq!(pending.await.unwrap().unwrap_err().code(), Code::Unknown);
        let (mut current, _) = fixture.client(&server, "alice").await;
        let original = current
            .get_zone_operation(GetZoneOperationRequest {
                operation_id: "committed".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(original.operation_id, "committed");
        assert!(!original.error.is_empty());
        let replay = current
            .get_zone_operation(GetZoneOperationRequest {
                operation_id: "committed".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(original, replay);
        server.close().await;
    });
}

#[test]
fn revoked_owner_cannot_receive_an_inflight_read() {
    run(async |fixture| {
        let server = fixture.serve().await;
        let (mut alice, cert) = fixture.client(&server, "alice").await;
        let cut = Arc::new(Cut::default());
        *fixture.backend.after_read.lock().unwrap() = Some(Arc::clone(&cut));
        let pending = tokio::spawn(async move { alice.zone_status(status()).await });
        cut.entered().await;
        let der = lib::transport_primitives::first_certificate_der(&cert, "fixture").unwrap();
        let serial = transport::peer_identity::from_der(&der).unwrap().serial;
        fixture.auth.set_revoked_serials(HashSet::from([serial]));
        cut.release();
        assert_eq!(
            pending.await.unwrap().unwrap_err().code(),
            Code::Unauthenticated
        );
        fixture.auth.set_revoked_serials(HashSet::new());
        let (mut current, _) = fixture.client(&server, "alice").await;
        current.zone_status(status()).await.unwrap();
        server.close().await;
    });
}

#[test]
fn owner_zone_route_refuses_an_operator_backend() {
    let fixture = Fixture::with_operator_backend(true);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let server = fixture.serve().await;
            let (mut alice, _) = fixture.client(&server, "alice").await;
            assert_eq!(
                alice.zone_status(status()).await.unwrap_err().code(),
                Code::Unavailable
            );
            assert_eq!(
                alice
                    .zone_unmount(request("wrong-backend"))
                    .await
                    .unwrap_err()
                    .code(),
                Code::Unavailable
            );
            assert_eq!(fixture.backend.calls.load(Ordering::SeqCst), 0);
            server.close().await;
        });
}

#[test]
fn receiver_replacement_during_authentication_is_rechecked_before_journal() {
    run(async |fixture| {
        let server = fixture.serve().await;
        let (mut alice, _) = fixture.client(&server, "alice").await;
        let cut = Arc::new(Cut::default());
        // Capture and the queued-worker check precede the final identity check
        // after mount permission. Pause that last check before journal access.
        *fixture.auth_cut.selected.lock().unwrap() = Some((3, Arc::clone(&cut)));
        let pending = tokio::spawn(async move { alice.zone_unmount(request("auth-wait")).await });
        cut.entered().await;
        assert_eq!(fixture.auth_cut.calls.load(Ordering::SeqCst), 3);
        fixture
            .identity
            .replace(TlsPolicy::Configured(fixture.tls.clone()));
        cut.release();
        assert_eq!(
            pending.await.unwrap().unwrap_err().code(),
            Code::Unavailable
        );
        assert_eq!(
            fixture.backend.calls.load(Ordering::SeqCst),
            0,
            "receiver replaced during authentication reached the journal"
        );
        let (mut current, _) = fixture.client(&server, "alice").await;
        assert_eq!(
            current
                .get_zone_operation(GetZoneOperationRequest {
                    operation_id: "auth-wait".into(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        current.zone_status(status()).await.unwrap();
        server.close().await;
    });
}

struct PermissionCut(Arc<Cut>);
impl kernel::PermissionProvider for PermissionCut {
    fn check(
        &self,
        _path: &str,
        _route: Option<&kernel::vfs_router::RouteResult>,
        _permission: kernel::Permission,
        _context: &kernel::kernel::OperationContext,
    ) -> Result<(), kernel::kernel::KernelError> {
        self.0.hold();
        Ok(())
    }
}

#[test]
fn owner_revocation_during_mount_permission_wait_prevents_journal_effects() {
    run(async |fixture| {
        let cut = Arc::new(Cut::default());
        fixture
            .kernel
            .set_permission_provider(Arc::new(Box::new(PermissionCut(Arc::clone(&cut)))));
        let server = fixture.serve().await;
        let (mut alice, cert) = fixture.client(&server, "alice").await;
        let pending =
            tokio::spawn(async move { alice.zone_unmount(request("permission-wait")).await });
        cut.entered().await;
        let der = lib::transport_primitives::first_certificate_der(&cert, "fixture").unwrap();
        let serial = transport::peer_identity::from_der(&der).unwrap().serial;
        fixture.auth.set_revoked_serials(HashSet::from([serial]));
        cut.release();
        assert_eq!(
            pending.await.unwrap().unwrap_err().code(),
            Code::Unauthenticated
        );
        assert_eq!(
            fixture.backend.calls.load(Ordering::SeqCst),
            0,
            "revoked caller reached the journal after the permission wait"
        );
        fixture.auth.set_revoked_serials(HashSet::new());
        let (mut current, _) = fixture.client(&server, "alice").await;
        assert_eq!(
            current
                .get_zone_operation(GetZoneOperationRequest {
                    operation_id: "permission-wait".into(),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        current.zone_status(status()).await.unwrap();
        server.close().await;
    });
}
