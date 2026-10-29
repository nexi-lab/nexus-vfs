//! Exercise both typed operations and a lost response against the real actor/store.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use kernel::kernel::conditional_content::{ConditionalContentError, ConditionalContentResult};
use kernel::kernel::{KernelError, OperationContext};
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
