//! HTTP API for search, indexing, credentials, and relationship grants.
//!
//! Protected routes resolve one Authorization bearer and retain it for downstream
//! RPCs. Search uses canonical VFS paths; the gRPC host enforces zone and file
//! access, including cached results. Production composition shares the daemon's
//! auth provider, Raft tuple store, TLS channels, and data-plane readiness gate.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::middleware::from_fn_with_state;
use axum::Router;
use tokio::net::TcpListener;
use transport::auth::AuthProvider;

pub mod backends;
pub mod handlers;
pub mod middleware;
pub mod revision;
pub mod search_backend;
pub mod zone;

/// Client stubs for the workspace's `nexus.search.v1` proto SSOT
/// — generated at build time by `build.rs` from
/// `rust/services/proto/nexus/search/v1/search.proto`.  Client-only
/// (this crate never implements the service).
pub mod search_proto {
    #![allow(clippy::all)]
    #![allow(unused_qualifications)]
    tonic::include_proto!("nexus.search.v1");
}

pub use handlers::status::StatusResponse;
pub use search_backend::{BackendError, SearchBackend};

/// Concrete federated dispatcher this crate wires into
/// [`AppState::federated`] under `--features rebac`.
///
/// The generic parameter is fixed:
/// [`crate::backends::plugin_local::PluginLocalSearchBackend`] +
/// [`crate::backends::tonic_remote::TonicRemoteSearchBackend`] behind
/// [`nexus_federated_search::RoutingBackend`].  A zone the caller
/// can read from routes local unless the
/// [`nexus_search_common::ZoneSearchRegistry`] hands the router a
/// per-zone remote target — in which case
/// [`crate::backends::tonic_remote::TonicRemoteSearchBackend`] dials
/// the peer daemon over tonic with a [`nexus_search_common::SearchDelegation`]
/// stamped onto request metadata.  A composition root that keeps the
/// registry empty (single-daemon deployment) never touches the
/// remote path.
#[cfg(feature = "rebac")]
pub type DefaultFederatedDispatcher = nexus_federated_search::FederatedSearchDispatcher<
    nexus_federated_search::RoutingBackend<
        crate::backends::plugin_local::PluginLocalSearchBackend,
        crate::backends::tonic_remote::TonicRemoteSearchBackend,
    >,
>;

/// Shared state handed to every axum handler through
/// `axum::extract::State`.  Cheap to clone (`Arc` fields inside
/// each backend); one instance per process.
///
/// # `auth`
///
/// The `AuthProvider` used by [`middleware::auth::require_bearer`]
/// to resolve incoming bearer tokens.  Trait-object so a single
/// binary can pick `NoAuth` for dev, `ApiKeyAuthProvider` for
/// production, or a test double.  See
/// [`middleware::auth::default_no_auth_provider`] for the
/// single-node default.
#[derive(Clone)]
pub struct AppState {
    /// Shared daemon bootstrap gate; authentication and management wait for it.
    pub ready: Arc<transport::grpc::DataPlaneReady>,
    pub search: SearchBackend,
    pub auth: Arc<dyn AuthProvider>,
    /// The kernel-adjacent `AuthKeyStore` — list / revoke backend
    /// for `/v2/auth/keys`.  Threaded from the same
    /// `RaftAuthKeyStore` the kernel's gRPC bearer-auth path reads
    /// (via `kernel.auth_key_store()` at install time).  One SSOT,
    /// two surfaces (gRPC + HTTP).
    pub auth_key_store: Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    /// The daemon's HMAC secret for sk- key material — `Some(_)`
    /// under API-key auth, `None` under `--no-tls` (mint returns
    /// 503).  Threaded from `ServiceBootCtx.api_key_secret` (the
    /// same secret `DaemonKeyMinter` uses on the gRPC side) so the
    /// HTTP mint plane hashes with the identical secret.  Never
    /// exposed in logs / Debug output — the mint layer's own
    /// `auth::mint::mint_key` takes it as `&str` and consumes it
    /// only for HMAC.
    pub api_key_secret: Option<Arc<str>>,
    /// Read-your-writes fence backend (Issue #4737).  Any object that
    /// can report `sys_stat(path).gen` — the middleware polls this to
    /// decide when a fenced read can proceed.  In production the
    /// install closure passes the live `Arc<Kernel>` (which impls
    /// `KernelSyscall` and therefore `StatGen` via the blanket impl
    /// in `middleware/revision.rs`); tests can pass any `StatGen`
    /// (see `for_tests` — a `ZeroGenKernel` that returns 0, so a
    /// fenced request just 412s).
    pub kernel: Arc<dyn middleware::revision::StatGen>,
    /// The kernel-adjacent ReBAC tuple store — grant / list / revoke
    /// backend for `/v2/rebac/tuples`.  Present iff this crate was
    /// built `--features rebac`; the composition root in `nexusd`
    /// (also under `--features rebac`) passes the same
    /// `RaftReBACTupleStore` the kernel's `PermissionProvider`
    /// reads, so grants written via HTTP take effect on the next
    /// permission check without a second SSOT.
    #[cfg(feature = "rebac")]
    pub rebac_store: Arc<dyn nexus_rebac::ReBACTupleStore>,
    /// Cross-zone search dispatcher — fans a `/v2/search/query` out
    /// to every zone the caller can read from, fuses per-zone hits
    /// via RRF (`nexus-federated-search`).  Wired only under
    /// `--features rebac` because zone discovery reads ReBAC tuples;
    /// a non-rebac build has no way to compute the readable zone set
    /// and takes the single-zone fast path instead.
    ///
    /// The `/v2/search/query` handler decides whether to dispatch
    /// federated by checking the caller's accessible zone count: 0
    /// or 1 zone ⇒ single-zone path (unchanged); >1 zone ⇒ dispatch
    /// through here for fanout + fusion.  Single-zone callers pay
    /// nothing extra.
    #[cfg(feature = "rebac")]
    pub federated: Arc<DefaultFederatedDispatcher>,
    /// The per-subject "which zones can this caller read from"
    /// TTL cache the federated dispatcher's zone discovery uses.
    /// Shared with the `/v2/search/query` handler so the "should
    /// I federate?" precheck and the actual dispatch pull from the
    /// same cache — one round-trip to ReBAC per (subject, TTL)
    /// window regardless of whether the request federates.
    #[cfg(feature = "rebac")]
    pub accessible_zones: Arc<nexus_rebac::list_zones::AccessibleZonesCache>,
}

impl AppState {
    /// Convenience constructor for tests / probes that need a fully-
    /// wired [`AppState`] but do not care about the exact backend
    /// target or auth policy.  Wires the search backend at
    /// `grpc_target` (dial-on-first-use — never dialed if the test
    /// does not hit a search route) and the default `NoAuth`
    /// provider so bearer parsing / rejection can be tested
    /// separately.  Cheap: both fields are just `Arc` allocations.
    ///
    /// Not for production — the composition root in `nexusd` builds
    /// the same struct field-by-field with the real `SearchBackend`
    /// target + `ApiKeyAuthProvider`.
    ///
    /// Under `--features rebac`, wires an in-memory store so rebac
    /// route tests can exercise grant / list / revoke without a
    /// live raft cluster.
    pub fn for_tests(grpc_target: impl Into<Arc<str>>) -> Self {
        let grpc_target: Arc<str> = grpc_target.into();
        let search = SearchBackend::new(Arc::clone(&grpc_target));
        #[cfg(feature = "rebac")]
        let rebac_store: Arc<dyn nexus_rebac::ReBACTupleStore> =
            Arc::new(nexus_rebac::InMemoryReBACTupleStore::new());
        #[cfg(feature = "rebac")]
        let accessible_zones = Arc::new(nexus_rebac::list_zones::AccessibleZonesCache::new());
        #[cfg(feature = "rebac")]
        let federated = {
            use nexus_federated_search::{
                DispatcherConfig, FederatedSearchDispatcher, RoutingBackend,
            };
            use nexus_search_common::InMemoryZoneSearchRegistry;
            let local = Arc::new(
                crate::backends::plugin_local::PluginLocalSearchBackend::new(search.clone()),
            );
            // Real tonic-remote backend backed by a fresh
            // `PeerChannelCache`.  Never dialed under `for_tests`
            // because the registry below is empty — every zone
            // routes local via `RoutingBackend`.  Wired here so a
            // test that populates the registry gets end-to-end
            // remote dispatch without swapping the backend type.
            let peer_cache = Arc::clone(&search.channels);
            let remote =
                Arc::new(crate::backends::tonic_remote::TonicRemoteSearchBackend::new(peer_cache));
            // Empty registry — every zone falls through to the local
            // backend.  Real deployments populate this from a
            // per-zone plugin-target env var (see the composition
            // root in `nexusd`).
            let registry: Arc<nexus_search_common::InMemoryZoneSearchRegistry> =
                Arc::new(InMemoryZoneSearchRegistry::new());
            let routing = RoutingBackend::new(
                local,
                remote,
                Arc::clone(&registry) as Arc<dyn nexus_search_common::ZoneSearchRegistry>,
                // Test daemon self-id.  Real deployments read this
                // from identity.json.
                "test",
                // The plugin target itself is "local" so a registry
                // that pointed a zone at ourselves stays local.
                std::iter::once(grpc_target.as_ref().to_string()),
            );
            Arc::new(FederatedSearchDispatcher::new(
                Arc::new(routing),
                Arc::clone(&rebac_store),
                // Share ONE cache with the AppState field so the
                // handler's "should I federate?" precheck and the
                // dispatch itself both hit the same warm entry — one
                // ReBAC round-trip per (subject, TTL) window.
                Arc::clone(&accessible_zones),
                registry,
                DispatcherConfig::default(),
            ))
        };
        Self {
            ready: transport::grpc::DataPlaneReady::open(),
            search,
            auth: middleware::auth::default_no_auth_provider(),
            // Empty in-memory store for `/v2/auth/keys` tests.  The
            // real composition root pulls the raft-backed store from
            // `kernel.auth_key_store()` at install time.
            auth_key_store: Arc::new(middleware::auth::empty_auth_key_store_for_tests()),
            // No secret by default — mint tests set it explicitly.
            api_key_secret: None,
            // Zero-gen kernel — a fence probe would just time out at
            // 412, which is what a revision fence unit test wants.
            // Real deployments pull the live kernel from the install
            // closure (see `service_decl`).
            kernel: Arc::new(middleware::revision::ZeroGenKernel),
            #[cfg(feature = "rebac")]
            rebac_store,
            #[cfg(feature = "rebac")]
            federated,
            #[cfg(feature = "rebac")]
            accessible_zones,
        }
    }
}

/// Root [`Router`] carrying every configured route domain.  Callers
/// supply the [`AppState`] (which owns the upstream client caches)
/// so the same crate can be exercised in tests against a mock
/// backend and in production against the real search-plugin.
///
/// # Layering
///
/// The router splits into two sub-routers by auth posture:
///
/// * `public_router` — routes callable BEFORE a bearer exists
///   (liveness probes, unauth-metadata endpoints).  Currently just
///   `/v2/status`.
/// * `protected_router` — routes wrapped by
///   [`middleware::auth::require_bearer`].  Every `/v2/search/*` +
///   `/v2/documents/*` handler lives here.
///
/// Both sub-routers share the same [`AppState`]; only the middleware
/// stack differs.  A new domain lands as an additive merge on
/// whichever sub-router matches its auth posture — handlers stay
/// unaware of the split beyond optionally extracting
/// `Extension<OperationContext>`.
pub fn router(state: AppState) -> Router {
    let public_router = Router::new()
        .merge(handlers::status::router())
        .with_state(state.clone());
    let protected_router = {
        let r = Router::new()
            .merge(handlers::search::router())
            .merge(handlers::documents::router())
            .merge(handlers::auth::router());
        #[cfg(feature = "rebac")]
        let r = r.merge(handlers::rebac::router());
        r.layer(from_fn_with_state(
            state.clone(),
            middleware::auth::require_bearer,
        ))
        .with_state(state)
    };
    Router::new().merge(public_router).merge(protected_router)
}

/// Bind `addr` and serve [`router(state)`](router) until the returned
/// future completes.  Convenience wrapper over
/// [`axum::serve`] + [`tokio::net::TcpListener::bind`] so callers
/// (integration tests and the `nexusd-cluster` assembly
/// binary) do not each re-implement the two-line startup dance.
///
/// Returns the [`SocketAddr`] actually bound so callers who pass
/// `127.0.0.1:0` can learn the OS-picked port.  A shutdown hook is
/// deliberately absent from this signature — tests drop the future
/// when the runtime tears down, and the production binary wires
/// its own graceful-shutdown signal on top of the raw future via
/// [`axum::serve::Serve::with_graceful_shutdown`].
pub async fn serve(addr: SocketAddr, state: AppState) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await
}

/// Same shape as [`serve`] but binds ahead of time so the caller
/// can read `local_addr()` (the OS-picked port when `addr.port() == 0`)
/// before the serve future starts.  Convenience for tests + any
/// production caller that needs to log the bound port before the
/// event loop runs.
pub async fn bind_and_serve(
    addr: SocketAddr,
    state: AppState,
) -> io::Result<(
    SocketAddr,
    impl std::future::Future<Output = io::Result<()>>,
)> {
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let fut = async move { axum::serve(listener, router(state)).await };
    Ok((bound, fut))
}

/// Declare the HTTP listener with the daemon's shared credential store,
/// authorization store, transport, and bootstrap gate. Bind errors fail boot.
pub fn service_decl(
    addr: SocketAddr,
    search: SearchBackend,
    auth: Arc<dyn AuthProvider>,
    runtime: tokio::runtime::Handle,
    api_key_secret: Option<Arc<str>>,
    #[cfg(feature = "rebac")] rebac_store: Arc<dyn nexus_rebac::ReBACTupleStore>,
    ready: Arc<transport::grpc::DataPlaneReady>,
) -> kernel::kernel::ServiceDecl {
    kernel::kernel::ServiceDecl {
        name: "http_api".to_string(),
        install: Box::new(move |kernel| {
            let auth_key_store = kernel.auth_key_store();
            let stat_kernel: Arc<dyn middleware::revision::StatGen> = {
                let k: Arc<kernel::kernel::Kernel> = Arc::clone(kernel);
                k
            };
            install_impl(
                addr,
                search,
                auth,
                runtime,
                auth_key_store,
                api_key_secret,
                stat_kernel,
                #[cfg(feature = "rebac")]
                rebac_store,
                ready,
            )
        }),
    }
}

/// The install-closure body extracted as a plain fn so it is
/// callable from a test WITHOUT constructing a real `Arc<Kernel>`
/// (a full `Kernel` needs a metastore + backends + observers —
/// heavy for a bind-only regression pin).
///
/// Marked `pub` (not `pub(crate)`) purely so the integration test
/// `tests/serve_e2e.rs` — a separate compilation unit — can drive
/// it under a real tokio runtime.  Production callers should use
/// [`service_decl`], not this fn directly; a `#[doc(hidden)]`
/// annotation keeps it out of the rustdoc surface.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn install_impl(
    addr: SocketAddr,
    search: SearchBackend,
    auth: Arc<dyn AuthProvider>,
    runtime: tokio::runtime::Handle,
    auth_key_store: Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    api_key_secret: Option<Arc<str>>,
    kernel: Arc<dyn middleware::revision::StatGen>,
    #[cfg(feature = "rebac")] rebac_store: Arc<dyn nexus_rebac::ReBACTupleStore>,
    ready: Arc<transport::grpc::DataPlaneReady>,
) -> Result<(), String> {
    #[cfg(feature = "rebac")]
    let accessible_zones = Arc::new(nexus_rebac::list_zones::AccessibleZonesCache::new());
    #[cfg(feature = "rebac")]
    let federated = {
        use nexus_federated_search::{DispatcherConfig, FederatedSearchDispatcher, RoutingBackend};
        use nexus_search_common::InMemoryZoneSearchRegistry;
        let local =
            Arc::new(crate::backends::plugin_local::PluginLocalSearchBackend::new(search.clone()));
        // Local and remote legs share the configured TLS identity and channels.
        let peer_cache = Arc::clone(&search.channels);
        let remote =
            Arc::new(crate::backends::tonic_remote::TonicRemoteSearchBackend::new(peer_cache));
        // Env-driven registry — the ONE knob for cross-daemon
        // dispatch.  Empty env → empty registry → every zone
        // routes local (single-daemon deployment, default).  A
        // populated `NEXUS_SEARCH_REMOTE_ZONE_TARGETS=zone1=url1,...`
        // unlocks per-zone remote dial.  Malformed entries fail
        // LOUD here so a typo is a boot-time error instead of a
        // silently-empty registry (standing rule: fail loud on
        // partial config).
        let registry: Arc<InMemoryZoneSearchRegistry> = Arc::new(
            crate::backends::registry_config::registry_from_env()
                .map_err(|e| format!("nexus-http-api: NEXUS_SEARCH_REMOTE_ZONE_TARGETS: {e}"))?,
        );
        let routing = RoutingBackend::new(
            local,
            remote,
            Arc::clone(&registry) as Arc<dyn nexus_search_common::ZoneSearchRegistry>,
            // The ingress control plane belongs to the root namespace.
            contracts::ROOT_ZONE_ID,
            std::iter::empty::<String>(),
        );
        Arc::new(FederatedSearchDispatcher::new(
            Arc::new(routing),
            Arc::clone(&rebac_store),
            Arc::clone(&accessible_zones),
            registry,
            DispatcherConfig::default(),
        ))
    };
    let state = AppState {
        ready,
        search,
        auth,
        auth_key_store,
        api_key_secret,
        kernel,
        #[cfg(feature = "rebac")]
        rebac_store,
        #[cfg(feature = "rebac")]
        federated,
        #[cfg(feature = "rebac")]
        accessible_zones,
    };
    // Bind synchronously so address errors fail service installation. Convert
    // the listener on the active runtime without entering a nested runtime.
    let std_listener = std::net::TcpListener::bind(addr)
        .map_err(|e| format!("nexus-http-api: bind {addr}: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("nexus-http-api: set_nonblocking after bind: {e}"))?;
    let listener = TcpListener::from_std(std_listener)
        .map_err(|e| format!("nexus-http-api: from_std after bind: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("nexus-http-api: local_addr after bind: {e}"))?;
    tracing::info!(addr = %bound, "nexus-http-api: axum listener bound");
    // Detach the serve loop — the listener has a life of
    // its own from here, running until the daemon shuts down.
    runtime.spawn(async move {
        if let Err(e) = axum::serve(listener, router(state)).await {
            tracing::error!(
                addr = %bound,
                error = %e,
                "nexus-http-api: axum serve loop terminated",
            );
        }
    });
    Ok(())
}
