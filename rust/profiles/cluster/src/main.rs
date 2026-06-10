//! Nexus cluster-profile runtime — `nexusd-cluster`.
//!
//! A self-contained ~5 MB Rust binary that brings up:
//!   * [`nexus_raft::ZoneManager`] (multi-zone Raft + gRPC server)
//!   * Day-1 TLS bootstrap (CA + node cert + join token) on first start
//!   * Static topology (`NEXUS_FEDERATION_ZONES` + `NEXUS_FEDERATION_MOUNTS`)
//!   * Health-check loop that drives `apply_topology` to convergence
//!
//! Subcommands:
//!   * `nexusd-cluster`             — start the daemon (default)
//!   * `nexusd-cluster share`       — detach a local subtree into a new zone
//!   * `nexusd-cluster join`        — mount a remote zone locally
//!
//! `share` / `join` open the data directory directly — they must run
//! while the daemon is stopped (redb holds an exclusive file lock).
//! Sudowork's primary deployment path is the static topology env vars
//! consumed at daemon startup; share/join are operator escape hatches.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use backends::provider::DefaultObjectStoreProvider;
use backends::storage::path_local::PathLocalBackend;
use clap::{Parser, Subcommand};
use kernel::abc::object_store::ObjectStore;
use kernel::hal::object_store_provider::set_provider;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::Kernel;

use nexus_raft::distributed_coordinator::{
    bootstrap_or_join_zone, read_or_mint_node_id, validate_bootstrap_mode,
    validate_peers_excludes_self, BootstrapMode,
};
use nexus_raft::federation::{parse_federation_env, ENV_FEDERATION_MOUNTS, ENV_FEDERATION_ZONES};
use nexus_raft::transport::{bootstrap_tls, NodeAddress};
use nexus_raft::{TlsFiles, ZoneManager};

const DEFAULT_BIND: &str = "0.0.0.0:2126";
const TOPOLOGY_TICK: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
#[command(
    name = "nexusd-cluster",
    version,
    about = "Nexus cluster-profile daemon (pure Rust runtime)",
    long_about = None,
)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, clap::Args)]
struct CommonArgs {
    /// This node's hostname. Falls back to NEXUS_HOSTNAME, then OS hostname.
    #[arg(long, env = "NEXUS_HOSTNAME", global = true)]
    hostname: Option<String>,

    /// Bind address for the federation gRPC server.
    #[arg(long, env = "NEXUS_BIND_ADDR", default_value = DEFAULT_BIND, global = true)]
    bind_addr: String,

    /// Persistent data directory (TLS bundle + per-zone redb files).
    #[arg(
        long,
        env = "NEXUS_DATA_DIR",
        default_value = "./nexus-cluster-data",
        global = true
    )]
    data_dir: PathBuf,

    /// Comma-separated raft peers in `id@host:port` form.
    #[arg(long, env = "NEXUS_PEERS", default_value = "", global = true)]
    peers: String,

    /// Disable TLS — plaintext gRPC for local testing only.
    #[arg(long, env = "NEXUS_NO_TLS", default_value_t = false, global = true)]
    no_tls: bool,

    /// Host filesystem directory exposed as the cluster root mount.
    /// `nexusd-cluster` mounts this path at `/` via `PathLocalBackend`
    /// at boot so gRPC writes through DLC land on the host fs.
    /// Defaults to `<data_dir>/root` for self-contained operation.
    #[arg(long, env = "NEXUS_ROOT_FS", global = true)]
    root_path: Option<PathBuf>,

    /// Directory of plugin dylibs to auto-load at startup.
    /// All `.so` / `.dylib` files in this directory are loaded via
    /// `Kernel::load_plugin_dir` after the kernel is created.
    #[arg(long, env = "NEXUS_PLUGIN_DIR", global = true)]
    plugin_dir: Option<PathBuf>,

    /// Mount a driver plugin into the VFS at startup.  Repeatable.
    ///
    /// Syntax: `<plugin-name>:<zone-id>:<vfs-path>:<config-json>`
    ///
    /// Example (single-node, root zone):
    /// `--mount-driver local-connector:root:/tasks:{"local_root":"/home/me/.claude/tasks"}`
    ///
    /// Example (separate zone):
    /// `--mount-driver local-connector:my-docs:/files:{"local_root":"/home/me/docs"}`
    ///
    /// The plugin must already be loaded (drop its `.so` into
    /// `--plugin-dir` first).  `<vfs-path>` may live in any zone the
    /// operator chooses (root for node-local single-canonical
    /// routing, a separate raft zone when federation extends the
    /// mount); `<config-json>` is passed verbatim to
    /// `nexus_driver_create` and may contain its own colons (the
    /// 4-part split is left-anchored to the first three `:`).
    ///
    /// `<vfs-path>` must not be `/`.  The boot-time
    /// `PathLocalBackend` already owns that mount point, and
    /// `Kernel::add_mount`'s `rebind_missing_backends` branch keys
    /// on `(zone="root", mount_point="/")` — replacing that mount
    /// silently re-points every backend-less federation child mount
    /// at the operator's driver.
    ///
    /// Loaded-but-not-mounted is a no-op: `--plugin-dir` registers
    /// the dylib's name but does not mutate the VFS topology.  Only
    /// `--mount-driver` flips a driver into the routing table.
    #[arg(
        long = "mount-driver",
        value_name = "NAME:ZONE:PATH:CONFIG",
        global = true
    )]
    mount_drivers: Vec<String>,

    /// Bootstrap mode declaration — `static`, `dynamic`, or `restart`.
    ///
    /// Operator must declare intent at startup so the daemon does not
    /// silently mix scenarios.  See `BootstrapMode` in `nexus_raft`
    /// for the full contract.  Required for the daemon mode (no
    /// subcommand) — share/join/mount/unmount subcommands skip the
    /// validator since they always operate on existing state.
    #[arg(long, env = "NEXUS_BOOTSTRAP_MODE", global = true)]
    bootstrap_mode: Option<String>,
}

/// Parsed `--mount-driver` argument.
///
/// 4-part syntax: `name:zone:vfs-path:config-json`.  The first three
/// `:` separators are fixed positions; everything after the third `:`
/// is the JSON config so embedded `:` in values (which JSON object
/// syntax always contains) survives the split.
///
/// `vfs-path` must not be the root path `/`.  The boot-time
/// `PathLocalBackend` already owns that mount point, and
/// `Kernel::add_mount`'s `rebind_missing_backends` branch keys
/// specifically on `(zone="root", mount_point="/")` — overwriting
/// that mount silently re-points every backend-less federation child
/// mount at the operator's driver.  Any non-root path is fine;
/// `zone` is operator-supplied with no kernel-imposed constraint
/// (root is the common single-node case, a separate raft zone is the
/// federated case).
#[derive(Debug, Clone)]
struct MountDriverSpec {
    name: String,
    zone_id: String,
    vfs_path: String,
    config_json: String,
}

fn parse_mount_driver_spec(raw: &str) -> Result<MountDriverSpec, String> {
    let mut parts = raw.splitn(4, ':');
    let name = parts
        .next()
        .ok_or_else(|| format!("--mount-driver: missing name in '{raw}'"))?
        .trim();
    let zone_id = parts
        .next()
        .ok_or_else(|| format!("--mount-driver: missing zone in '{raw}'"))?
        .trim();
    let vfs_path = parts
        .next()
        .ok_or_else(|| format!("--mount-driver: missing vfs-path in '{raw}'"))?
        .trim();
    let config_json = parts
        .next()
        .ok_or_else(|| format!("--mount-driver: missing config-json in '{raw}'"))?
        .trim();
    if name.is_empty() || zone_id.is_empty() || vfs_path.is_empty() || config_json.is_empty() {
        return Err(format!(
            "--mount-driver: name / zone / vfs-path / config-json must all be non-empty in '{raw}'"
        ));
    }
    if !vfs_path.starts_with('/') {
        return Err(format!(
            "--mount-driver: vfs-path must start with '/' in '{raw}' (got '{vfs_path}')"
        ));
    }
    if vfs_path == "/" {
        return Err(
            "--mount-driver: vfs-path '/' is reserved for the boot-time \
             PathLocalBackend mount.  Operator-defined driver mounts must \
             use a non-root path (e.g. '/tasks', '/external/blobs')."
                .to_string(),
        );
    }
    Ok(MountDriverSpec {
        name: name.to_string(),
        zone_id: zone_id.to_string(),
        vfs_path: vfs_path.to_string(),
        config_json: config_json.to_string(),
    })
}

impl CommonArgs {
    fn root_fs_path(&self) -> PathBuf {
        self.root_path
            .clone()
            .unwrap_or_else(|| self.data_dir.join("root"))
    }
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Detach a local subtree into a new federation zone.
    ///
    /// The subtree under `<path>` (in the parent zone) is copied into a
    /// new raft group identified by `--zone-id`, with paths rebased so
    /// that what was at `<parent>/<path>/foo` becomes `/foo` inside the
    /// new zone. After share, peers can join the new zone via
    /// `nexusd-cluster join`.
    ///
    /// Pass `--mount-at <path>` to also write a DT_MOUNT entry in the
    /// parent zone's metastore that routes that path to the new zone.
    /// The mount entry is raft-replicated, so every member of the parent
    /// zone (including future joiners) sees the same mount automatically
    /// — symmetric to what `join` does on the joiner side. Without
    /// `--mount-at` the new zone exists as a raft group but the sharer's
    /// own writes to `<path>` keep routing to the original (local)
    /// mount, which is the historical pitfall.
    Share {
        /// Subtree path in the parent zone (e.g. `/data/shared`).
        path: String,
        /// Zone id for the new federation zone.
        #[arg(long)]
        zone_id: String,
        /// Parent zone id; defaults to root.
        #[arg(long, default_value = "root")]
        parent_zone: String,
        /// Optional VFS path to mount the new zone at on this node (the
        /// sharer). Writes a DT_MOUNT entry via the parent zone's raft
        /// state machine, so the mount is visible on every member of
        /// the parent zone. Idempotent.
        #[arg(long)]
        mount_at: Option<String>,
    },
    /// Per-zone health audit of a stopped daemon's data directory.
    ///
    /// Reads each zone's persisted RaftState (ConfState + HardState)
    /// and last log index directly from disk, then prints a one-screen
    /// summary plus per-zone alarms for the failure modes that have
    /// historically wedged operators (e.g. half-installed state after
    /// a crashed `nexusd-cluster join`).  Read-only — but redb requires
    /// exclusive access, so the daemon must be stopped first.
    ///
    /// Typical use:
    ///   pkill -f nexusd-cluster
    ///   nexusd-cluster doctor --data-dir /tmp/nexus-fed-data
    Doctor {
        /// Path to the daemon's data directory (the one passed to
        /// `--data-dir` at boot).  The doctor walks its subdirectories
        /// looking for zones (presence of `<zone>/raft/raft.redb`).
        #[arg(long)]
        data_dir: PathBuf,
        /// Restrict the audit to a single zone id — defaults to all
        /// zones found on disk.
        #[arg(long)]
        zone: Option<String>,
    },
    /// Mount a remote zone at a local path.
    ///
    /// Joins `<remote_zone_id>` (must already exist on `<peer_addr>`),
    /// then writes a DT_MOUNT entry under `<parent_zone>` so syscalls
    /// at `<local_path>` route into the remote zone.
    Join {
        /// Remote peer in `id@host:port` form (e.g. `2@nexus-2:2126`).
        peer_addr: String,
        /// Zone id to join on the remote side.
        remote_zone_id: String,
        /// Local path to mount the remote zone at.
        local_path: String,
        /// Parent zone for the mount entry; defaults to root.
        #[arg(long, default_value = "root")]
        parent_zone: String,
    },
}

fn main() -> Result<()> {
    // Held until `main` returns so the non-blocking log writer thread stays
    // alive and flushes on shutdown.
    let _tracing_guard = install_tracing();
    let args = Args::parse();
    // Size the multi-thread runtime against the host: federation
    // gRPC + raft IO is IO-bound, so the kernel `available_parallelism`
    // estimate (logical cores under cgroup / affinity constraints) is
    // the right target. Falls back to 2 — the previous hard-coded
    // worker count — when the platform can't report a value (e.g.
    // bare-metal probes that aren't WASI-style sandboxed but lack
    // `_SC_NPROCESSORS_ONLN`).
    let workers = contracts::recommended_worker_threads(2);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .thread_name("nexusd-cluster")
        .build()
        .context("build tokio runtime")?
        .block_on(async move {
            match args.cmd {
                None => run_daemon(args.common).await,
                Some(Cmd::Share {
                    path,
                    zone_id,
                    parent_zone,
                    mount_at,
                }) => {
                    run_share(
                        args.common,
                        &parent_zone,
                        &path,
                        &zone_id,
                        mount_at.as_deref(),
                    )
                    .await
                }
                Some(Cmd::Doctor { data_dir, zone }) => run_doctor(&data_dir, zone.as_deref()),
                Some(Cmd::Join {
                    peer_addr,
                    remote_zone_id,
                    local_path,
                    parent_zone,
                }) => {
                    run_join(
                        args.common,
                        &peer_addr,
                        &remote_zone_id,
                        &local_path,
                        &parent_zone,
                    )
                    .await
                }
            }
        })
}

/// Bundle returned by [`open_zone_manager`].  Carries the opaque
/// `node_id` minted/loaded from `<data_dir>/.node_id` plus the
/// structured peer address book and self-address derived from
/// `--bind-addr`/`--hostname`.  `run_daemon` hands the lot to
/// [`bootstrap_or_join_zone`] which owns the actual root-zone
/// dispatch.
struct ZoneManagerBundle {
    zm: std::sync::Arc<ZoneManager>,
    node_id: u64,
    self_address: String,
    peer_addrs: Vec<NodeAddress>,
}

/// Open a `ZoneManager` against the data dir, sharing the daemon's
/// startup conventions. Used by both `daemon` and the offline
/// `share`/`join` subcommands.
///
/// Node identity is read from (or minted into) `<data_dir>/.node_id`
/// via [`read_or_mint_node_id`] — the same SSOT Python `nexusd` uses.
/// Decoupling node_id from hostname is the PR #3996 contract: a
/// wiped-and-rejoined node's fresh random ID has
/// `Progress[new_id].matched=0` from the moment AddNode commits, so
/// heartbeats with `m.commit=0` cannot trip raft-rs 0.7's
/// `commit_to`'s stale-`Progress` panic.
fn open_zone_manager(
    common: &CommonArgs,
    extra_grpc_services: Option<tonic::service::Routes>,
) -> Result<ZoneManagerBundle> {
    std::fs::create_dir_all(&common.data_dir)
        .with_context(|| format!("create data dir {}", common.data_dir.display()))?;

    let hostname = resolve_hostname(common.hostname.as_deref());
    let zones_dir = common
        .data_dir
        .to_str()
        .context("data_dir must be UTF-8")?
        .to_string();

    // Opaque random `node_id` per first boot, persisted to
    // `<data_dir>/.node_id`.  Restart loads the persisted value;
    // wipe-rejoin mints a fresh ID (see fn doc).
    let node_id = read_or_mint_node_id(&zones_dir)
        .map_err(|e| anyhow::anyhow!("read_or_mint_node_id: {}", e))?;

    let use_tls = !common.no_tls;
    let tls = if !use_tls {
        tracing::warn!("TLS disabled (--no-tls / NEXUS_NO_TLS); plaintext gRPC");
        None
    } else {
        let bundle = bootstrap_tls(
            &common.data_dir,
            contracts::ROOT_ZONE_ID,
            &hostname,
            node_id,
        )
        .map_err(|e| anyhow::anyhow!("TLS bootstrap failed: {}", e))?;
        Some(TlsFiles {
            cert_path: bundle.node_cert_path,
            key_path: bundle.node_key_path,
            ca_path: bundle.ca_path.clone(),
            ca_key_path: Some(bundle.ca_key_path),
            join_token_hash: Some(bundle.join_token_hash),
        })
    };

    // Parse `--peers` into structured `NodeAddress` entries — address
    // book only.  ZoneManager seeds its transport peer map from this;
    // ConfState is independent (mutated only by ConfChange via
    // JoinZone driven by `bootstrap_or_join_zone`).
    let peer_addrs: Vec<NodeAddress> = NodeAddress::parse_peer_list(&common.peers, use_tls)
        .map_err(|e| anyhow::anyhow!("--peers/NEXUS_PEERS parse: {}", e))?;
    let peers_str: Vec<String> = peer_addrs
        .iter()
        .map(NodeAddress::to_raft_peer_str)
        .collect();

    // Advertise address — used as `StepMessage.sender_address` so the
    // peer-map runtime SSOT can learn this node's reachable endpoint.
    // Default: `<hostname>:<bind_port>`.
    let bind_port = common
        .bind_addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(2126);
    let self_address = format!("{hostname}:{bind_port}");

    // Reject "self listed in --peers" early — see
    // `validate_peers_excludes_self` for why this is a hard error
    // under the PR #3996 opaque-ID contract.
    validate_peers_excludes_self(&peer_addrs, &self_address)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let zm = ZoneManager::with_node_id(
        &hostname,
        node_id,
        &zones_dir,
        peers_str,
        &common.bind_addr,
        tls,
        Some(self_address.clone()),
        extra_grpc_services,
    )
    .map_err(|e| anyhow::anyhow!("ZoneManager::with_node_id: {}", e))?;

    Ok(ZoneManagerBundle {
        zm,
        node_id,
        self_address,
        peer_addrs,
    })
}

async fn run_daemon(common: CommonArgs) -> Result<()> {
    let hostname = resolve_hostname(common.hostname.as_deref());
    tracing::info!(
        hostname = %hostname,
        bind = %common.bind_addr,
        data_dir = %common.data_dir.display(),
        "nexusd-cluster starting (daemon mode)",
    );

    let bootstrap_new = std::env::var("NEXUS_BOOTSTRAP_NEW")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false);

    let peers_non_empty = common.peers.split(',').any(|s| !s.trim().is_empty());

    // `<data_dir>/root/raft/` — caller-side check the validator
    // uses to detect "this is actually a restart, not a fresh
    // bootstrap".  Cheap filesystem stat.
    let data_dir_has_root = common.data_dir.join("root").join("raft").exists();

    // Operator MUST declare bootstrap intent.  No implicit dispatch:
    // explicit mode declaration is the SSOT for what kind of boot
    // this is (static = env-driven cluster formation, dynamic =
    // rootless + runtime API, restart = resume from disk).
    let mode_str = common.bootstrap_mode.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "--bootstrap-mode (or NEXUS_BOOTSTRAP_MODE) is required.  Pass one of: \
             static, dynamic, restart.  See BootstrapMode docs in nexus_raft.",
        )
    })?;
    let mode = BootstrapMode::parse(mode_str).map_err(|e| anyhow::anyhow!("{}", e))?;
    validate_bootstrap_mode(mode, data_dir_has_root, bootstrap_new, peers_non_empty)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    tracing::info!(
        mode = mode.as_str(),
        bootstrap_new,
        peers_non_empty,
        data_dir_has_root,
        "bootstrap mode validated",
    );

    // ── ObjectStoreProvider ─────────────────────────────────────────
    // Registered before the first DT_MOUNT so that any mount going
    // through the provider (bridge-2, #4262) can call get_provider()
    // at construction time. Cargo features control which backend arms
    // compile into the provider — no runtime gate needed.
    set_provider(Arc::new(DefaultObjectStoreProvider))
        .unwrap_or_else(|_| tracing::warn!("ObjectStoreProvider already registered"));

    // ── Data plane: mount host-fs at "/" via PathLocalBackend ──
    // Created BEFORE ZoneManager so the VFS gRPC service can be
    // co-hosted on the same port as the raft gRPC server.
    let kernel = Arc::new(Kernel::new());

    // ── Durable metastore (#4343) ─────────────────────────────────
    // `Kernel::new()` boots on a tempfile-backed `LocalMetaStore` —
    // fine for tests and benches, fatal for a server: the namespace
    // (the inode SSOT) drops with the process, so every restart made
    // all previously-registered files invisible while their payload
    // bytes stayed on disk. Swap in a redb inside the data dir BEFORE
    // the first mount so the DT_MOUNT entry lands in the durable
    // store too.
    //
    // The override env is deliberately `NEXUS_KERNEL_METASTORE_PATH`
    // (the `NEXUS_KERNEL_*` namespace, like `NEXUS_KERNEL_BINARY`),
    // NOT `NEXUS_METASTORE_PATH`: the Python server sets the latter
    // for its own legacy metadata path and copies its env into this
    // subprocess — reusing it here would point the kernel at the
    // Python-era redb file instead of this node's own store.
    if let Some(ms_path) = resolve_metastore_path(
        std::env::var("NEXUS_KERNEL_METASTORE_PATH").ok().as_deref(),
        &common.data_dir,
    ) {
        if let Some(parent) = ms_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create metastore dir {}", parent.display()))?;
        }
        let ms_str = ms_path.to_str().context("metastore path must be UTF-8")?;
        kernel.set_metastore_path(ms_str).map_err(|e| {
            anyhow::anyhow!("open durable metastore at {}: {:?}", ms_path.display(), e)
        })?;
        tracing::info!(path = %ms_path.display(), "durable metastore opened (namespace survives restarts)");
    } else {
        tracing::warn!(
            "NEXUS_KERNEL_METASTORE_PATH=\"\" — ephemeral tempfile metastore; \
             the namespace will NOT survive a restart"
        );
    }
    let root_fs = common.root_fs_path();
    std::fs::create_dir_all(&root_fs)
        .with_context(|| format!("create cluster root mount dir {}", root_fs.display()))?;
    let backend: Arc<dyn ObjectStore> = Arc::new(
        PathLocalBackend::new(&root_fs, /* fsync */ false)
            .with_context(|| format!("PathLocalBackend init at {}", root_fs.display()))?,
    );
    kernel
        .mount("/", MountOptions::new("local").with_backend(backend))
        .map_err(|e| anyhow::anyhow!("mount / via path_local: {:?}", e))?;
    tracing::info!(
        root_fs = %root_fs.display(),
        "mounted host-fs at \"/\" via PathLocalBackend",
    );

    // ── Plugin loading (§10) ─────────────────────────────────────────
    // Auto-load all .so/.dylib files from --plugin-dir (if specified).
    // Runs after kernel + root mount so plugins can use sys_read/sys_write.
    if let Some(ref plugin_dir) = common.plugin_dir {
        match kernel.load_plugin_dir(plugin_dir) {
            Ok(names) => {
                if !names.is_empty() {
                    tracing::info!(
                        count = names.len(),
                        names = ?names,
                        dir = %plugin_dir.display(),
                        "plugins loaded from --plugin-dir",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(err = %e, dir = %plugin_dir.display(), "plugin dir scan failed")
            }
        }
    }

    // Build VFS gRPC service as tonic Routes — co-hosted on the raft
    // port via ZoneManager. Uses NoAuth (mTLS is the boundary).
    let vfs_auth: Arc<dyn transport::auth::AuthProvider> = Arc::new(transport::auth::NoAuth);
    let vfs_routes = transport::grpc::build_vfs_routes(
        Arc::clone(&kernel),
        vfs_auth,
        64 * 1024 * 1024,
        "nexusd-cluster",
    );

    let ZoneManagerBundle {
        zm,
        node_id,
        self_address,
        peer_addrs,
    } = open_zone_manager(&common, Some(vfs_routes))?;

    // Bring root zone online based on declared mode.
    //
    //   * Static: dispatch through `bootstrap_or_join_zone` — empty
    //     peers → 1-voter single-node default; non-empty peers →
    //     joiner retry loop.
    //   * Restart: dispatch through `bootstrap_or_join_zone` —
    //     persisted ConfState resumes (branch 1).
    //   * Dynamic: SKIP root bootstrap entirely; daemon comes up
    //     rootless, operator drives `create_zone` via runtime API.
    //
    // `bootstrap_or_join_zone` is a sync helper that may spin a
    // nested `tokio::runtime` for its JoinZone RPCs (joiner branch),
    // which would panic with "Cannot start a runtime from within a
    // runtime" on a worker thread of the outer `#[tokio::main]`.
    // `spawn_blocking` moves it onto the blocking pool where nested
    // runtime creation is allowed.
    if matches!(mode, BootstrapMode::Static | BootstrapMode::Restart) {
        let zm_for_bootstrap = zm.clone();
        let self_addr_for_bootstrap = self_address.clone();
        let peer_addrs_for_bootstrap = peer_addrs.clone();
        tokio::task::spawn_blocking(move || {
            bootstrap_or_join_zone(
                zm_for_bootstrap.as_ref(),
                "root",
                node_id,
                &self_addr_for_bootstrap,
                &peer_addrs_for_bootstrap,
                bootstrap_new,
                /* max_attempts */ None, // daemon boot — retry forever
                /* as_learner   */
                false, // root cluster votes; learners are for share/join
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("bootstrap join task panicked: {}", e))?
        .map_err(|e| anyhow::anyhow!("bootstrap_or_join_zone: {}", e))?;
    } else {
        tracing::info!(
            "bootstrap mode = dynamic; daemon up rootless — operator drives \
             create_zone via runtime API",
        );
    }

    // `bootstrap_static` — invoked below when federation env vars are
    // set — is `NEXUS_FEDERATION_ZONES`/`_MOUNTS` driven and only
    // meaningful on the founder (`bootstrap_new` true).
    let peers_str: Vec<String> = peer_addrs
        .iter()
        .map(NodeAddress::to_raft_peer_str)
        .collect();

    let fed = parse_federation_env();
    // Surface every dropped `NEXUS_FEDERATION_MOUNTS` entry so the
    // operator sees them in boot logs.  When the input was non-empty
    // but the parser ate everything (the Mac↔Win L1 smoke wedge:
    // Windows MSYS Git Bash mangling `/shared=sharedzone` into
    // `C:/Program Files/Git/shared=sharedzone`), refuse to boot —
    // a silent `mount_count=0` federation leaves the operator
    // chasing downstream raft-replication symptoms for hours.
    for d in &fed.mounts.dropped {
        tracing::error!(
            raw = %d.raw,
            reason = d.reason,
            env_var = ENV_FEDERATION_MOUNTS,
            "federation mount entry dropped at parse",
        );
    }
    if fed.mounts.is_silent_dropall() {
        return Err(anyhow::anyhow!(
            "{} parsed to zero mounts despite non-empty input — refusing to start \
             with a silently broken federation topology.  Inspect the per-entry \
             reasons logged above (one common trigger is MSYS path conversion on \
             Windows Git Bash; export MSYS_NO_PATHCONV=1 or single-quote the value).",
            ENV_FEDERATION_MOUNTS,
        ));
    }
    if !fed.zones.is_empty() || !fed.mounts.mounts.is_empty() {
        tracing::info!(
            zones = ?fed.zones,
            mount_count = fed.mounts.mounts.len(),
            "Bootstrapping static topology from {} / {}",
            ENV_FEDERATION_ZONES,
            ENV_FEDERATION_MOUNTS,
        );
        zm.bootstrap_static_async(
            fed.zones.clone(),
            peers_str.clone(),
            fed.mounts.mounts.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("bootstrap_static: {}", e))?;
    }

    // Canonical coordinator boot wiring: self-address publish, DT_MOUNT
    // apply-cb install on every loaded zone (root + env-listed federation
    // zones + zones restored from disk), DT_MOUNT replay, blob-fetcher
    // slot stash + drain, `bootstrap_done` flip.  Without this, DT_MOUNT
    // entries proposed via `share --mount-at` / `join` / `apply_topology`
    // would write into raft state but never reach `VFSRouter`, writes
    // would carry no `last_writer_address`, and ReadBlob would have
    // nothing to serve.  Held until shutdown so the apply-cb closures +
    // their Arc clones see a stable provider lifetime.
    let _dist_coord = {
        let coord = nexus_raft::distributed_coordinator::RaftDistributedCoordinator::new();
        coord.install_with_kernel(zm.clone(), zm.runtime_handle(), &self_address, &kernel);
        coord
    };

    // Outbound peer-blob client — installs a `PeerBlobClient` over
    // the kernel-shared tokio runtime, replacing the `NoopPeerBlobClient`
    // default so `Kernel::try_remote_fetch` can actually fetch bytes
    // from origin nodes on local-backend misses.  Sits above raft in
    // the dep graph; kept out of `install_with_kernel` for that reason.
    transport::peer_blob::install(kernel.as_ref());

    // ── Driver-plugin mounts (§10) ───────────────────────────────────
    // Parse `--mount-driver name:zone:vfs-path:config-json` and mount
    // each entry through the kernel's normal mount surface.  Order
    // contract:
    //   1. `--plugin-dir` scan already loaded the dylibs above.
    //   2. Federation static-topology bootstrap has already created
    //      the env-listed zones (`NEXUS_FEDERATION_ZONES`), and
    //      `RaftDistributedCoordinator::install_with_kernel` has just
    //      flipped `is_initialized` to true.  That gates the
    //      `kernel.mount(..)` zone-create-on-mount path inside
    //      `sys_setattr DT_MOUNT` — required when the operator names
    //      a separate zone that doesn't yet exist.
    //   3. PeerBlobClient is installed so cross-node fetches on
    //      `last_writer_address` already-replicated bytes have a
    //      transport to ride.
    //
    // `vfs_path` must be non-`/` (the boot mount owns that point);
    // `zone` is operator-supplied without further constraint — root
    // is the single-canonical node-local case (same-zone routing
    // keeps it strictly local), a separate raft zone is the case
    // operators reach for when extending the mount across peers.
    for raw in &common.mount_drivers {
        let spec = parse_mount_driver_spec(raw)
            .map_err(|e| anyhow::anyhow!("--mount-driver parse error: {e}"))?;
        let backend = kernel
            .make_driver(&spec.name, &spec.config_json)
            .map_err(|e| {
                anyhow::anyhow!(
                    "make_driver({}, …): {e} \
                     (is the dylib in --plugin-dir and was it loaded?)",
                    spec.name,
                )
            })?;
        kernel
            .mount(
                &spec.vfs_path,
                MountOptions::new(&spec.name)
                    .with_backend(backend)
                    .with_zone(&spec.zone_id),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "mount driver '{}' at zone '{}' path '{}': {:?}",
                    spec.name,
                    spec.zone_id,
                    spec.vfs_path,
                    e,
                )
            })?;
        tracing::info!(
            driver = %spec.name,
            zone_id = %spec.zone_id,
            vfs_path = %spec.vfs_path,
            "mounted driver plugin",
        );
    }

    let zm_for_loop = zm.clone();
    let topology_handle = tokio::spawn(async move {
        loop {
            match zm_for_loop
                .apply_topology_async(contracts::ROOT_ZONE_ID)
                .await
            {
                Ok(true) => {
                    if !zm_for_loop.pending_mounts().is_empty() {
                        tokio::time::sleep(TOPOLOGY_TICK).await;
                        continue;
                    }
                    tokio::time::sleep(TOPOLOGY_TICK * 6).await;
                }
                Ok(false) => tokio::time::sleep(TOPOLOGY_TICK).await,
                Err(err) => {
                    tracing::warn!(%err, "apply_topology error; will retry");
                    tokio::time::sleep(TOPOLOGY_TICK).await;
                }
            }
        }
    });

    wait_for_shutdown().await;
    tracing::info!("nexusd-cluster shutting down");

    // Stop the convergence loop first — it's a best-effort reconciler,
    // safe to abort mid-tick.
    topology_handle.abort();

    // Drain ZoneManager: signal gRPC + zone transport loops to exit
    // their serve_with_shutdown paths so in-flight raft messages drain
    // cleanly. ZoneManager::shutdown() is synchronous and uses an
    // internal bridge_block_on; call it from spawn_blocking so we
    // don't trigger "Cannot drop a runtime" / nested-runtime panics.
    //
    // 10s cap matches typical k8s preStop / SIGTERM grace windows —
    // if tonic hasn't finished draining by then, force-drop and exit
    // rather than hang the pod.
    //
    // TODO(leader-transfer): on graceful shutdown of a leader we could
    // proactively transfer leadership before drain, sparing the cluster
    // one election round. raft-rs's `MsgTransferLeader` is not exposed
    // through our wrapper today, and `propose_conf_change(RemoveNode,
    // self_id)` would permanently demote the node — wrong semantics
    // for a restart-and-rejoin cycle. Out of scope for this PR; needs
    // a dedicated commitment-timeline test plan.
    let zm_for_drain = zm.clone();
    let drain = tokio::task::spawn_blocking(move || {
        zm_for_drain.shutdown();
    });
    match tokio::time::timeout(Duration::from_secs(10), drain).await {
        Ok(Ok(())) => tracing::info!("ZoneManager drain complete"),
        Ok(Err(join_err)) => tracing::warn!(?join_err, "ZoneManager drain task panicked"),
        Err(_) => tracing::warn!("ZoneManager drain exceeded 10s — forcing exit"),
    }

    // Drop Kernel (which owns a nested tokio Runtime) on a blocking
    // thread — dropping it inside the current async context panics with
    // "Cannot drop a runtime in a context where blocking is not allowed".
    tokio::task::spawn_blocking(move || {
        drop(kernel);
        drop(zm);
    })
    .await
    .ok();

    Ok(())
}

async fn run_share(
    common: CommonArgs,
    parent_zone: &str,
    path: &str,
    new_zone_id: &str,
    mount_at: Option<&str>,
) -> Result<()> {
    let ZoneManagerBundle { zm, peer_addrs, .. } = open_zone_manager(&common, None)?;
    let peers_str: Vec<String> = peer_addrs
        .iter()
        .map(NodeAddress::to_raft_peer_str)
        .collect();

    if zm.get_zone(new_zone_id).is_none() {
        zm.create_zone_async(new_zone_id, peers_str)
            .await
            .map_err(|e| anyhow::anyhow!("create_zone({}): {}", new_zone_id, e))?;
    }

    // No leader-wait dance here — ``share_subtree_core`` owns its
    // leadership precondition internally (waits on ``new_zone_id``,
    // the actual write target).  Reads on ``parent_zone`` are local
    // sequential-consistency, no leader required.
    let copied = zm
        .share_subtree_core_async(parent_zone, path, new_zone_id)
        .await
        .map_err(|e| anyhow::anyhow!("share_subtree: {}", e))?;

    println!(
        "Shared '{}' from zone '{}' as new zone '{}' ({} entries copied)",
        path, parent_zone, new_zone_id, copied
    );

    // Optional self-mount in the same operation. zm.mount writes a
    // DT_MOUNT entry via the parent zone's raft state machine, so the
    // entry replicates to every member — both the sharer's later writes
    // to `mount_path` and any future joiner see the same mount with no
    // extra coordination. Without this step `share` only creates the
    // raft group; the sharer's own writes keep routing to the original
    // (local) mount until some peer's `join` happens to add the entry.
    // Idempotent re-mount to the same target is a no-op (see
    // `zm.mount`).
    if let Some(mount_path) = mount_at {
        zm.mount_async(parent_zone, mount_path, new_zone_id, true)
            .await
            .map_err(|e| anyhow::anyhow!("mount({mount_path}): {e}"))?;
        println!("Mounted zone '{new_zone_id}' at '{mount_path}' in parent zone '{parent_zone}'");
    }
    Ok(())
}

async fn run_join(
    common: CommonArgs,
    peer_addr: &str,
    remote_zone_id: &str,
    local_path: &str,
    parent_zone: &str,
) -> Result<()> {
    let ZoneManagerBundle {
        zm,
        node_id,
        self_address,
        ..
    } = open_zone_manager(&common, None)?;

    // Pre-#3996 (and pre-this commit) ``run_join`` only invoked
    // ``zm.join_zone(remote_zone_id, peers, false)`` — that registers
    // the zone locally with ``skip_bootstrap=true`` but never tells
    // the leader on ``peer_addr`` "I want in".  No JoinZone RPC fires,
    // no AddNode commits, the joiner waits forever after restart.
    //
    // Drive the same SSOT machinery ``run_daemon`` uses for the root
    // zone: ``bootstrap_or_join_zone`` with ``bootstrap_new=false``.  That
    // (a) registers the zone locally with ``skip_bootstrap=true`` so
    // the local gRPC server can serve append-entries from the leader
    // once the membership change commits, then (b) sends ``JoinZone``
    // RPC to ``peer_addr``, then (c) returns once the leader's response
    // confirms the change + the snapshot has installed authoritative
    // ConfState locally.
    //
    // ``as_learner=true`` — `share` / `join` is the owner-pattern
    // subtree-mount flow.  The creator of the shared zone (`share`)
    // is the authoritative single voter; every joiner enters as a
    // Learner so it receives full replication but never participates
    // in quorum.  This makes wipe-rejoin safe by construction —
    // losing or replacing a learner has zero impact on the owner's
    // ability to commit, so SSD swap / OS reinstall / device
    // migration cannot strand the zone in `not leader` deadlock the
    // way the historical 2-voter pattern could (the failure that
    // motivated this change).
    //
    // ``max_attempts=Some(15)`` × ``JOIN_ZONE_RETRY_INTERVAL`` (2 s)
    // ≈ 30 s upper bound on the operator command — long enough to
    // absorb a leader election round on the remote, short enough that
    // a stuck command terminates with a clear error rather than
    // hanging forever like the daemon-boot path does.
    let use_tls = !common.no_tls;
    let peer = NodeAddress::parse(peer_addr, use_tls)
        .map_err(|e| anyhow::anyhow!("--peer-addr parse '{}': {}", peer_addr, e))?;
    let peer_addrs = vec![peer];

    let zm_for_join = zm.clone();
    let self_addr_for_join = self_address.clone();
    let zone_id_for_join = remote_zone_id.to_string();
    tokio::task::spawn_blocking(move || {
        nexus_raft::distributed_coordinator::bootstrap_or_join_zone(
            zm_for_join.as_ref(),
            &zone_id_for_join,
            node_id,
            &self_addr_for_join,
            &peer_addrs,
            /* bootstrap_new */ false,
            /* max_attempts  */ Some(15),
            /* as_learner    */ true,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("join task panicked: {}", e))?
    .map_err(|e| anyhow::anyhow!("bootstrap_or_join_zone({}): {}", remote_zone_id, e))?;

    zm.mount_async(parent_zone, local_path, remote_zone_id, true)
        .await
        .map_err(|e| anyhow::anyhow!("mount: {}", e))?;

    println!(
        "Joined remote zone '{}' (via {}); mounted at '{}' inside zone '{}'",
        remote_zone_id, peer_addr, local_path, parent_zone
    );
    Ok(())
}

/// One-shot federation-state health audit of a stopped daemon's data
/// directory.  Reads each zone's persisted ConfState + HardState +
/// last_log_index directly from redb (no driver, no async runtime,
/// no kernel attachment) and prints a single-screen summary with
/// per-zone alarms that name the historical operator failure modes:
///
///   * `STALE_LOG` — log_last_index = 0 but ConfState non-empty.
///     The half-installed state that wedged the Mac↔Win L1 smoke
///     for 8 h.  Use the same `check_zone_resumable_from_indices`
///     invariant `bootstrap_or_join_zone` Branch 1 uses, so doctor
///     and daemon-boot stay aligned by construction.
///
/// `--data-dir` is the same path passed to `nexusd-cluster
/// --data-dir`.  Subdirectories that contain a `raft/raft.redb` file
/// are treated as zones; others are skipped.  redb's exclusive lock
/// means the daemon must be stopped first — the failure mode
/// otherwise is a clear "could not open zone storage" error per zone.
fn run_doctor(data_dir: &std::path::Path, zone_filter: Option<&str>) -> Result<()> {
    use nexus_raft::raft::RaftStorage;

    if !data_dir.exists() {
        return Err(anyhow::anyhow!(
            "doctor: --data-dir {} does not exist",
            data_dir.display()
        ));
    }

    // Discover candidate zones — any subdir whose `raft/raft.redb`
    // file exists.  Same shape `ZoneRaftRegistry::enumerate_*` uses
    // at boot, just without instantiating the live state machine.
    let mut zones: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(data_dir)
        .with_context(|| format!("doctor: read_dir({})", data_dir.display()))?
    {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let raft_dir = entry.path().join("raft");
        if !raft_dir.join("raft.redb").exists() {
            continue;
        }
        if let Some(filter) = zone_filter {
            if name != filter {
                continue;
            }
        }
        zones.push((name, raft_dir));
    }
    zones.sort_by(|a, b| a.0.cmp(&b.0));

    if zones.is_empty() {
        if let Some(filter) = zone_filter {
            println!(
                "doctor: no zone '{filter}' found under {}",
                data_dir.display()
            );
        } else {
            println!(
                "doctor: no zones found under {} (looking for <zone>/raft/raft.redb)",
                data_dir.display()
            );
        }
        return Ok(());
    }

    let total = zones.len();
    let mut alarmed = 0usize;
    println!("# Doctor — {} zone(s) under {}", total, data_dir.display());
    println!();
    for (zone_id, raft_dir) in zones {
        let storage = match RaftStorage::open(&raft_dir) {
            Ok(s) => s,
            Err(e) => {
                println!("## zone '{zone_id}'");
                println!("  ALARM  STORAGE_LOCKED: could not open raft storage at {} — is the daemon still running?  {e}", raft_dir.display());
                println!();
                alarmed += 1;
                continue;
            }
        };
        // RaftStorage exposes the storage state via inherent _impl
        // methods (the raft-rs `Storage` trait methods all delegate
        // to these); using them directly keeps the trait out of
        // scope here.
        let state = storage
            .initial_state_impl()
            .map_err(|e| anyhow::anyhow!("zone '{zone_id}': initial_state: {e:?}"))?;
        let last_log_index = storage
            .last_index_impl()
            .map_err(|e| anyhow::anyhow!("zone '{zone_id}': last_index: {e:?}"))?;
        let first_log_index = storage
            .first_index_impl()
            .map_err(|e| anyhow::anyhow!("zone '{zone_id}': first_index: {e:?}"))?;

        println!("## zone '{zone_id}'");
        println!(
            "  voters     = {:?}",
            state.conf_state.voters.iter().collect::<Vec<_>>()
        );
        println!(
            "  learners   = {:?}",
            state.conf_state.learners.iter().collect::<Vec<_>>()
        );
        println!("  term       = {}", state.hard_state.term);
        println!("  commit     = {}", state.hard_state.commit);
        println!("  log_first  = {first_log_index}");
        println!("  log_last   = {last_log_index}");

        // Cross-check against the same invariant `bootstrap_or_join_zone`
        // Branch 1 uses — single SSOT for "resumable state".
        if let Err(reason) =
            nexus_raft::distributed_coordinator::check_zone_resumable_from_indices(last_log_index)
        {
            alarmed += 1;
            println!(
                "  ALARM  STALE_LOG: {reason}\n  \
                 RECOVERY: stop the daemon, then either\n  \
                 (a) run `nexusd-cluster join <leader_node_id>@<leader_addr> {zone_id} \
                 /<mount> --data-dir <data_dir> --no-tls` against the leader, then restart, or\n  \
                 (b) `rm -rf {raft_dir_parent}` (this zone only) and restart in static mode.",
                raft_dir_parent = raft_dir
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| zone_id.clone()),
            );
        } else {
            println!("  OK");
        }
        println!();
    }
    println!(
        "Summary: {alarmed} alarmed / {total} total zone(s).  {}",
        if alarmed == 0 {
            "All zones look healthy."
        } else {
            "See per-zone RECOVERY hints above."
        }
    );
    if alarmed > 0 {
        // Non-zero exit for scripted use (CI alarms, watch loops).
        std::process::exit(2);
    }
    Ok(())
}

/// Install the global tracing subscriber with a non-blocking stdout
/// writer. The returned [`WorkerGuard`] MUST be held for the lifetime of
/// the process — dropping it flushes buffered lines and stops the writer
/// thread, so logs emitted after the drop are lost.
///
/// The non-blocking writer hands every log line to a dedicated thread
/// instead of writing stdout inline. Under a slow or stalled stdout sink
/// the default `fmt()` writer blocks the calling tokio worker in a
/// `write()` syscall; at high log frequency that can stall enough workers
/// to starve the gRPC server's accept/handshake path. Decoupling the I/O
/// keeps the runtime responsive regardless of log volume.
fn install_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("nexusd_cluster=info,nexus_raft=info")
            }),
        )
        .with_writer(non_blocking)
        .init();
    guard
}

fn resolve_hostname(cli: Option<&str>) -> String {
    if let Some(h) = cli {
        return h.to_string();
    }
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// Resolve the durable metastore path for this node (#4343).
///
/// Precedence:
///   * `NEXUS_KERNEL_METASTORE_PATH` set and non-empty → that file path.
///   * `NEXUS_KERNEL_METASTORE_PATH` set but EMPTY → `None` — explicit opt-out
///     back into the ephemeral tempfile metastore (debug escape hatch;
///     the namespace then dies with the process).
///   * unset → `<data_dir>/metastore.redb`.
fn resolve_metastore_path(env_value: Option<&str>, data_dir: &std::path::Path) -> Option<PathBuf> {
    match env_value {
        Some("") => None,
        Some(v) => Some(PathBuf::from(v)),
        None => Some(data_dir.join("metastore.redb")),
    }
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("Received Ctrl+C"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Received Ctrl+C");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metastore_path_defaults_into_data_dir() {
        let p = resolve_metastore_path(None, std::path::Path::new("/data"));
        assert_eq!(p, Some(PathBuf::from("/data/metastore.redb")));
    }

    #[test]
    fn metastore_path_env_overrides() {
        let p = resolve_metastore_path(Some("/elsewhere/ms.redb"), std::path::Path::new("/data"));
        assert_eq!(p, Some(PathBuf::from("/elsewhere/ms.redb")));
    }

    #[test]
    fn metastore_path_empty_env_opts_out() {
        assert_eq!(
            resolve_metastore_path(Some(""), std::path::Path::new("/data")),
            None
        );
    }

    #[test]
    fn mount_driver_parses_basic_spec() {
        let spec = parse_mount_driver_spec(
            "local-connector:sharedzone:/cc-tasks/mac:{\"local_root\":\"/host/tasks-mac\"}",
        )
        .expect("valid spec");
        assert_eq!(spec.name, "local-connector");
        assert_eq!(spec.zone_id, "sharedzone");
        assert_eq!(spec.vfs_path, "/cc-tasks/mac");
        assert_eq!(spec.config_json, "{\"local_root\":\"/host/tasks-mac\"}");
    }

    #[test]
    fn mount_driver_preserves_colons_in_json() {
        // JSON object literal has 2 colons inside (key:value pairs); the
        // 4-part splitn must keep them all in `config_json`.
        let raw = "s3-conn:blob-zone:/external/blobs:{\"endpoint\":\"https://s3.example.com:9000\",\"bucket\":\"x\"}";
        let spec = parse_mount_driver_spec(raw).expect("colons in JSON survive split");
        assert_eq!(spec.name, "s3-conn");
        assert_eq!(spec.zone_id, "blob-zone");
        assert_eq!(spec.vfs_path, "/external/blobs");
        assert_eq!(
            spec.config_json,
            "{\"endpoint\":\"https://s3.example.com:9000\",\"bucket\":\"x\"}"
        );
    }

    #[test]
    fn mount_driver_rejects_root_mount_path() {
        // `/` collides with the boot-time PathLocalBackend mount and
        // trips `add_mount`'s `rebind_missing_backends` SSOT branch
        // (the operator's driver would silently re-point every
        // backend-less federation child mount at host fs).
        let err = parse_mount_driver_spec("local-connector:root:/:{\"local_root\":\"/host\"}")
            .unwrap_err();
        assert!(err.contains("reserved for the boot-time"), "got: {err}");
    }

    #[test]
    fn mount_driver_accepts_root_zone_non_root_path() {
        // Root zone with a non-`/` path is the canonical single-node
        // host-fs exposure case — same-canonical routing keeps it
        // local (no federation replication or zone create-on-mount).
        let spec =
            parse_mount_driver_spec("local-connector:root:/tasks:{\"local_root\":\"/host/tasks\"}")
                .expect("root zone is allowed for non-root paths");
        assert_eq!(spec.zone_id, "root");
        assert_eq!(spec.vfs_path, "/tasks");
    }

    #[test]
    fn mount_driver_accepts_separate_zone() {
        // Separate-zone mounts stay first-class — they're how a
        // future cross-node operator-mount substrate will compose.
        let spec = parse_mount_driver_spec(
            "local-connector:my-docs:/files:{\"local_root\":\"/home/me/docs\"}",
        )
        .expect("any non-empty zone name is accepted");
        assert_eq!(spec.zone_id, "my-docs");
        assert_eq!(spec.vfs_path, "/files");
    }

    #[test]
    fn mount_driver_rejects_relative_path() {
        let err = parse_mount_driver_spec("local-connector:myzone:relative/path:{}").unwrap_err();
        assert!(err.contains("must start with '/'"), "got: {err}");
    }

    #[test]
    fn mount_driver_rejects_empty_parts() {
        assert!(parse_mount_driver_spec(":::").is_err());
        assert!(parse_mount_driver_spec("name::/path:config").is_err());
        assert!(parse_mount_driver_spec("name:zone:/path:").is_err());
        assert!(parse_mount_driver_spec("name:zone::config").is_err());
    }

    #[test]
    fn mount_driver_rejects_too_few_parts() {
        assert!(parse_mount_driver_spec("local-connector").is_err());
        assert!(parse_mount_driver_spec("local-connector:myzone").is_err());
        assert!(parse_mount_driver_spec("local-connector:myzone:/path").is_err());
    }
}
