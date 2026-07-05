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
    ///
    /// Display label only — used by ZoneManager for human-readable
    /// identification in logs and (when TLS bootstraps cert SANs).
    /// Peers learn this node's REACHABLE endpoint from
    /// `--advertise-addr` instead.
    ///
    /// Past behaviour overloaded hostname as both display label AND
    /// advertise identity, which silently broke cross-machine
    /// federation over Tailscale/VPN overlays where the OS hostname
    /// does not resolve through the overlay (peers would dial
    /// `http://win:2126` from a Mac and fail at the DNS layer).
    #[arg(long, env = "NEXUS_HOSTNAME", global = true)]
    hostname: Option<String>,

    /// Address this node advertises to peers as its reachable raft
    /// endpoint, in `host:port` form.
    ///
    /// Used as `StepMessage.sender_address` so peer-map runtime SSOT
    /// learns where to dial this node back. MUST be reachable from
    /// every peer that needs to talk to this node — for cross-machine
    /// federation over an overlay network (Tailscale, WireGuard,
    /// VPN), this MUST be that overlay's IP, not the OS hostname.
    ///
    /// Falls back to `{hostname}:{bind_port}` when unset, which is
    /// fine for single-node tests but breaks cross-machine setups
    /// where the OS hostname does not resolve through the overlay.
    /// Boot logs a warning if the fallback looks unreachable
    /// (`0.0.0.0:*`, loopback, or non-IP host with peers configured).
    #[arg(long, env = "NEXUS_ADVERTISE_ADDR", global = true)]
    advertise_addr: Option<String>,

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

    /// Node-bound identity directory holding `identity.json`
    /// (schema-versioned peer address book).
    ///
    /// Unset (default): resolved via
    /// `nexus_raft::identity::default_identity_dir()` to the
    /// platform-native user-data location (`%LOCALAPPDATA%\Nexus`,
    /// `~/Library/Application Support/Nexus`, `$XDG_DATA_HOME/nexus`).
    /// Set explicitly for Docker E2E tests that need to redirect the
    /// identity file to a fixture path, or operators who want the
    /// identity under a specific management scope.  Persists ONLY the
    /// transport peer list — `node_id` stays at `<data_dir>/.node_id`
    /// with its rotate-on-wipe lifecycle, per the raft heartbeat
    /// invariant documented in `docs/federation-architecture.md`
    /// § 6.3.1.  SHOULD live outside `--data-dir` so cache-loss cleanup
    /// does not remove it — boot warns if `identity_dir` is a child of
    /// `data_dir`.
    #[arg(long, env = "NEXUS_IDENTITY_DIR", global = true)]
    identity_dir: Option<PathBuf>,

    /// Durable global metastore (redb) — the kernel's VFS namespace.
    /// File registrations survive restarts only if this lives on
    /// persistent storage. Defaults to `<data_dir>/metastore.redb`;
    /// relative values resolve against the data dir (a cwd-anchored
    /// store would silently re-anchor when a wrapper changes the
    /// working directory). The literal `ephemeral` opts into the
    /// non-durable boot tempfile store (debug escape hatch — the
    /// namespace then dies with the process); an explicitly EMPTY
    /// value refuses to boot.
    ///
    /// The env is deliberately `NEXUS_KERNEL_METASTORE_PATH` (the
    /// `NEXUS_KERNEL_*` subprocess-control namespace, like
    /// `NEXUS_KERNEL_BINARY`), NOT `NEXUS_METASTORE_PATH`: the Python
    /// server sets the latter for its own legacy metadata path and
    /// copies its environment into this subprocess — reusing it here
    /// would point the kernel at the Python-era redb file instead of
    /// this node's own store.
    #[arg(long, env = "NEXUS_KERNEL_METASTORE_PATH", global = true)]
    metastore_path: Option<PathBuf>,

    /// Comma-separated raft peers in `host:port` form (e.g.
    /// `nexus-2:2126,nexus-3:2126`).  Node IDs are opaque and learned
    /// from raft messages at runtime — operators never carry them in
    /// the address book (see `PeerAddress::parse` docstring for the
    /// `learn_peer_address` contract).
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
        /// Remote peer as `host:port` (e.g. `nexus-2:2126` or
        /// `100.64.0.27:2126`).  This is the ONLY accepted form —
        /// peer `node_id` is opaque + random per boot and never
        /// belongs in the address book.  The `JoinZone` RPC targets
        /// this URL; the peer's real `node_id` is learned
        /// automatically from the first inbound `MsgSnapshot` via
        /// `transport::learn_peer_address`, which populates the
        /// peer_map entry outbound raft replies route through.
        ///
        /// Legacy `<id>@host:port` form is hard-rejected at parse
        /// time with a clear migration message — see
        /// `PeerAddress::parse` for the retirement rationale.
        peer_addr: String,
        /// Zone id to join on the remote side.
        remote_zone_id: String,
        /// Local path to mount the remote zone at.
        local_path: String,
        /// Parent zone for the mount entry; defaults to root.
        #[arg(long, default_value = "root")]
        parent_zone: String,
        /// Membership role on the shared zone — ``voter`` (default,
        /// symmetric-peer pattern: joiner counts toward quorum, equal
        /// write authority as the founder) or ``learner``
        /// (owner-pattern: joiner gets full replication but doesn't
        /// affect the owner's ability to commit; wipe-rejoin-safe).
        ///
        /// ``voter`` is the default because the canonical federation
        /// workflows we ship for (cc-tasks-share Mac↔Win, corp-zone
        /// partition smoke) are symmetric — both sides write and need
        /// to keep writing during partition.  It also aligns the CLI
        /// with the wire-level protocol default: `JoinZoneRequest`'s
        /// `bool as_learner` field defaults to `false` (voter) under
        /// proto3, so operators driving JoinZone via grpcurl already
        /// got voter by omission.
        ///
        /// ``learner`` is the right pick for owner-pattern workloads
        /// (single owner, dispensable followers): the guarantees from
        /// nexus-vfs PR #57 mean losing or replacing a learner has
        /// zero impact on the owner's ability to commit, so SSD swap
        /// / OS reinstall / device migration cannot strand the zone
        /// in `not leader` deadlock.  Pass `--as learner` to opt in.
        // Field name is `as_role` because `as` is a Rust keyword.
        // `long = "as"` overrides clap's default snake-to-kebab
        // derivation (which would give `--as-role`) so the
        // operator-facing flag reads naturally: `--as voter`.
        #[arg(long = "as", value_enum, default_value_t = JoinRole::Voter)]
        as_role: JoinRole,
    },
    /// Remove a node from a zone's ConfState via a `RemoveNode`
    /// ConfChange.  Mirror of `join` on the wire (which proposes
    /// `AddNode` / `AddLearnerNode`) for the reverse direction.
    ///
    /// The RPC is a straight pass-through to raft-rs's
    /// `RawNode::propose_conf_change` — no transport bypass, no
    /// Progress mutation, no state-machine surgery.  Same
    /// leader-only + follower-redirect pattern JoinZone uses; same
    /// idempotency behaviour raft-rs `Changer::remove` provides on
    /// unknown ids.  raft-rs itself rejects the "would remove all
    /// voters" case at apply time, so the RPC cannot brick the zone.
    ///
    /// Primary use case: prune a genuinely-dead voter (host is off
    /// or has been replaced) so the ConfState reflects reality.
    /// Cluster hygiene; not required to unblock wipe-rejoin under
    /// the rotate-on-wipe rule (a wiped node's fresh `node_id` joins
    /// via `join` without touching the old ghost's `Progress`).
    ///
    /// Typical flow:
    ///
    /// 1. Voter B is permanently offline (host destroyed, or SSD
    ///    swap without transfer).
    /// 2. Operator on any live node runs `nexusd-cluster remove-voter
    ///    <A_host>:<port> sharedzone --target <B_old_node_id>`.
    /// 3. B's ghost id is dropped from `ConfState`, and the Phase B
    ///    apply callback mirrors the new membership into
    ///    `identity.json` on every live node.
    ///
    /// ### Consequences the operator picks up
    ///
    /// Neither of these is a raft-protocol violation — both are
    /// spec-defined ConfChange semantics — but the operator owns the
    /// call:
    ///
    /// * **Quorum shrinks immediately.** A 2-voter cluster becomes
    ///   SOLO (still committable).  A 3-voter cluster becomes 2-of-2
    ///   (both remaining voters must be reachable to commit).
    /// * **Leader-removes-self triggers re-election.** If `--target`
    ///   is the current leader, raft-rs steps down and holds an
    ///   election on the remaining voters (spec-mandated behaviour).
    ///   Prefer to run against a follower node id or wait for
    ///   leadership to move.
    RemoveVoter {
        /// Any live cluster member as `host:port` — bare form only,
        /// same schema as `join`'s `<peer_addr>`.  Follower redirects
        /// resolve to the leader automatically.
        peer_addr: String,
        /// Zone whose ConfState should be pruned.
        zone_id: String,
        /// The stale node id to remove.  Learn it from `nexusd-cluster
        /// doctor` output, cluster status logs, or `identity.zones`
        /// members list on a surviving node.
        #[arg(long)]
        target: u64,
    },
}

/// Membership role a new node takes when joining an existing zone.
///
/// See the doc comment on ``Cmd::Join::as_role`` for the operator
/// decision matrix.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum JoinRole {
    /// Joiner does not count toward quorum.  Wipe-rejoin-safe.
    Learner,
    /// Joiner counts toward quorum.  Symmetric peer authority.
    Voter,
}

impl JoinRole {
    /// Translate to the ``as_learner: bool`` flag the underlying
    /// ``bootstrap_or_join_zone`` API takes today.
    fn is_learner(self) -> bool {
        matches!(self, JoinRole::Learner)
    }
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
                    as_role,
                }) => {
                    run_join(
                        args.common,
                        &peer_addr,
                        &remote_zone_id,
                        &local_path,
                        &parent_zone,
                        as_role.is_learner(),
                    )
                    .await
                }
                Some(Cmd::RemoveVoter {
                    peer_addr,
                    zone_id,
                    target,
                }) => run_remove_voter(&peer_addr, &zone_id, target).await,
            }
        })
}

/// Operator-facing wrapper around
/// [`nexus_raft::transport::call_remove_voter_rpc`].  See the
/// [`Cmd::RemoveVoter`] docstring for the operator flow.  Followers
/// return a leader_address; we follow the redirect once before failing
/// loud — matching the pattern in `run_join` / `bootstrap_or_join_zone`.
async fn run_remove_voter(peer_addr: &str, zone_id: &str, target_node_id: u64) -> Result<()> {
    // Parse operator-facing bare `host:port` and coerce to the http URL
    // the tonic Endpoint helper expects.  Reject the legacy `id@host:port`
    // form the same way `run_join` does.
    let peer = NodeAddress::parse_operator_addr(peer_addr, /* use_tls */ false)
        .map_err(|e| anyhow::anyhow!("--peer-addr parse '{}': {}", peer_addr, e))?;
    let endpoint = peer.endpoint.clone();

    let attempt = |endpoint: String| async move {
        nexus_raft::transport::call_remove_voter_rpc(
            &endpoint,
            zone_id,
            target_node_id,
            /* timeout_secs */ 15,
        )
        .await
        .map_err(|e| anyhow::anyhow!("RemoveVoter RPC: {}", e))
    };

    let result = attempt(endpoint.clone()).await?;
    let result = if !result.success {
        if let Some(leader_addr) = result.leader_address.clone() {
            tracing::info!(
                initial_peer = %endpoint,
                leader = %leader_addr,
                "RemoveVoter: follower redirect -- retrying on leader",
            );
            let leader_endpoint =
                if leader_addr.starts_with("http://") || leader_addr.starts_with("https://") {
                    leader_addr
                } else {
                    format!("http://{leader_addr}")
                };
            attempt(leader_endpoint).await?
        } else {
            result
        }
    } else {
        result
    };

    if !result.success {
        return Err(anyhow::anyhow!(
            "RemoveVoter refused: error={:?}, leader_address={:?}",
            result.error,
            result.leader_address,
        ));
    }

    println!("Removed voter node_id={target_node_id} from zone '{zone_id}' via {peer_addr}",);
    Ok(())
}

/// Bundle returned by [`open_zone_manager`].  Carries the opaque
/// `node_id` minted/loaded from `<data_dir>/.node_id` plus the
/// structured peer address book and self-address derived from
/// `--bind-addr`/`--hostname`.  `run_daemon` hands the lot to
/// [`bootstrap_or_join_zone`] which owns the actual root-zone
/// dispatch.
///
/// Two peer-list fields on purpose — same value shape, different
/// semantics, different consumers, different downstream contracts.
/// Do NOT be tempted to merge them; see the trade-off in the peer-
/// identity + bootstrap-safety PR body for why unifying strictly
/// weakens either the S3 identity-reconnect contract or the root
/// SOLO-invariant defense-in-depth.
struct ZoneManagerBundle {
    zm: std::sync::Arc<ZoneManager>,
    node_id: u64,
    self_address: String,
    /// CLI `--peers` / `NEXUS_PEERS` ONLY — this is what
    /// `bootstrap_or_join_zone("root", ..., peers=)` receives.  Root
    /// is per-node SOLO by contract (`distributed_coordinator.rs`
    /// SOLO-invariant guard), and non-empty here on root triggers a
    /// hard-fail.  Identity-persisted peers MUST NOT flow into this
    /// field — they're the S3 reconnect hint (survives data_dir wipe),
    /// not a bootstrap dispatch input.
    cli_peer_addrs: Vec<NodeAddress>,
    /// Identity ∪ CLI union re-persisted to `identity.json` at boot.
    /// Two consumers:
    ///   (a) `ZoneManager`'s transport peer_map seed — reconnect hint
    ///       that survives `data_dir` wipe (S3 identity contract).
    ///   (b) split-brain guard around `bootstrap_static` — non-empty
    ///       here + `NEXUS_FEDERATION_ZONES` set = both-founder
    ///       misconfig, fail loud rather than wedge downstream.
    /// MUST NOT flow into `bootstrap_or_join_zone(peers=)` for root —
    /// see the `cli_peer_addrs` docstring above.
    identity_persisted_peers: Vec<String>,
    /// Snapshot of `identity.json`'s per-zone membership at boot.
    /// Populated by the ConfChange apply callback in prior boots.
    /// Empty on fresh nodes.  Feeds `BootConfig::identity_zones` so
    /// the S3 Phase B auto-reconnect path knows which zones to
    /// JoinZone against.
    identity_zones: Vec<nexus_raft::identity::IdentityZone>,
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

    // Parse `--peers` into structured `NodeAddress` entries.  Merge
    // with the node-bound `identity.json` peer list so a cold-boot
    // after `<data_dir>` cleanup does not need operator re-specifying
    // `--peers`.  Identity's `peers[]` is a *transport seed*, NOT a
    // `ConfState` shadow (ConfState is independent, mutated only by
    // ConfChange via JoinZone in `bootstrap_or_join_zone`).
    //
    // See `docs/federation-architecture.md` § 6.3.1 — the split scopes
    // identity narrowly to the address book; `node_id` intentionally
    // stays at `<data_dir>/.node_id` under the rotate-on-wipe raft
    // heartbeat invariant.
    // Operator-facing strict parse: rejects `<id>@host:port`, forces
    // bare `host:port`.  See PeerAddress::parse_operator_addr.
    let cli_peer_addrs: Vec<NodeAddress> =
        NodeAddress::parse_peer_list_operator(&common.peers, use_tls)
            .map_err(|e| anyhow::anyhow!("--peers/NEXUS_PEERS parse: {}", e))?;
    // Identity persistence uses the operator-facing bare form so a
    // subsequent cold-boot load through `parse_operator_addr` never
    // trips the id-prefix rejection.
    let cli_peer_strs: Vec<String> = cli_peer_addrs
        .iter()
        .map(NodeAddress::to_operator_str)
        .collect();

    let identity_dir = common
        .identity_dir
        .clone()
        .unwrap_or_else(nexus_raft::identity::default_identity_dir);
    if identity_dir.starts_with(&common.data_dir) {
        tracing::warn!(
            identity_dir = %identity_dir.display(),
            data_dir = %common.data_dir.display(),
            "identity_dir lives under data_dir — cache-loss cleaners \
             that remove data_dir will also destroy identity; consider \
             --identity-dir <outside-data-dir>",
        );
    }
    let identity_loaded = nexus_raft::identity::load(&identity_dir)
        .map_err(|e| anyhow::anyhow!("identity load: {}", e))?;
    let identity_persisted =
        nexus_raft::identity::persist_peers(&identity_dir, &identity_loaded, &cli_peer_strs)
            .map_err(|e| anyhow::anyhow!("identity persist_peers: {}", e))?;

    // Feed the merged (identity ∪ CLI) list through NodeAddress so
    // self-address validation runs on the full set (an
    // identity-persisted peer that happens to match self_address must
    // still be rejected at parse time, not after `Zone registered`).
    //
    // The MERGED list seeds `ZoneManager`'s transport peer map (i.e.
    // "who might this node dial for federation") but does NOT
    // propagate into `bundle.cli_peer_addrs` — which is CLI-only, per
    // the struct docstring.  Reason: root is per-node SOLO, and
    // `bootstrap_or_join_zone("root", ..., peers=merged, ...)` would
    // hit the SOLO-invariant guard as soon as identity persisted a
    // sharedzone-leader peer.  Post-restart joiners in cc-tasks-share
    // topology reproduced exactly this cascade — identity carried
    // founder's address, root bootstrap errored, daemon exited,
    // sharedzone lost quorum, founder's FUSE writes hung with I/O
    // error.
    let merged_peers_joined = identity_persisted.peers.join(",");
    // Identity persistence is operator-strict too — see
    // `parse_operator_addr` docstring.
    let merged_peer_addrs: Vec<NodeAddress> =
        NodeAddress::parse_peer_list_operator(&merged_peers_joined, use_tls)
            .map_err(|e| anyhow::anyhow!("identity peers parse: {}", e))?;
    let merged_peers_str: Vec<String> = merged_peer_addrs
        .iter()
        .map(NodeAddress::to_raft_peer_str)
        .collect();

    // Advertise address — used as `StepMessage.sender_address` so the
    // peer-map runtime SSOT can learn this node's reachable endpoint.
    //
    // SSOT precedence:
    //   1. `--advertise-addr` / NEXUS_ADVERTISE_ADDR (explicit; required
    //      for cross-machine federation over overlay networks).
    //   2. Fallback `<hostname>:<bind_port>` (matches pre-PR behaviour;
    //      fine for single-node tests, breaks cross-machine federation
    //      whenever the OS hostname does not resolve through the
    //      overlay — see warn_if_self_address_unreachable below).
    let bind_port = common
        .bind_addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(2126);
    let self_address = resolve_self_address(
        common.advertise_addr.as_deref(),
        &hostname,
        bind_port,
        merged_peer_addrs.len(),
    );

    // Reject "self listed in --peers" early — see
    // `validate_peers_excludes_self` for why this is a hard error
    // under the PR #3996 opaque-ID contract.  Runs on the MERGED set
    // so an identity-persisted stale self-entry also surfaces here
    // rather than after `Zone registered`.
    validate_peers_excludes_self(&merged_peer_addrs, &self_address)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let zm = ZoneManager::with_node_id(
        &hostname,
        node_id,
        &zones_dir,
        merged_peers_str,
        &common.bind_addr,
        tls,
        Some(self_address.clone()),
        extra_grpc_services,
    )
    .map_err(|e| anyhow::anyhow!("ZoneManager::with_node_id: {}", e))?;

    // S3 Phase B: hand the identity directory to the zone registry so
    // every future zone install (both static founder and JoinZone
    // joiner paths) installs the ConfState apply mirror.  Must happen
    // BEFORE `bootstrap_or_join_zone` / `bootstrap_static_async` so
    // the first ConfChange apply is already covered.
    zm.registry().set_identity_dir(identity_dir.clone());

    // Return CLI-only cli_peer_addrs (root bootstrap consumer) +
    // identity ∪ CLI union (transport seed + split-brain guard
    // consumer) — see `ZoneManagerBundle` docstring for why they're
    // distinct fields, not merged.
    Ok(ZoneManagerBundle {
        zm,
        node_id,
        self_address,
        cli_peer_addrs,
        identity_persisted_peers: identity_persisted.peers,
        identity_zones: identity_persisted.zones,
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

    // ── Data plane: kernel + durable metastore + host-fs "/" mount ──
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
    // store too. Fail the boot if the redb cannot open: a silent
    // tempdir fallback is exactly the data-loss defect this guards
    // against. `--metastore-path` / NEXUS_KERNEL_METASTORE_PATH
    // overrides (see the arg docs for the env-name rationale and the
    // `ephemeral` escape hatch).
    wire_durable_metastore(&kernel, common.metastore_path.as_deref(), &common.data_dir)?;

    // Federation cache: kernel-global PathLocalBackend rooted at
    // `<data_dir>/federation-cache/`.  Satisfies the uniform local-
    // first sys_write contract — cross-mount writes to federation-
    // peer-mount placeholders land on THIS voter's host fs here,
    // addressed by canonical VFS path.  Path-addressed so every
    // placeholder mount on this node shares ONE on-disk root; the
    // metastore.put done by sys_write stamps `last_writer_address =
    // self`, and remote readers fetch back via the last-writer-aware
    // sys_read fallback.  Single Arc → kernel slot via
    // `Kernel::set_federation_cache` (see
    // `kernel/src/federation/coordinator_wiring.rs`).
    let federation_cache_root = common.data_dir.join("federation-cache");
    std::fs::create_dir_all(&federation_cache_root).with_context(|| {
        format!(
            "create federation cache dir {}",
            federation_cache_root.display()
        )
    })?;
    let federation_cache: Arc<dyn ObjectStore> = Arc::new(
        PathLocalBackend::new(&federation_cache_root, /* fsync */ false).with_context(|| {
            format!(
                "PathLocalBackend init at {}",
                federation_cache_root.display()
            )
        })?,
    );
    kernel.set_federation_cache(Arc::clone(&federation_cache));
    tracing::info!(
        federation_cache_root = %federation_cache_root.display(),
        "federation cache wired",
    );

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

    // Merge plugin-exposed gRPC services onto the same Routes.  Each
    // service-plugin that exported the optional
    // `nexus_plugin_grpc_services` ABI symbol gets one URL prefix per
    // declared service; the proxy strips the gRPC frame and hands raw
    // proto bytes to the plugin's existing `nexus_service_dispatch`.
    // Plugins without the opt-in symbol are unaffected — they keep
    // routing through the legacy Call RPC + ServiceRegistry path.
    let plugin_endpoints = kernel.plugin_grpc_endpoints();
    if !plugin_endpoints.is_empty() {
        tracing::info!(
            count = plugin_endpoints.len(),
            "merging plugin gRPC endpoints into VFS Routes",
        );
    }
    let vfs_routes = transport::grpc_plugin_proxy::extend_routes_with_plugin_endpoints(
        vfs_routes,
        plugin_endpoints,
    );

    let ZoneManagerBundle {
        zm,
        node_id,
        self_address,
        cli_peer_addrs,
        identity_persisted_peers,
        identity_zones,
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
        let peer_addrs_for_bootstrap = cli_peer_addrs.clone();
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

    // Preserved PR #112 split-brain guard — backstops the FailLoud arm
    // of `plan_boot_action` (row 5) with a longer, operator-actionable
    // hint so the concrete recovery path is one paragraph rather than
    // one sentence.  Order matters: this fires BEFORE plan_boot_action
    // sees the same shape, so the verbose message wins.  Kept even
    // though row 5 is unreachable from here on because bootstrap.rs
    // also has it — belt-and-suspenders for one of the most expensive
    // debugging traps we've hit (152-commit vs 1-commit both-founder
    // wedge, 2026-07-04).
    if (!fed.zones.is_empty() || !fed.mounts.mounts.is_empty())
        && !identity_persisted_peers.is_empty()
    {
        return Err(anyhow::anyhow!(
            "split-brain guard: {} is set (zones={:?}) but identity.json \
                 already lists peers={:?}.  Auto-creating a SOLO zone on a \
                 node that already knows peers is the both-founder misconfig \
                 -- it produces two independent raft clusters sharing the \
                 same zone name whose leader histories cannot merge.  \
                 Choose one role:\n  \
                 (a) FOUNDER -- this node is the source of truth.  Remove \
                 the persisted peers first: rm -f IDENTITY_DIR/identity.json \
                 (leave data_dir alone if you have prior state to reuse), \
                 then re-run.\n  \
                 (b) JOINER -- the persisted peers are the actual founders. \
                 Unset {} and {} in this launcher, then run: \
                 nexusd-cluster join FOUNDER_HOST:PORT ZONE MOUNT_PATH \
                 --data-dir DATA_DIR  before restarting the daemon.",
            ENV_FEDERATION_ZONES,
            fed.zones,
            identity_persisted_peers,
            ENV_FEDERATION_ZONES,
            ENV_FEDERATION_MOUNTS,
        ));
    }

    // Unified bring-up decision layer (S3 完全体).  Replaces the pre-
    // refactor unconditional `bootstrap_static_async` call.  See
    // `nexus_raft::bootstrap` for the full decision matrix; the
    // dispatch below has one arm per `BootAction` variant.
    let boot_cfg = nexus_raft::bootstrap::BootConfig {
        identity_persisted_peers: identity_persisted_peers.clone(),
        cli_peer_addrs: cli_peer_addrs.clone(),
        federation_zones: fed.zones.clone(),
        federation_mounts: fed.mounts.mounts.clone(),
        bootstrap_new,
        has_disk_state: data_dir_has_root,
        identity_zones: identity_zones.clone(),
    };
    match nexus_raft::bootstrap::plan_boot_action(&boot_cfg) {
        nexus_raft::bootstrap::BootAction::StaticFounder {
            zones,
            mounts,
            peers_for_ha,
        } => {
            // Matrix row 1 — see `plan_boot_action` docstring for the
            // full table.  Pure founder: auto-create SOLO per zone.
            tracing::info!(
                zones = ?zones,
                mount_count = mounts.len(),
                ha_seed_count = peers_for_ha.len(),
                "Bootstrapping static topology from {} / {}",
                ENV_FEDERATION_ZONES,
                ENV_FEDERATION_MOUNTS,
            );
            // S3 Phase D: expose the founder's federation mount table
            // via the `DiscoverZones` RPC so a fresh joiner boot with
            // only `--peers <founder>` can auto-JoinZone each zone
            // without an offline `nexusd-cluster join` sidecar.
            zm.registry().set_federation_mounts(mounts.clone());
            zm.bootstrap_static_async(zones, peers_for_ha, mounts)
                .await
                .map_err(|e| anyhow::anyhow!("bootstrap_static: {}", e))?;
        }
        nexus_raft::bootstrap::BootAction::RootlessDynamic => {
            // Matrix row 2 — see `plan_boot_action` docstring.  Nothing
            // declared; root already handled upstream, federation
            // branch is a no-op.
        }
        nexus_raft::bootstrap::BootAction::JoinFederationZones {
            peers,
            zones,
            mounts,
        } => {
            // Matrix rows 3 + 4 — see `plan_boot_action` docstring.
            // Joiner path.  Phase A: `zones` list
            // is empty (rows 3/4 require NEXUS_FEDERATION_ZONES unset).
            // Empty case is a log-only no-op — the daemon comes up
            // with root bootstrapped + transport peer_map seeded (via
            // open_zone_manager's merged-peers path), and zone-level
            // joining continues through the offline `nexusd-cluster
            // join` sidecar.  Phase B populates `zones` from
            // identity.zones so this branch auto-reconnects.
            let (zones, mounts) = if zones.is_empty() && !peers.is_empty() {
                // S3 Phase D: fresh joiner with `--peers` but no
                // identity.zones snapshot yet.  Ask each peer to
                // report its local federation topology via
                // `DiscoverZones` and merge into the auto-join set.
                // First peer to respond with a non-empty list wins —
                // subsequent peers' responses are unioned so a
                // partially-configured founder pair (each half
                // exposing a disjoint zone) still discovers both.
                let mut discovered_mounts: std::collections::BTreeMap<String, String> =
                    std::collections::BTreeMap::new();
                let mut discovered_zone_order: Vec<String> = Vec::new();
                for peer in &peers {
                    match nexus_raft::transport::call_discover_zones_rpc(
                        &peer.endpoint,
                        /* timeout */ 10,
                    )
                    .await
                    {
                        Ok(entries) => {
                            tracing::info!(
                                peer = %peer.endpoint,
                                discovered = entries.len(),
                                "DiscoverZones: peer reported federation zones",
                            );
                            for entry in entries {
                                // Preserve first-response order for
                                // downstream `join_zones_for_boot`
                                // (BTreeMap sorts by path anyway, but
                                // the zones list order matters for
                                // per-zone JoinZone dispatch).
                                if !discovered_mounts.contains_key(&entry.mount_path) {
                                    discovered_zone_order.push(entry.zone_id.clone());
                                }
                                discovered_mounts.insert(entry.mount_path, entry.zone_id);
                            }
                        }
                        Err(e) => tracing::warn!(
                            peer = %peer.endpoint,
                            error = %e,
                            "DiscoverZones: peer unreachable — trying next",
                        ),
                    }
                }
                (discovered_zone_order, discovered_mounts)
            } else {
                (zones, mounts)
            };
            if zones.is_empty() {
                tracing::info!(
                    cli_peer_count = peers.len(),
                    "boot joiner: no federation zones auto-declared and none \
                     reported by peers; daemon up rootless-with-peers. Use \
                     `nexusd-cluster join` sidecar for zone-specific joining, \
                     or wait for a ConfChange apply to populate identity.zones.",
                );
            } else {
                // Phase B row 4: `zones` came from identity.zones.  When CLI
                // --peers was not passed on this boot the daemon still needs
                // *some* addresses to send JoinZone against.  Precedence:
                //   1. CLI --peers (operator override).
                //   2. identity.peers (union widened at prior boot's persist).
                //   3. identity.zones[i].members (populated by the apply cb;
                //      the "wipe took data_dir + peers but the apply cb had
                //      already stamped the members list before" case).
                let peers_for_join = if !peers.is_empty() {
                    peers
                } else {
                    let use_tls = !common.no_tls;
                    let mut seed = identity_persisted_peers.clone();
                    if seed.is_empty() {
                        for z in &identity_zones {
                            for m in &z.members {
                                if !seed.iter().any(|s| s == m) {
                                    seed.push(m.clone());
                                }
                            }
                        }
                    }
                    NodeAddress::parse_peer_list_operator(&seed.join(","), use_tls)
                        .map_err(|e| anyhow::anyhow!("identity peers reparse: {}", e))?
                };
                join_zones_for_boot(
                    zm.clone(),
                    node_id,
                    self_address.clone(),
                    peers_for_join,
                    contracts::ROOT_ZONE_ID.to_string(),
                    common.data_dir.clone(),
                    zones,
                    mounts,
                    /* as_learner */ false,
                )
                .await?;
            }
        }
        nexus_raft::bootstrap::BootAction::FailLoud { reason, hint } => {
            // Matrix rows 5 + 6 — see `plan_boot_action` docstring.
            // Row 5 is unreachable here because the preserved PR #112
            // guard above fires first with a longer hint; row 6 lands
            // here.  Both cases surface as a single exit-1 code path.
            return Err(anyhow::anyhow!(
                "nexusd-cluster boot refused ({reason}): {hint}"
            ));
        }
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
    // Outbound federation-peer typed-RPC client.  Constructed BEFORE
    // the coordinator so it can be passed in via `install_with_kernel`
    // as the grpc_ops arc — single install hook for federation
    // peer dispatch.  Without this the coordinator's `peer_*` impls
    // surface every cross-node dispatch as a silent miss via the
    // PR #94 observability warn-loud path (`grpc_ops not installed`).
    let federation_client: Arc<dyn kernel::federation::grpc_ops::FederationGrpcOps> = Arc::new(
        transport::federation::FederationClient::new(Arc::clone(kernel.runtime()), None),
    );

    // Construct the provider as `Arc<RaftDistributedCoordinator>` so
    // `install_with_kernel` can clone it into the kernel's coordinator
    // slot (the slot type is `Arc<dyn DistributedCoordinator>`).  Once
    // wired, the kernel keeps the provider alive for the lifetime of
    // the kernel — no separate local `_dist_coord` holder needed.
    Arc::new(nexus_raft::distributed_coordinator::RaftDistributedCoordinator::new())
        .install_with_kernel(
            zm.clone(),
            zm.runtime_handle(),
            &self_address,
            &kernel,
            federation_client,
        );

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
    //   2. Federation static-topology bootstrap has staged the
    //      env-listed zones + cross-zone mounts (`NEXUS_FEDERATION_*`)
    //      and `RaftDistributedCoordinator::install_with_kernel` has
    //      just flipped `is_initialized` to true.  That gates the
    //      `kernel.mount(..)` zone-create-on-mount path inside
    //      `sys_setattr DT_MOUNT` — required when the operator names
    //      a separate zone that doesn't yet exist.
    //   3. PeerBlobClient is installed so cross-node fetches on
    //      `last_writer_address` already-replicated bytes have a
    //      transport to ride.
    //   4. **Topology has fully converged** (the drain below).  Without
    //      this gate, `--mount-driver`'s `dlc.mount` call runs while
    //      the env-listed cross-zone mounts (e.g. `/shared=sharedzone`)
    //      are still in `pending_mounts` — `vfs_router.route()` for the
    //      driver's vfs-path then finds only `/` (root) as the parent,
    //      so the DT_MOUNT entry lands in root's metastore (non-
    //      federated, never replicated) instead of the operator-
    //      specified target zone's state machine, and peers joining
    //      later see `count=1` from `replay_existing_mounts` — only
    //      the `/shared` mount itself, not the nested driver mount
    //      operators installed under it.  The single sync drain
    //      collapses the race deterministically.
    //
    // `vfs_path` must be non-`/` (the boot mount owns that point);
    // `zone` is operator-supplied without further constraint — root
    // is the single-canonical node-local case (same-zone routing
    // keeps it strictly local), a separate raft zone is the case
    // operators reach for when extending the mount across peers.

    // Order step (4): drain pending mounts before any driver-mount
    // runs.  `apply_topology_async` is idempotent + crash-safe; when
    // `pending_mounts` is empty (no FEDERATION env, or topology
    // already converged from a prior tick) this is a near-zero-cost
    // no-op.
    if !common.mount_drivers.is_empty() && !zm.pending_mounts().is_empty() {
        // Bounded retry: under contention the leader may not be elected
        // yet on the very first call.  Cap at 30 ticks of TOPOLOGY_TICK
        // so a genuinely stuck topology surfaces a startup error rather
        // than silently dropping driver mounts into the wrong zone.
        let mut converged = false;
        for _ in 0..30 {
            match zm.apply_topology_async(contracts::ROOT_ZONE_ID).await {
                Ok(true) if zm.pending_mounts().is_empty() => {
                    converged = true;
                    break;
                }
                Ok(_) => tokio::time::sleep(TOPOLOGY_TICK).await,
                Err(err) => {
                    tracing::warn!(%err, "apply_topology error during driver-mount drain; retrying");
                    tokio::time::sleep(TOPOLOGY_TICK).await;
                }
            }
        }
        if !converged {
            return Err(anyhow::anyhow!(
                "--mount-driver pre-drain: federation topology did not converge \
                 within 30 ticks; refusing to install driver mounts whose parent \
                 routing would silently land in the wrong zone.  Pending: {:?}",
                zm.pending_mounts(),
            ));
        }
    }

    for raw in &common.mount_drivers {
        let spec = parse_mount_driver_spec(raw)
            .map_err(|e| anyhow::anyhow!("--mount-driver parse error: {e}"))?;

        // `--mount-driver` installs a backend INSIDE a zone.  The zone
        // itself is created elsewhere — via `NEXUS_FEDERATION_ZONES`
        // bootstrap (founder), or via `nexusd-cluster join` (joiner).
        // If the target zone isn't loaded yet, skipping is the correct
        // semantic: re-running the cluster after the operator-driven
        // zone-create / join completes lets the daemon re-attempt the
        // mount with the zone present.
        //
        // The alternative — letting `kernel.mount` fall through to
        // `sys_setattr DT_MOUNT`'s zone-create-on-mount branch — would
        // bootstrap a parallel 1-voter zone on the joiner, diverging
        // from the cluster's authoritative ConfState.  Offline join's
        // `bootstrap_or_join_zone` Branch 1 then short-circuits on the
        // "zone already loaded from persisted storage" check and never
        // dials JoinZone against the founder, leaving the joiner in a
        // solo split-brain that silently passes liveness probes.  Root
        // is the one mountable zone that may legitimately be bootstrapped
        // here (single-node founder default), so it falls through.
        if spec.zone_id != contracts::ROOT_ZONE_ID && zm.get_zone(&spec.zone_id).is_none() {
            tracing::info!(
                driver = %spec.name,
                zone_id = %spec.zone_id,
                vfs_path = %spec.vfs_path,
                "skipping --mount-driver: target zone not loaded on this node — \
                 declare via NEXUS_FEDERATION_ZONES (founder) or run \
                 `nexusd-cluster join` (joiner) to bring the zone in first, \
                 then restart; --mount-driver re-applies on restart",
            );
            continue;
        }

        let backend = kernel
            .make_driver(&spec.name, &spec.config_json)
            .map_err(|e| {
                anyhow::anyhow!(
                    "make_driver({}, …): {e} \
                     (is the dylib in --plugin-dir and was it loaded?)",
                    spec.name,
                )
            })?;

        // Inherit the parent federation mount's `ZoneMetaStore` Arc so
        // this driver mount sees the SAME path-translation anchor as
        // every other surface on the same federated zone.
        //
        // Why: `coordinator.metastore_for_zone(zone)` (the auto-fallback
        // `sys_setattr DT_MOUNT` would take on `(None, None)`) returns
        // a fresh `ZoneMetaStore` rooted at canonical `/<zone_id>` — the
        // raft-internal namespace.  But the federation mount (e.g.
        // `/shared` → sharedzone) installed its own `ZoneMetaStore`
        // rooted at the global path `/shared` via
        // `wire_mount_core::install_metastore`.  Two different mount
        // points = two different `to_zone_key` translations applied to
        // the same state machine — writes through one anchor end up
        // under keys reads through the other never look up.  The
        // smoking-gun symptom: joiner serves bytes + `observe_backend_content`
        // proposes metadata, raft replicates the entry, but founder's
        // `vfs_stat` still reports `found=False` because its lookup
        // translates the path differently from the writer's.
        //
        // The federation mount's metastore is the SSOT for the federated
        // zone's namespace.  Look it up via `vfs_router.route()` against
        // the parent directory (parent of `vfs_path`); the recursive
        // descent (#48) routes through the federation mount and hands
        // back its installed `metastore`.  Pass that exact `Arc` into
        // `MountOptions.with_metastore` so `sys_setattr DT_MOUNT` takes
        // the explicit-metastore branch and skips the auto-fallback
        // entirely.
        //
        // Falls back to no override when the parent route has no
        // metastore (driver mount under a non-federation parent, e.g.
        // root with a `PathLocal` backend): `sys_setattr` will then take
        // its `(None, _) => None` branch as before, which is correct —
        // such mounts route to the kernel's global metastore where
        // `to_zone_key` is a no-op.
        let parent_metastore = {
            let parent_dir = spec
                .vfs_path
                .rsplit_once('/')
                .map(|(p, _)| p)
                .unwrap_or("/");
            let parent_dir = if parent_dir.is_empty() {
                "/"
            } else {
                parent_dir
            };
            kernel
                .vfs_router_arc()
                .route(parent_dir, contracts::ROOT_ZONE_ID)
                .and_then(|r| r.metastore)
        };

        let mut opts = MountOptions::new(&spec.name)
            .with_backend(backend)
            .with_zone(&spec.zone_id);
        if let Some(ms) = parent_metastore {
            opts = opts.with_metastore(ms);
        }
        kernel.mount(&spec.vfs_path, opts).map_err(|e| {
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
    let ZoneManagerBundle {
        zm, cli_peer_addrs, ..
    } = open_zone_manager(&common, None)?;
    let peers_str: Vec<String> = cli_peer_addrs
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

/// Boot-time joiner primitive shared by the offline `join` sidecar
/// (single-zone) and the future daemon federation-branch joiner path
/// (multi-zone from `NEXUS_FEDERATION_MOUNTS` / identity.zones).
///
/// For each zone in `zone_ids`:
///   1. If `parent_zone` is not on disk, bootstrap it as SOLO (empty
///      peers — parent is per-node by design; the DT_MOUNT entry lands
///      in this zone's metastore).  Idempotent: `bootstrap_or_join_zone`
///      Branch 1 resumes when ConfState is on disk.
///   2. `bootstrap_or_join_zone(zone, peers, bootstrap_new=false,
///      max_attempts=Some(15), as_learner)` against the leader.
///   3. If `mounts` maps a `local_path -> zone`, propose the DT_MOUNT
///      entry via `zm.mount_async(parent_zone, local_path, zone, true)`.
///
/// `max_attempts=Some(15)` × `JOIN_ZONE_RETRY_INTERVAL` matches
/// `run_join`'s previous behavior — ~30 s upper bound, long enough to
/// absorb a leader election on the remote, short enough that a stuck
/// boot terminates with a clear error.
///
/// Runs `bootstrap_or_join_zone` inside `tokio::task::spawn_blocking`
/// because that helper spins a nested tokio runtime for its JoinZone
/// RPCs; nested runtime creation panics on a worker thread of the outer
/// `#[tokio::main]` unless we move it onto the blocking pool.
#[allow(
    clippy::too_many_arguments,
    reason = "wraps `bootstrap_or_join_zone` (8 params) plus a data_dir + mounts map \
     without bundling — a Params struct here just re-shuffles the field \
     list without adding a semantic grouping."
)]
async fn join_zones_for_boot(
    zm: Arc<ZoneManager>,
    node_id: u64,
    self_address: String,
    peers: Vec<NodeAddress>,
    parent_zone: String,
    data_dir: PathBuf,
    zone_ids: Vec<String>,
    mounts: std::collections::BTreeMap<String, String>,
    as_learner: bool,
) -> Result<()> {
    let parent_zone_dir = parent_zone_storage_path(&data_dir, &parent_zone);
    let parent_zone_loaded = parent_zone_dir.exists();
    if !parent_zone_loaded {
        tracing::info!(
            parent_zone = %parent_zone,
            data_dir = %data_dir.display(),
            "boot joiner: parent zone not in data dir — bootstrapping as SOLO",
        );
        let zm_for_parent = zm.clone();
        let self_addr_for_parent = self_address.clone();
        let parent_zone_for_bootstrap = parent_zone.clone();
        tokio::task::spawn_blocking(move || {
            nexus_raft::distributed_coordinator::bootstrap_or_join_zone(
                zm_for_parent.as_ref(),
                &parent_zone_for_bootstrap,
                node_id,
                &self_addr_for_parent,
                /* peers */ &[],
                /* bootstrap_new */ false,
                /* max_attempts  */ None,
                /* as_learner */ false,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("boot joiner parent-zone bootstrap task panicked: {}", e))?
        .map_err(|e| {
            anyhow::anyhow!(
                "boot joiner bootstrap_or_join_zone(parent={}): {}",
                parent_zone,
                e
            )
        })?;
    }

    for zone_id in &zone_ids {
        let zm_for_join = zm.clone();
        let self_addr_for_join = self_address.clone();
        let zone_id_for_join = zone_id.clone();
        let peers_for_join = peers.clone();
        tokio::task::spawn_blocking(move || {
            nexus_raft::distributed_coordinator::bootstrap_or_join_zone(
                zm_for_join.as_ref(),
                &zone_id_for_join,
                node_id,
                &self_addr_for_join,
                &peers_for_join,
                /* bootstrap_new */ false,
                /* max_attempts  */ Some(15),
                as_learner,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("boot joiner join task panicked ({zone_id}): {}", e))?
        .map_err(|e| anyhow::anyhow!("bootstrap_or_join_zone({zone_id}): {}", e))?;
    }

    for (local_path, zone_id) in &mounts {
        zm.mount_async(&parent_zone, local_path, zone_id, true)
            .await
            .map_err(|e| anyhow::anyhow!("mount({local_path} -> {zone_id}): {}", e))?;
    }

    Ok(())
}

async fn run_join(
    common: CommonArgs,
    peer_addr: &str,
    remote_zone_id: &str,
    local_path: &str,
    parent_zone: &str,
    as_learner: bool,
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
    // ``as_learner`` is now operator-configurable via ``--as
    // learner|voter`` (default ``learner``):
    //
    //   * **learner** — owner-pattern subtree-mount flow.  The creator
    //     of the shared zone (`share`) is the authoritative voter;
    //     joiners enter as Learners so they receive full replication
    //     but never participate in quorum.  Wipe-rejoin-safe — losing
    //     or replacing a learner has zero impact on the owner's
    //     ability to commit, so SSD swap / OS reinstall / device
    //     migration cannot strand the zone in `not leader` deadlock
    //     (this was the failure that motivated PR #57's Learner
    //     default).  Default because the owner-pattern is the broader
    //     use case.
    //
    //   * **voter** — symmetric-peer pattern (cc-tasks-share-style,
    //     Mac↔Win mutually sharing CC task dirs).  Joiner counts
    //     toward quorum.  Per-write EC routing on sys_setattr means
    //     a voter joiner can still write metadata locally when the
    //     founder is offline (Ec WAL + local apply, async replicate);
    //     only SC writes (locks, CAS) require quorum.  The
    //     wipe-rejoin risk re-emerges if a voter goes through
    //     SSD swap without first transferring its voter slot away —
    //     operator-aware tradeoff.
    //
    // ``max_attempts=Some(15)`` × ``JOIN_ZONE_RETRY_INTERVAL`` (2 s)
    // ≈ 30 s upper bound on the operator command — long enough to
    // absorb a leader election round on the remote, short enough that
    // a stuck command terminates with a clear error rather than
    // hanging forever like the daemon-boot path does.
    let use_tls = !common.no_tls;
    // Operator-facing strict parse: rejects `<id>@host:port`, forces
    // bare `host:port`.  See PeerAddress::parse_operator_addr for the
    // retirement rationale.
    let peer = NodeAddress::parse_operator_addr(peer_addr, use_tls)
        .map_err(|e| anyhow::anyhow!("--peer-addr parse '{}': {}", peer_addr, e))?;
    // Cache the operator peer string (bare `host:port`) before moving
    // `peer_addrs` into the spawn_blocking closure below — identity
    // persistence must round-trip through `parse_operator_addr` on
    // next cold-boot, so we serialize in that form.
    let peer_str_for_identity = peer.to_operator_str();
    let peer_addrs = vec![peer];

    // Delegate to the shared boot-time joiner primitive.  Sidecar
    // semantics = single zone + single mount + parent bootstrap under
    // the run_join contract (parent_zone user-configurable).  The
    // daemon federation-branch will call the same primitive with the
    // multi-zone federation map in a follow-up commit.
    let mut mounts = std::collections::BTreeMap::new();
    mounts.insert(local_path.to_string(), remote_zone_id.to_string());
    join_zones_for_boot(
        zm.clone(),
        node_id,
        self_address.clone(),
        peer_addrs.clone(),
        parent_zone.to_string(),
        common.data_dir.clone(),
        vec![remote_zone_id.to_string()],
        mounts,
        as_learner,
    )
    .await?;

    // Persist the leader address in identity so subsequent daemon
    // restarts (with `--peers` unset — the routine `restart` container
    // mode) still have a transport-layer seed to contact this peer.
    // Without this, every join sidecar would leave identity empty and
    // the daemon's `open_zone_manager` would lose the peer address as
    // soon as the entrypoint script unsets `NEXUS_PEERS` on restart.
    // Merge, not overwrite — identity may already carry other peers
    // from earlier joins.
    let identity_dir = common
        .identity_dir
        .clone()
        .unwrap_or_else(nexus_raft::identity::default_identity_dir);
    let ident = nexus_raft::identity::load(&identity_dir)
        .map_err(|e| anyhow::anyhow!("identity load: {}", e))?;
    nexus_raft::identity::persist_peers(
        &identity_dir,
        &ident,
        std::slice::from_ref(&peer_str_for_identity),
    )
    .map_err(|e| anyhow::anyhow!("identity persist_peers: {}", e))?;

    let role = if as_learner { "learner" } else { "voter" };
    println!(
        "Joined remote zone '{}' as {} (via {}); mounted at '{}' inside zone '{}'; \
         peer '{}' persisted to identity '{}'",
        remote_zone_id,
        role,
        peer_addr,
        local_path,
        parent_zone,
        peer_str_for_identity,
        identity_dir.display(),
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

/// Filesystem path the daemon (and `bootstrap_or_join_zone`) uses to
/// detect whether `<zone_id>` has persisted raft state in `data_dir`.
/// Mirrors the `data_dir_has_root` check in `run_daemon` so the join
/// sidecar's "should I bootstrap this parent zone?" decision aligns
/// with the daemon's later "should I resume from disk?" check.
fn parent_zone_storage_path(data_dir: &std::path::Path, zone_id: &str) -> PathBuf {
    data_dir.join(zone_id).join("raft")
}

fn resolve_hostname(cli: Option<&str>) -> String {
    if let Some(h) = cli {
        return h.to_string();
    }
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// Resolve the address this node advertises to peers as its raft
/// endpoint.  Decouples advertise identity from the display-only
/// `hostname` so cross-machine federation over overlay networks
/// (Tailscale / VPN) can pin the overlay IP independently.
///
/// Precedence:
///   1. `advertise_cli` — explicit `--advertise-addr` / NEXUS_ADVERTISE_ADDR.
///      Empty string treated as unset (operator templating slip-through).
///   2. Fallback `<hostname>:<bind_port>` — matches pre-PR behaviour.
///      Single-node tests work unchanged; cross-machine setups MUST
///      pin advertise_cli to the overlay IP.
///
/// When the resolved address looks unreachable (`0.0.0.0:*`, loopback,
/// or non-IP host with peers configured), warn-loud so the operator
/// sees the misconfiguration in boot logs — the Mac↔Win L1 wedge that
/// motivated this seam manifested as silent "ConfState install timeout
/// after JoinZone success" hours later.
fn resolve_self_address(
    advertise_cli: Option<&str>,
    hostname: &str,
    bind_port: u16,
    peer_count: usize,
) -> String {
    let resolved = match advertise_cli {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => format!("{hostname}:{bind_port}"),
    };
    warn_if_self_address_unreachable(&resolved, peer_count);
    resolved
}

/// Warn-loud when the resolved self_address looks unreachable from
/// peers. Heuristic, not a hard error — single-node tests legitimately
/// bind 0.0.0.0 with no peers, and operators may name a fully-qualified
/// hostname their peers can resolve.
fn warn_if_self_address_unreachable(self_address: &str, peer_count: usize) {
    let (host, _port) = match self_address.rsplit_once(':') {
        Some(parts) => parts,
        None => {
            tracing::warn!(
                target: "nexusd_cluster",
                self_address = %self_address,
                "advertise self_address has no :port — peers cannot dial it; \
                 set --advertise-addr <host>:<port>",
            );
            return;
        }
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host == "0.0.0.0" || host == "::" || host.is_empty() {
        tracing::warn!(
            target: "nexusd_cluster",
            self_address = %self_address,
            "advertise self_address binds wildcard — peers cannot dial it; \
             set --advertise-addr to a reachable host:port",
        );
        return;
    }
    if host == "127.0.0.1" || host == "::1" || host == "localhost" {
        if peer_count > 0 {
            tracing::warn!(
                target: "nexusd_cluster",
                self_address = %self_address,
                peer_count,
                "advertise self_address is loopback while peers are configured — \
                 cross-machine peers cannot reach this node; set --advertise-addr \
                 to the reachable network IP",
            );
        }
        return;
    }
    // Non-IP host with peers configured — likely the OS hostname,
    // which does not resolve through Tailscale/VPN overlays.
    let looks_like_ip = host
        .split('.')
        .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()))
        && host.split('.').count() == 4;
    let looks_like_ipv6 = host.contains(':');
    if !looks_like_ip && !looks_like_ipv6 && peer_count > 0 && !host.contains('.') {
        tracing::warn!(
            target: "nexusd_cluster",
            self_address = %self_address,
            peer_count,
            "advertise self_address is a bare hostname; if peers are on a \
             different machine and reach this node via an overlay (Tailscale, \
             VPN), set --advertise-addr to the overlay IP — bare hostnames \
             rarely resolve across overlays",
        );
    }
}

/// Metastore mode resolved from the environment (#4343).
#[derive(Debug, PartialEq, Eq)]
enum MetastoreMode {
    /// Open a durable redb at this path (the production default).
    Durable(PathBuf),
    /// Keep the kernel's boot tempfile metastore — the namespace dies
    /// with the process. Debug-only escape hatch, must be requested
    /// with the explicit literal `ephemeral`.
    Ephemeral,
}

/// Resolve the durable metastore mode for this node (#4343).
///
/// `override_path` is the `--metastore-path` flag (env:
/// `NEXUS_KERNEL_METASTORE_PATH` — see the arg docs for why it is NOT
/// `NEXUS_METASTORE_PATH`).
///
/// Precedence:
///   * unset → `<data_dir>/metastore.redb` (durable default).
///   * the literal `ephemeral` → tempfile metastore (explicit opt-out).
///   * any other non-empty value → that file path. Relative paths are
///     resolved against `data_dir`, NOT the process cwd — a cwd-relative
///     store would silently re-anchor when a wrapper or restart changes
///     the working directory, which presents as namespace loss.
///   * set but EMPTY → hard error. An empty value usually means broken
///     templating or an unset secret, and silently degrading to the
///     ephemeral store would reintroduce the exact restart data-loss
///     this wiring exists to prevent. Fail closed.
///   * non-UTF-8 values pass through here and fail closed at the
///     explicit UTF-8 check in `wire_durable_metastore`.
fn resolve_metastore_path(
    override_path: Option<&std::path::Path>,
    data_dir: &std::path::Path,
) -> Result<MetastoreMode, String> {
    let Some(p) = override_path else {
        return Ok(MetastoreMode::Durable(data_dir.join("metastore.redb")));
    };
    let anchor = |pb: PathBuf| {
        if pb.is_absolute() {
            pb
        } else {
            data_dir.join(pb)
        }
    };
    match p.to_str().map(str::trim) {
        Some("") => Err(
            "metastore path (--metastore-path / NEXUS_KERNEL_METASTORE_PATH) is set \
             but empty — refusing to guess. Set a file path, or the literal \
             'ephemeral' to explicitly opt into a non-durable metastore (the \
             namespace will NOT survive restarts)."
                .to_string(),
        ),
        Some("ephemeral") => Ok(MetastoreMode::Ephemeral),
        Some(v) => Ok(MetastoreMode::Durable(anchor(PathBuf::from(v)))),
        // Non-UTF-8: anchor as-is; wire_durable_metastore rejects it.
        None => Ok(MetastoreMode::Durable(anchor(p.to_path_buf()))),
    }
}

/// Wire the kernel's durable metastore from the flag/env + data dir
/// (#4343).
///
/// This is the real production wiring `run_daemon` uses — kept as a
/// standalone function so tests can drive the exact same path
/// (resolution, parent-dir creation, `set_metastore_path`) against a
/// temp data dir. Returns the durable path, or `None` in (explicitly
/// requested) ephemeral mode.
fn wire_durable_metastore(
    kernel: &Kernel,
    override_path: Option<&std::path::Path>,
    data_dir: &std::path::Path,
) -> Result<Option<PathBuf>> {
    match resolve_metastore_path(override_path, data_dir).map_err(|e| anyhow::anyhow!(e))? {
        MetastoreMode::Durable(ms_path) => {
            if let Some(parent) = ms_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create metastore dir {}", parent.display()))?;
            }
            let ms_str = ms_path.to_str().context("metastore path must be UTF-8")?;
            kernel.set_metastore_path(ms_str).map_err(|e| {
                anyhow::anyhow!("open durable metastore at {}: {:?}", ms_path.display(), e)
            })?;
            tracing::info!(path = %ms_path.display(), "durable metastore opened (namespace survives restarts)");
            Ok(Some(ms_path))
        }
        MetastoreMode::Ephemeral => {
            tracing::warn!(
                "NEXUS_KERNEL_METASTORE_PATH=ephemeral — tempfile metastore; \
                 the namespace will NOT survive a restart"
            );
            Ok(None)
        }
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
    use clap::Parser;

    /// Pin the operator-facing flag name for the join subcommand's
    /// membership-role selector.  Clap derives `--as-role` by default
    /// from the field name `as_role` (snake-to-kebab); the
    /// `long = "as"` override on the field is what gives the natural
    /// `--as voter` / `--as learner` UX the runbook (and every doc /
    /// commit / downstream test in nexus's federation E2E) refers to.
    ///
    /// A regression that drops or renames the `long = "as"` override
    /// would surface here as a clap parse error.
    #[test]
    fn join_cli_accepts_as_voter_and_as_learner_flags() {
        let parsed_voter = Args::try_parse_from([
            "nexusd-cluster",
            "join",
            "host:2126",
            "sharedzone",
            "/shared",
            "--as",
            "voter",
        ])
        .expect("--as voter must parse");
        match parsed_voter.cmd.expect("join cmd") {
            Cmd::Join { as_role, .. } => assert!(matches!(as_role, JoinRole::Voter)),
            other => panic!("expected Join, got {other:?}"),
        }

        let parsed_learner = Args::try_parse_from([
            "nexusd-cluster",
            "join",
            "host:2126",
            "sharedzone",
            "/shared",
            "--as",
            "learner",
        ])
        .expect("--as learner must parse");
        match parsed_learner.cmd.expect("join cmd") {
            Cmd::Join { as_role, .. } => assert!(matches!(as_role, JoinRole::Learner)),
            other => panic!("expected Join, got {other:?}"),
        }

        // Default (no --as flag) is Voter — symmetric peer is the
        // canonical workload (Mac↔Win cc-tasks-share, corp-zone
        // partition) and aligns the CLI default with the wire-level
        // protocol default (`JoinZoneRequest.as_learner` defaults to
        // `false` under proto3).  Operators wanting owner-pattern
        // semantics opt in with `--as learner`.
        let parsed_default = Args::try_parse_from([
            "nexusd-cluster",
            "join",
            "host:2126",
            "sharedzone",
            "/shared",
        ])
        .expect("default (no --as) must parse");
        match parsed_default.cmd.expect("join cmd") {
            Cmd::Join { as_role, .. } => assert!(matches!(as_role, JoinRole::Voter)),
            other => panic!("expected Join, got {other:?}"),
        }
    }

    /// Bare `host:port` is the preferred `peer_addr` form — operators
    /// no longer sync opaque `node_id` between peers.  Pins the CLI +
    /// docstring contract that `nexusd-cluster join <addr> <zone>
    /// <path>` alone is a valid invocation.  Legacy `<id>@<addr>` form
    /// stays supported (previous test above), so the two forms MUST
    /// both parse to `Cmd::Join`.
    #[test]
    fn join_accepts_bare_host_port_without_explicit_node_id() {
        // Preferred form — no operator id-lookup ceremony.
        let bare = Args::try_parse_from([
            "nexusd-cluster",
            "join",
            "100.64.0.27:2126",
            "sharedzone",
            "/shared",
        ])
        .expect("bare host:port must parse");
        match bare.cmd.expect("join cmd") {
            Cmd::Join {
                peer_addr,
                remote_zone_id,
                local_path,
                as_role,
                parent_zone,
            } => {
                assert_eq!(peer_addr, "100.64.0.27:2126");
                assert_eq!(remote_zone_id, "sharedzone");
                assert_eq!(local_path, "/shared");
                assert_eq!(parent_zone, "root");
                assert!(matches!(as_role, JoinRole::Voter));
            }
            other => panic!("expected Join, got {other:?}"),
        }

        // Hostname form (Docker-compose network alias) — same shape.
        let by_name = Args::try_parse_from([
            "nexusd-cluster",
            "join",
            "founder:2126",
            "sharedzone",
            "/shared",
        ])
        .expect("bare hostname:port must parse");
        match by_name.cmd.expect("join cmd") {
            Cmd::Join { peer_addr, .. } => assert_eq!(peer_addr, "founder:2126"),
            other => panic!("expected Join, got {other:?}"),
        }
    }

    #[test]
    fn metastore_path_defaults_into_data_dir() {
        let p = resolve_metastore_path(None, std::path::Path::new("/data"));
        assert_eq!(
            p,
            Ok(MetastoreMode::Durable(PathBuf::from(
                "/data/metastore.redb"
            )))
        );
    }

    #[test]
    fn metastore_path_flag_overrides() {
        let p = resolve_metastore_path(
            Some(std::path::Path::new("/elsewhere/ms.redb")),
            std::path::Path::new("/data"),
        );
        assert_eq!(
            p,
            Ok(MetastoreMode::Durable(PathBuf::from("/elsewhere/ms.redb")))
        );
    }

    #[test]
    fn metastore_path_relative_flag_resolves_against_data_dir() {
        // A cwd-relative store would silently re-anchor when a wrapper
        // changes the working directory — relative overrides must pin
        // to the data dir instead.
        let p = resolve_metastore_path(
            Some(std::path::Path::new("custom/ms.redb")),
            std::path::Path::new("/data"),
        );
        assert_eq!(
            p,
            Ok(MetastoreMode::Durable(PathBuf::from(
                "/data/custom/ms.redb"
            )))
        );
    }

    #[test]
    fn metastore_path_ephemeral_literal_opts_out() {
        assert_eq!(
            resolve_metastore_path(
                Some(std::path::Path::new("ephemeral")),
                std::path::Path::new("/data")
            ),
            Ok(MetastoreMode::Ephemeral)
        );
    }

    #[test]
    fn metastore_path_empty_flag_fails_closed() {
        // Empty usually means broken templating / unset secret — silently
        // booting ephemeral would reintroduce the #4343 data loss.
        assert!(resolve_metastore_path(
            Some(std::path::Path::new("")),
            std::path::Path::new("/data")
        )
        .is_err());
        assert!(resolve_metastore_path(
            Some(std::path::Path::new("   ")),
            std::path::Path::new("/data")
        )
        .is_err());
    }

    #[test]
    fn wire_durable_metastore_creates_redb_in_data_dir() {
        let td = tempfile::tempdir().expect("tempdir");
        let kernel = Kernel::new();
        let wired = wire_durable_metastore(&kernel, None, td.path()).expect("wire");
        let expect = td.path().join("metastore.redb");
        assert_eq!(wired, Some(expect.clone()));
        assert!(expect.is_file(), "durable redb must exist on disk");
        kernel.release_metastores();
    }

    #[test]
    fn wire_durable_metastore_creates_missing_parent_dirs() {
        let td = tempfile::tempdir().expect("tempdir");
        let nested = td.path().join("deep/nested/ms.redb");
        let kernel = Kernel::new();
        let wired =
            wire_durable_metastore(&kernel, Some(nested.as_path()), td.path()).expect("wire");
        assert_eq!(wired, Some(nested.clone()));
        assert!(nested.is_file());
        kernel.release_metastores();
    }

    #[test]
    fn wire_durable_metastore_empty_env_refuses_to_boot() {
        let td = tempfile::tempdir().expect("tempdir");
        let kernel = Kernel::new();
        assert!(
            wire_durable_metastore(&kernel, Some(std::path::Path::new("")), td.path()).is_err()
        );
    }

    #[test]
    fn wire_durable_metastore_ephemeral_keeps_boot_store() {
        let td = tempfile::tempdir().expect("tempdir");
        let kernel = Kernel::new();
        let wired =
            wire_durable_metastore(&kernel, Some(std::path::Path::new("ephemeral")), td.path())
                .expect("wire");
        assert_eq!(wired, None);
        assert!(!td.path().join("metastore.redb").exists());
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

    // ── --advertise-addr decoupling tests (symmetric-peer PR) ────────

    #[test]
    fn advertise_addr_explicit_wins() {
        // Cross-machine federation: advertise pins Tailscale IP
        // independently of OS hostname.
        let resolved =
            resolve_self_address(Some("100.64.0.27:2126"), "win", 2126, /* peers */ 1);
        assert_eq!(resolved, "100.64.0.27:2126");
    }

    #[test]
    fn advertise_addr_empty_string_falls_back() {
        // Operator templating slip-through (envsubst with unset variable)
        // produces empty string — fall back to hostname:port rather than
        // advertising literal "".
        let resolved = resolve_self_address(Some("   "), "myhost", 9000, 0);
        assert_eq!(resolved, "myhost:9000");
    }

    #[test]
    fn advertise_addr_unset_falls_back_to_hostname_port() {
        let resolved = resolve_self_address(None, "single-node", 2126, 0);
        assert_eq!(resolved, "single-node:2126");
    }

    #[test]
    fn advertise_addr_overrides_distinct_port_from_bind() {
        // operator binds 0.0.0.0:2126 but advertises an externally
        // reachable port (port-forward / load-balancer scenarios).
        let resolved = resolve_self_address(Some("public.example.com:443"), "internal", 2126, 1);
        assert_eq!(resolved, "public.example.com:443");
    }

    // ── parent_zone_storage_path tests ────────────────────────────────

    #[test]
    fn parent_zone_storage_path_matches_run_daemon_check() {
        // The join sidecar's "should I bootstrap parent_zone?" gate
        // MUST point at the same path run_daemon uses to detect
        // `data_dir_has_root` — otherwise the two sides of the
        // contract drift and one re-creates state the other expects
        // to load.
        let data_dir = std::path::Path::new("/data");
        assert_eq!(
            parent_zone_storage_path(data_dir, "root"),
            PathBuf::from("/data/root/raft"),
            "parent zone storage path must match the run_daemon \
             data_dir_has_root probe (<data_dir>/<zone>/raft)",
        );
        assert_eq!(
            parent_zone_storage_path(data_dir, "sharedzone"),
            PathBuf::from("/data/sharedzone/raft"),
        );
    }

    // ── --advertise-addr CLI surface tests ────────────────────────────

    #[test]
    fn join_cli_accepts_advertise_addr_flag() {
        // The cross-machine fix flow: operator passes both --hostname
        // (display label) and --advertise-addr (network identity).
        let parsed = Args::try_parse_from([
            "nexusd-cluster",
            "--hostname",
            "macos",
            "--advertise-addr",
            "100.64.0.21:2126",
            "join",
            "host:2126",
            "sharedzone",
            "/shared",
        ])
        .expect("--advertise-addr must parse on join subcommand");
        assert_eq!(
            parsed.common.advertise_addr.as_deref(),
            Some("100.64.0.21:2126"),
            "advertise_addr global flag must be visible to join",
        );
        assert_eq!(
            parsed.common.hostname.as_deref(),
            Some("macos"),
            "hostname stays a separate field, not overloaded",
        );
    }

    #[test]
    fn daemon_cli_accepts_advertise_addr_flag() {
        // Daemon mode (no subcommand) also accepts the global flag.
        let parsed = Args::try_parse_from([
            "nexusd-cluster",
            "--advertise-addr",
            "100.64.0.27:2126",
            "--bootstrap-mode",
            "static",
        ])
        .expect("--advertise-addr must parse on daemon mode");
        assert_eq!(
            parsed.common.advertise_addr.as_deref(),
            Some("100.64.0.27:2126"),
        );
    }
}
