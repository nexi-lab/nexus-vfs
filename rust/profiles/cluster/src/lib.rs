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
//!   * `nexusd-cluster serve-local` — start a loopback-only trusted local backend
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

mod auth_posture;
use auth_posture::{AuthPosture, AuthPostureInputs};
use kernel::abc::object_store::ObjectStore;
use kernel::hal::object_store_provider::set_provider;
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::Kernel;

use nexus_raft::distributed_coordinator::{
    bootstrap_or_join_zone, peers_excluding_self, read_or_mint_node_id,
};
use nexus_raft::federation::{parse_federation_env, ENV_FEDERATION_MOUNTS, ENV_FEDERATION_ZONES};
use nexus_raft::transport::{bootstrap_tls, NodeAddress};
use nexus_raft::{TlsFiles, ZoneLoadPolicy, ZoneManager};

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

    /// Additional loopback-only VFS bind for LOCAL agents, in `host:port`
    /// form (e.g. `127.0.0.1:2130`).
    ///
    /// `--bind-addr` serves cluster PEERS over mTLS — the node/peer plane,
    /// `agent_id = None`. A local agent (sudocode-host or an AI runtime on
    /// THIS host) instead reaches the same kernel through this loopback
    /// bind and authenticates with an `sk-` Agent key (the token plane), so
    /// its mailbox writes carry an unforgeable `agent_id` that the A2A stamp
    /// hook turns into `from`. mTLS ⊥ token: the two identity planes live on
    /// separate binds by audience (remote peers vs. local agents).
    ///
    /// Requires `NEXUS_API_KEY_SECRET` (the token plane) and refuses a
    /// non-loopback address — a bearer token over plaintext must never
    /// leave the host.
    #[arg(long, env = "NEXUS_AGENT_BIND_ADDR", global = true)]
    agent_bind_addr: Option<String>,

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

    /// Serve without authenticating anyone: every caller, including one
    /// presenting no token at all, becomes a system admin on this node's VFS.
    ///
    /// You do NOT need this on loopback — a plaintext, tokenless daemon bound
    /// to 127.0.0.1 is a trusted local backend and starts without any flag.
    /// This exists for the case that would otherwise refuse to boot: an
    /// unauthenticated socket on a REACHABLE address. Appropriate for a CI or
    /// docker-compose cluster that is already wide open; never for anything
    /// holding real data.
    ///
    /// It is a flag rather than a default because "wide open" should be
    /// something a deployment says out loud, in a place a reader can grep for.
    #[arg(
        long,
        env = "NEXUS_INSECURE_NO_AUTH",
        default_value_t = false,
        global = true
    )]
    insecure_no_auth: bool,

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

/// `auth` actions. Split out of [`Cmd`] so the feature gate lands on one
/// arm rather than three.
#[derive(Debug, Subcommand)]
enum AuthCmd {
    /// Mint a key and print it. This is the only time it exists in the clear.
    Mint {
        /// What the key authenticates: `user`, `agent`, or `service`.
        ///
        /// `agent` is the one that matters for A2A: an agent key's subject
        /// becomes the context's `agent_id`, which is the identity the mailbox
        /// hook stamps into an envelope's `from`. Nothing else can author that
        /// agent's mail.
        #[arg(long, default_value = "agent")]
        subject_type: String,
        /// The principal — an agent name, a user id, a service name.
        #[arg(long)]
        subject_id: String,
        /// Zone grant, repeatable: `--zone sharedzone:rw --zone eng:r`.
        ///
        /// A key with no zone grants reaches nothing, and is refused at
        /// authentication time unless it is `--admin` — otherwise it would
        /// fall through to the root zone and hold the whole namespace.
        #[arg(long = "zone", value_name = "ZONE:PERMS")]
        zones: Vec<String>,
        /// Global admin. The only principal allowed to hold a zoneless key.
        #[arg(long)]
        admin: bool,
        /// Expire the key this many days from now. Omit for a key that
        /// never expires.
        #[arg(long)]
        expires_in_days: Option<u64>,
        /// Human label for the audit view ("mac-ai laptop", "ci runner").
        #[arg(long, default_value = "")]
        name: String,
        /// Add a second key for a subject that already holds one — key
        /// rotation, or an extra credential for the same agent. Without it,
        /// minting a subject that already has an active key is refused: an
        /// identity is unique cluster-wide, so two holders cannot claim one
        /// `agent_id` (the `from` guarantee).
        #[arg(long)]
        allow_existing: bool,
    },
    /// Revoke a key. Takes the key itself, or its hash from `auth list`.
    Revoke {
        /// The `sk-` key, if you hold it.
        #[arg(long, conflicts_with = "key_hash")]
        key: Option<String>,
        /// The key's hash, as shown by `auth list` — the shape an admin uses,
        /// working from the audit view rather than from a key they do not have.
        #[arg(long, conflicts_with = "key")]
        key_hash: Option<String>,
    },
    /// List every credential: hash, subject, zones, expiry.
    List,
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
    /// Mint, revoke and list `sk-` API keys.
    ///
    /// The `useradd` / `passwd` of this system, and offline for the same
    /// reason: a key is a credential, not a network resource. The daemon must
    /// be STOPPED — this opens the same data directory it holds an exclusive
    /// lock on.
    ///
    /// A key exists in the clear exactly once, in the output of `mint`. What
    /// lands in the store is its HMAC, so a lost key is reissued, never
    /// recovered. `NEXUS_API_KEY_SECRET` must match the daemon's, or the
    /// hashes will not line up and the key will authenticate as nobody.
    Auth {
        #[command(subcommand)]
        action: AuthCmd,
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
    /// Run a loopback-only daemon: a trusted local backend.
    ///
    /// Shorthand for `--bind-addr 127.0.0.1:<port> --no-tls`. Binding
    /// loopback and serving plaintext is exactly the posture the boot
    /// auth gate (`auth_posture.rs`) recognises as a trusted local
    /// backend, so it starts WITHOUT `--insecure-no-auth`.
    ///
    /// This is the ONE mode the embedding products (sudowork / moss /
    /// sudocode) use to spawn a private per-process nexus backend. It
    /// exists so the loopback + no-tls invariant lives in the binary
    /// instead of being hand-written — and drifting — at each spawn
    /// site (the `--bootstrap-mode` breakage that hit all three at once
    /// is the failure mode this closes).
    ///
    /// Runs the daemon like the default (no-subcommand) invocation —
    /// same long-running gRPC server, same stdout log routing. The usual
    /// global flags (`--data-dir`, `--root-fs`, `--metastore-path`, …)
    /// apply; `--bind-addr` and `--no-tls` are forced here and any
    /// values passed for them are ignored.
    ServeLocal {
        /// Loopback port to bind (`127.0.0.1:<port>`).
        #[arg(long, default_value_t = 2126)]
        port: u16,
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

/// Library entry point shared by `nexusd-cluster` and `nexusd-full`.
///
/// Both `profiles/cluster/src/main.rs` and `profiles/full/src/main.rs`
/// are 3-line binaries that just call this function. The per-binary
/// difference is which `backends` features Cargo activated via feature
/// unification — cluster gets `driver-path-local + driver-remote`,
/// full adds `driver-s3` on top. `DefaultObjectStoreProvider` reads
/// which arms compiled in and dispatches accordingly.
pub fn run() -> Result<()> {
    let args = Args::parse();
    // Held until this function returns so the non-blocking log writer
    // thread stays alive and flushes on shutdown. Subcommands log to
    // stderr — their stdout is data a caller captures. `serve-local` is
    // a daemon, not a data-emitting subcommand, so it logs to stdout
    // like the default (no-subcommand) daemon.
    let is_daemon = matches!(args.cmd, None | Some(Cmd::ServeLocal { .. }));
    let _tracing_guard = install_tracing(/* logs_to_stderr */ !is_daemon);
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
                Some(Cmd::ServeLocal { port }) => {
                    // Force the trusted-local-backend posture: loopback
                    // bind + plaintext. auth_posture then grants the
                    // no-auth start without `--insecure-no-auth`.
                    let mut common = args.common;
                    common.bind_addr = format!("127.0.0.1:{port}");
                    common.no_tls = true;
                    run_daemon(common).await
                }
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
                Some(Cmd::Auth { action }) => run_auth(args.common, action).await,
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
            // Operator CLI dials plaintext (parsed with use_tls=false above);
            // mTLS support here would load the node's on-disk TLS bundle from
            // <data_dir>/tls/ — a separate follow-up, not a boot-path caller.
            None,
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
    load_policy: ZoneLoadPolicy,
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

    // Exclude self from the peer address book — warn, don't crash. Self is
    // never a transport peer (it joins via bootstrap / AddNode, PR #3996
    // opaque-ID contract). A self-entry can appear from an operator listing
    // self OR a stale learned entry that survived in the persisted identity;
    // hard-failing on it would BRICK a restart (the daemon could never boot
    // again without hand-editing identity.json). Filter on the MERGED set so
    // both sources are handled. Raft membership (ConfState) is untouched.
    let merged_peer_addrs = peers_excluding_self(&merged_peer_addrs, &self_address);
    let merged_peers_str: Vec<String> = merged_peer_addrs
        .iter()
        .map(NodeAddress::to_raft_peer_str)
        .collect();

    let zm = ZoneManager::with_node_id_opts(
        &hostname,
        node_id,
        &zones_dir,
        merged_peers_str,
        &common.bind_addr,
        tls,
        Some(self_address.clone()),
        extra_grpc_services,
        load_policy,
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

/// Resolve `--agent-bind-addr` into a bind address, fail-closed.
///
/// The local-agent bind exists to give a local agent an `agent_id` via the
/// token plane (`sk-` Agent key) — mTLS ⊥ token, the two identity planes on
/// separate binds by audience (auth-doc §3.1 / §4.1). So it is only legal
/// when:
///   * the token plane is on (`NEXUS_API_KEY_SECRET` set) — a NoAuth agent
///     bind resolves every caller as nobody and could never stamp a `from`;
///   * the address is loopback — it carries bearer tokens over plaintext, so
///     a reachable bind would leak them off-host (the exact reachable-plaintext
///     hole the boot posture forbids, §3).
///
/// Returns `Ok(None)` when the flag is unset (no local-agent bind), or the
/// parsed `SocketAddr` when the posture is legal.
fn resolve_agent_bind(
    agent_bind: Option<&str>,
    token_plane_on: bool,
) -> Result<Option<std::net::SocketAddr>> {
    let Some(agent_bind) = agent_bind else {
        return Ok(None);
    };
    if !token_plane_on {
        return Err(anyhow::anyhow!(
            "--agent-bind-addr requires NEXUS_API_KEY_SECRET: the local-agent bind \
             authenticates on the token plane (sk- Agent key → agent_id); without a \
             secret every caller resolves as nobody and no `from` could be stamped"
        ));
    }
    if !auth_posture::is_loopback_bind(agent_bind) {
        return Err(anyhow::anyhow!(
            "--agent-bind-addr must be a loopback address (127.0.0.1:<port>); got \
             '{agent_bind}'. It carries bearer tokens over plaintext and must never \
             be reachable off-host"
        ));
    }
    let addr = agent_bind
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("--agent-bind-addr parse '{agent_bind}': {e}"))?;
    Ok(Some(addr))
}

async fn run_daemon(common: CommonArgs) -> Result<()> {
    let hostname = resolve_hostname(common.hostname.as_deref());
    tracing::info!(
        hostname = %hostname,
        bind = %common.bind_addr,
        data_dir = %common.data_dir.display(),
        "nexusd-cluster starting (daemon mode)",
    );

    // S3 Phase G: single boot decision layer.  No more explicit
    // `--bootstrap-mode` from the operator — the daemon reads the
    // authoritative signals (`data_dir_has_root`, identity contents,
    // CLI `--peers`, NEXUS_FEDERATION_* env) and dispatches through
    // `plan_boot_action`.  See `nexus_raft::bootstrap` for the full
    // decision matrix.
    let data_dir_has_root = common.data_dir.join("root").join("raft").exists();
    let peers_non_empty = common.peers.split(',').any(|s| !s.trim().is_empty());
    tracing::info!(
        peers_non_empty,
        data_dir_has_root,
        "boot inputs — see nexus_raft::bootstrap::plan_boot_action for dispatch",
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
    // port via ZoneManager.
    //
    // The `AuthProvider` slot is where a deployment decides *who* its callers
    // are, and it is a RUNTIME decision, not a build-time one: nobody ships a
    // different `sshd` for a trusted network, they configure it. One binary,
    // one gate, and the security posture is a property of the deployment.
    let api_key_auth = match auth_posture(&common)? {
        AuthPosture::ApiKey(secret) => {
            // Reads the kernel's §3.B.3 slot per lookup, so the provider can be
            // built here — before the zones bootstrap and the root zone's
            // consensus exists — and starts resolving the moment the boot path
            // installs `RaftAuthKeyStore` below. Until then the slot holds
            // `NoopAuthKeyStore`, so an early request authenticates as nobody
            // rather than as everybody.
            let store = auth::KernelSlotStore::new_arc(Arc::clone(&kernel));
            Some(Arc::new(auth::ApiKeyAuthProvider::new(store, secret)))
        }
        AuthPosture::Open => None,
    };

    let vfs_auth: Arc<dyn transport::auth::AuthProvider> = match &api_key_auth {
        Some(provider) => Arc::clone(provider) as _,
        None => Arc::new(transport::auth::NoAuth),
    };

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
    } = open_zone_manager(&common, Some(vfs_routes), ZoneLoadPolicy::All)?;

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
    // one sentence.
    //
    // S3 Phase G: gated on `!data_dir_has_root` because a restart with
    // authoritative persisted state is not a split-brain — the daemon
    // resumes from disk and env vars are advisory (row 0 Resume).
    if (!fed.zones.is_empty() || !fed.mounts.mounts.is_empty())
        && !identity_persisted_peers.is_empty()
        && !data_dir_has_root
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

    // S3 Phase G: single boot decision layer.  `plan_boot_action`
    // is the SSOT for what this daemon does at boot — no more
    // `--bootstrap-mode` operator declaration, no more
    // `NEXUS_BOOTSTRAP_NEW`.  See `nexus_raft::bootstrap` for the
    // decision matrix.
    let boot_cfg = nexus_raft::bootstrap::BootConfig {
        identity_persisted_peers: identity_persisted_peers.clone(),
        cli_peer_addrs: cli_peer_addrs.clone(),
        federation_zones: fed.zones.clone(),
        federation_mounts: fed.mounts.mounts.clone(),
        bootstrap_new: false, // retired knob; kept on struct for backwards struct-literal compat
        has_disk_state: data_dir_has_root,
        identity_zones: identity_zones.clone(),
    };
    let boot_action = nexus_raft::bootstrap::plan_boot_action(&boot_cfg);

    // Root zone bootstrap gate — the planner already decided this. The kernel
    // owns root unconditionally: it is the node's own SOLO one-voter raft
    // group, not a federation concept, so every boot that is not aborting
    // brings it up. That is what gives everything raft-backed a home whether
    // or not the operator federates — DT_MOUNT entries, the share registry,
    // WAL streams and pipes, credential records. `bootstrap_or_join_zone`
    // handles both branches internally (Branch 1 = resume from disk,
    // Branch 2 = fresh SOLO create).
    let root_needed = boot_action.needs_root_zone();
    if root_needed {
        let zm_for_root = zm.clone();
        let self_addr_for_root = self_address.clone();
        tokio::task::spawn_blocking(move || {
            bootstrap_or_join_zone(
                zm_for_root.as_ref(),
                "root",
                node_id,
                &self_addr_for_root,
                &[], // root is per-node SOLO — no peers by contract
                /* bootstrap_new */ false,
                /* max_attempts  */ None,
                /* as_learner    */ false,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("root bootstrap task panicked: {}", e))?
        .map_err(|e| anyhow::anyhow!("bootstrap_or_join_zone(root): {}", e))?;
    } else {
        tracing::info!(
            "daemon up rootless — no federation zones to auto-boot; \
             operator drives create_zone via runtime API",
        );
    }

    match boot_action {
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
            // S3 Phase D + F: the DiscoverZones RPC reads root's
            // DT_MOUNT entries directly at call time (Phase F SSOT
            // tightening), so no eager cache set is needed here — the
            // `mounts` map ends up in raft state via
            // `bootstrap_static_async` and gets served fresh on every
            // DiscoverZones call.
            zm.bootstrap_static_async(zones, peers_for_ha, mounts)
                .await
                .map_err(|e| anyhow::anyhow!("bootstrap_static: {}", e))?;
        }
        nexus_raft::bootstrap::BootAction::JoinFederationZones {
            peers,
            zones,
            as_learner_per_zone,
            mounts,
        } => {
            // Matrix rows 3 + 4 — see `plan_boot_action` docstring.  Joiner
            // path, two sub-cases:
            //   (A) `zones` empty (no identity.zones snapshot yet) →
            //       re-derive the topology from `--peers` via
            //       `reconcile_federation_from_peers` (DiscoverZones).  The
            //       empty/empty case (no zones, no peers) falls out as a
            //       reconciled=0 log-only no-op: the daemon comes up
            //       rootless-with-peers and zone joining continues via the
            //       offline `nexusd-cluster join` sidecar or a later
            //       ConfChange apply that populates identity.zones.
            //   (B) `zones` came from identity.zones (Phase B reconnect) →
            //       join those directly.
            if zones.is_empty() {
                let reconciled = reconcile_federation_from_peers(
                    zm.clone(),
                    node_id,
                    self_address.clone(),
                    common.data_dir.clone(),
                    peers,
                )
                .await?;
                if reconciled == 0 {
                    tracing::info!(
                        "boot joiner: no federation zones auto-declared and none \
                         reported by peers; daemon up rootless-with-peers. Use \
                         `nexusd-cluster join` sidecar for zone-specific joining, \
                         or wait for a ConfChange apply to populate identity.zones.",
                    );
                }
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
                assert_eq!(
                    as_learner_per_zone.len(),
                    zones.len(),
                    "Phase H parallel-vec invariant broken by BootAction dispatch",
                );
                join_zones_for_boot(
                    zm.clone(),
                    node_id,
                    self_address.clone(),
                    peers_for_join,
                    contracts::ROOT_ZONE_ID.to_string(),
                    common.data_dir.clone(),
                    zones,
                    mounts,
                    as_learner_per_zone,
                )
                .await?;
            }
        }
        nexus_raft::bootstrap::BootAction::Resume => {
            // Row 0 (Phase G) — see `plan_boot_action` docstring.
            // `data_dir_has_root=true` dominates: root was resumed above via
            // `bootstrap_or_join_zone` Branch 1, and every zone with persisted
            // redb state rehydrates on its own.  raft ConfState on disk is
            // authoritative for zone MEMBERSHIP.
            //
            // But a federation MOUNT (`/agents -> sharedzone`) is NOT raft
            // state — it is LOCAL DERIVED state cached from a peer's
            // `DiscoverZones` topology (the SSOT).  A joiner dropped mid-join
            // (after "Zone registered" but before `mount_async` persisted the
            // DT_MOUNT into its solo root) resumes with the zone fully
            // replicated yet the mount MISSING → `/agents/*` unroutable.  So
            // re-derive federation mounts from peers on every boot — the
            // `mount -a` model — idempotently (see
            // `reconcile_federation_from_peers`).  Peer precedence mirrors the
            // Join branch: CLI --peers → identity.peers → identity.zones[].members.
            let use_tls = !common.no_tls;
            let mut seed: Vec<String> = if !cli_peer_addrs.is_empty() {
                cli_peer_addrs
                    .iter()
                    .map(NodeAddress::to_operator_str)
                    .collect()
            } else {
                identity_persisted_peers.clone()
            };
            if seed.is_empty() {
                for z in &identity_zones {
                    for m in &z.members {
                        if !seed.iter().any(|s| s == m) {
                            seed.push(m.clone());
                        }
                    }
                }
            }
            let resume_peers = if seed.is_empty() {
                Vec::new()
            } else {
                let parsed = NodeAddress::parse_peer_list_operator(&seed.join(","), use_tls)
                    .map_err(|e| anyhow::anyhow!("resume peers reparse: {}", e))?;
                peers_excluding_self(&parsed, &self_address)
            };
            let reconciled = reconcile_federation_from_peers(
                zm.clone(),
                node_id,
                self_address.clone(),
                common.data_dir.clone(),
                resume_peers,
            )
            .await?;
            tracing::info!(
                fed_zones_env = ?fed.zones,
                fed_mounts_env_count = fed.mounts.mounts.len(),
                reconciled_zones = reconciled,
                "boot resumed from disk — federation mounts reconciled from peers (mount -a model)",
            );
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
    // ONE trust anchor for every outbound cluster-mTLS peer client.
    //
    // Both the federation fan-out (`FederationClient`) and the blob fetch
    // (`PeerBlobClient`) ride the cluster's raft-port mTLS: a fan-out RPC sends
    // an empty `auth_token`, so the ONLY thing that authenticates it is this
    // node cert (the peer plane), and `ReadBlob` is co-located on the same
    // `ZoneApiService`. A client left without this cert material dials the peer
    // in plaintext and the mTLS server closes the connection. Read the SSOT
    // (the zone registry's resolved TLS) ONCE here and arm every such client
    // from it, so a new peer client is wired in one obvious place instead of
    // each site remembering its own `install_tls`. `None` under `--no-tls`
    // correctly leaves the clients plaintext.
    let cluster_tls = zm.registry().tls_config();

    // Outbound federation-peer typed-RPC client.  Constructed BEFORE
    // the coordinator so it can be passed in via `install_with_kernel`
    // as the grpc_ops arc — single install hook for federation
    // peer dispatch.  Without this the coordinator's `peer_*` impls
    // surface every cross-node dispatch as a silent miss via the
    // PR #94 observability warn-loud path (`grpc_ops not installed`).
    let federation_client: Arc<dyn kernel::federation::grpc_ops::FederationGrpcOps> =
        Arc::new(transport::federation::FederationClient::new(
            Arc::clone(kernel.runtime()),
            cluster_tls.clone(),
        ));

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
    // Arm the blob client from the same `cluster_tls` SSOT read above (see the
    // "ONE trust anchor" note) — `ReadBlob` over mTLS otherwise dials plaintext
    // and the server closes the connection.
    if let Some(tls) = &cluster_tls {
        kernel
            .peer_client_arc()
            .install_tls(&tls.ca_pem, Some(&tls.cert_pem), Some(&tls.key_pem));
        tracing::info!("peer-blob client armed with cluster mTLS (ReadBlob over TLS)");
    }

    // Auth-key store (Control-Plane HAL §3.B.3) + the cache eviction that
    // makes a revocation take effect without waiting out a TTL.
    //
    // Bound to the ROOT zone's consensus: credentials are a cluster-wide
    // namespace, so a key minted on one node has to resolve on every node,
    // and it is the record's own zone grants — not the zone it happens to
    // be stored in — that decide what it may reach.
    //
    // The store is bound REGARDLESS of the auth posture. It costs one Arc, the
    // root zone always exists, and it is what lets `/__sys__/auth/keys/` answer
    // and an operator mint keys on a daemon that is not yet authenticating —
    // the usual order of operations when turning auth on for the first time.
    // Only the cache-eviction observer is conditional, because only a provider
    // has a cache.
    {
        let root_zone = zm.get_zone(contracts::ROOT_ZONE_ID).ok_or_else(|| {
            anyhow::anyhow!(
                "root zone is not open — the credential store has no consensus to                  live in. This should be impossible: the kernel owns root                  unconditionally (see BootAction::needs_root_zone)."
            )
        })?;
        let consensus = root_zone.consensus_node();
        let store = nexus_raft::auth_key_store::RaftAuthKeyStore::new_arc(
            consensus.clone(),
            root_zone.runtime_handle(),
        );
        kernel.set_auth_key_store(store);

        match &api_key_auth {
            Some(provider) => {
                // Revocation propagates because the command replicates:
                // `DeleteAuthKey` commits, every replica applies it, and every
                // replica's observer fires — so a key revoked on one node stops
                // resolving on all of them without a restart and without waiting
                // out the cache TTL. Keyed on the command variant rather than a
                // path, since credentials are not files.
                let provider_for_evict = Arc::clone(provider);
                consensus.register_apply_observer(Arc::new(
                    move |entry: &nexus_raft::prelude::AppliedEntry| {
                        let key_hash = match entry.command {
                            nexus_raft::prelude::Command::PutAuthKey { key_hash, .. }
                            | nexus_raft::prelude::Command::DeleteAuthKey { key_hash } => key_hash,
                            _ => return,
                        };
                        provider_for_evict.invalidate(key_hash);
                    },
                ));
                tracing::info!("sk- API-key auth armed (credential store bound to the root zone)");
            }
            None => {
                tracing::info!(
                    "credential store bound to the root zone; no auth provider is                      installed, so nothing resolves against it yet"
                );
            }
        }
    }

    // ── A2A messaging substrate (§F) ─────────────────────────────────
    // (1) Arm the mailbox `from`-stamp hook ONCE (the "a2a" hook-only
    // service — first boot-enlisted service). Fail-closed posture is tied
    // to auth: only when an auth provider is armed (`api_key_auth`) does a
    // mailbox write REQUIRE an agent identity. Under NoAuth every write has
    // an empty `agent_id`, so fail-closed would reject all mailbox writes —
    // hence gated. Behaviour-preserving under NoAuth: empty `agent_id` ⇒
    // fail-open ⇒ the policy returns None ⇒ no rewrite.
    let a2a_fail_closed = api_key_auth.is_some();
    a2a::install_a2a_stamp_hook(&kernel, a2a_fail_closed)
        .map_err(|e| anyhow::anyhow!("arm a2a stamp hook: {e}"))?;

    // (2) Arm the cross-machine stream-wakeup observer PER ZONE: a
    // replicated `AppendStreamEntry` (a chat-with-me DT_STREAM write on a
    // peer) wakes a `sys_watch` parked on this replica. The observer is a
    // generic raft primitive (`nexus_raft::stream_wakeup`), armed here —
    // NOT in a2a — because it needs a `Weak<Kernel>` (the `Arc` lives
    // here). It self-recovers the watched path from the wal-stream key, so
    // no per-zone mapping is threaded in. Root covers node-local
    // `/agents`; every federation mount (`NEXUS_FEDERATION_MOUNTS=
    // /agents=<zone>`) is what makes A2A cross-machine, because that zone's
    // raft replicates the mailbox across members — and the wal DT_STREAM
    // for a mailbox under that mount now proposes to THAT zone (see
    // `setattr_stream`'s path-zone resolution), so the append actually
    // reaches peers. These zones were created/joined by the BootAction
    // block above, so they are loaded now; a zone joined at runtime after
    // boot is a documented follow-up.
    {
        // Arm on every zone this node participates in — root plus every
        // federation zone created or joined by the BootAction block above.
        // The wakeup is a property of raft-consensus membership, NOT of
        // `NEXUS_FEDERATION_MOUNTS`: a JOINER reaches its shared zones via
        // DiscoverZones / identity.zones with the mounts env EMPTY (a
        // non-empty mounts env alongside `--peers` is a fail-loud ambiguous
        // boot — see `plan_boot_action` row 6), so keying off the env mounts
        // would arm root only and silently drop the joiner's shared mailbox
        // zone. `ZoneManager::list_zones` is the SSOT for loaded zones.
        // (A zone joined at RUNTIME, after this point — via a `share`/`join`
        // sidecar — is still a documented follow-up.)
        let mut wakeup_zone_ids: std::collections::BTreeSet<String> =
            zm.list_zones().into_iter().collect();
        wakeup_zone_ids.insert(contracts::ROOT_ZONE_ID.to_string());
        for zone_id in wakeup_zone_ids {
            match zm.get_zone(&zone_id) {
                Some(zone) => {
                    // The observer self-recovers the watched file path from
                    // the wal-stream entry key — no per-zone mapping needed.
                    nexus_raft::stream_wakeup::install_stream_wakeup_observer(
                        &zone.consensus_node(),
                        Arc::downgrade(&kernel),
                    );
                    tracing::info!(zone_id = %zone_id, "a2a stream-wakeup observer armed");
                }
                None => {
                    tracing::warn!(
                        zone_id = %zone_id,
                        "a2a stream-wakeup: zone not loaded at arming time; skipped"
                    );
                }
            }
        }
    }

    // Post-transport substrate observability — dual of the peer-blob
    // installation just above.  peer_blob is what performs cross-node
    // fetches; transport_observer classifies which substrate path each
    // fetch actually took (Tailscale direct vs DERP relay vs unknown)
    // and warns operators when their bytes traverse a third-party
    // relay.  Both installed as part of the same transport-tier boot
    // step so the observer is armed before the first cross-node fetch
    // can fire.  `install` spawns a background thread that polls
    // `tailscale status --json` every 30s; the poll silently no-ops
    // when tailscale is absent, so this call is safe on non-federated
    // dev boxes.
    transport::transport_observer::install(&kernel);
    tracing::info!(
        target: "nexusd_cluster",
        "transport_observer armed — distributed-VFS substrate-path warning \
         (30s Tailscale poll; TransportPolicy::Warn on Relay/Unknown)"
    );

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

        // Passthrough connectors reference a host directory that content
        // reaches out-of-band (e.g. `cc` writing task JSON directly,
        // bypassing sys_write). Arm kernel-side metadata sync so the
        // metastore stays authoritative for that content and peers see it
        // via raft-replicated `metastore.list`. Gated on the connector
        // driver — content-owning backends (CAS/S3) publish metadata
        // through sys_write and don't opt in.
        if matches!(spec.name.as_str(), "local-connector" | "local_connector") {
            kernel.arm_metadata_sync(&spec.vfs_path, &spec.zone_id);
        }
    }

    // Local-agent identity bind (mTLS ⊥ token — auth-doc §3.1 / §4.1).
    //
    // `--bind-addr` above serves cluster PEERS over mTLS (the node/peer
    // plane, `agent_id = None`). A local agent on THIS host reaches the
    // same kernel through this loopback bind and authenticates on the
    // token plane (`sk-` Agent key → `agent_id`), so its mailbox writes
    // carry an unforgeable `from` once the stamp hook rewrites them. The
    // two identity planes stay on separate binds by audience; `resolve()`
    // is still the single decision point for both.
    //
    // Fail-closed: an agent bind with NoAuth could not produce an
    // `agent_id` (defeating the purpose), and a token over reachable
    // plaintext is exactly the hole the boot posture forbids — so require
    // the token plane and refuse a non-loopback address.
    let agent_grpc =
        match resolve_agent_bind(common.agent_bind_addr.as_deref(), api_key_auth.is_some())? {
            Some(bind_addr) => {
                let provider = api_key_auth
                    .clone()
                    .expect("resolve_agent_bind returns a bind only when the token plane is on");
                let handle = transport::grpc::spawn(
                    Arc::clone(&kernel),
                    transport::grpc::VfsGrpcConfig {
                        bind_addr,
                        tls: None,
                        max_message_bytes: 64 * 1024 * 1024,
                        server_version: "nexusd-cluster".to_string(),
                    },
                    Arc::clone(&provider) as Arc<dyn transport::auth::AuthProvider>,
                )
                .map_err(|e| anyhow::anyhow!("spawn local-agent vfs bind: {e}"))?;
                tracing::info!(
                    bind = %bind_addr,
                    "local-agent VFS bind up (loopback, token plane: sk- Agent key → agent_id)"
                );
                Some(handle)
            }
            None => None,
        };

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
        // The local-agent bind owns its own tokio runtime; drop it on this
        // blocking thread (dropping a runtime in an async context panics).
        if let Some(handle) = agent_grpc {
            handle.shutdown_blocking();
        }
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
    } = open_zone_manager(&common, None, ZoneLoadPolicy::All)?;
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

/// Re-derive this joiner's federation topology from its peers and (re)wire it,
/// idempotently.  Returns the number of zones reconciled (0 when no peer
/// reported any topology — e.g. all peers unreachable at boot, or `peers`
/// empty).
///
/// A federation mount (`/agents -> sharedzone`) is NOT raft state — it is
/// LOCAL DERIVED state cached from a peer's `DiscoverZones` topology (the
/// SSOT), persisted only as a convenience into this node's per-node SOLO root.
/// So, exactly like `mount -a` re-reading `/etc/fstab` on every boot, it must
/// be re-established every boot from the SSOT rather than trusted from disk.
/// A joiner dropped mid-join — after "Zone registered" but before
/// `join_zones_for_boot`'s `mount_async` persisted the DT_MOUNT — otherwise
/// resumes with the zone fully replicated yet the mount MISSING, leaving
/// `/agents/*` permanently unroutable because `BootAction::Resume` treats the
/// on-disk state as complete.  This is the shared re-derivation the fresh
/// `Join` branch and `Resume` both call.
///
/// Safe to re-run (idempotent): `bootstrap_or_join_zone` short-circuits a
/// zone already loaded from persisted storage (no ConfChange, no membership
/// perturbation — raft §4), and `mount_async` is get-before-put idempotent, so
/// on the happy path re-running is a cheap no-op and on the interrupted-join
/// path it self-heals.
async fn reconcile_federation_from_peers(
    zm: Arc<ZoneManager>,
    node_id: u64,
    self_address: String,
    data_dir: PathBuf,
    peers: Vec<NodeAddress>,
) -> Result<usize> {
    if peers.is_empty() {
        return Ok(0);
    }
    // Ask each peer to report its local federation topology via
    // `DiscoverZones` and union the results — a partially-configured founder
    // pair (each half exposing a disjoint zone) still discovers both.  The
    // BTreeMap sorts by path; `discovered_zone_order` preserves first-response
    // order for per-zone JoinZone dispatch.
    let mut discovered_mounts: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut discovered_zone_order: Vec<String> = Vec::new();
    for peer in &peers {
        match nexus_raft::transport::call_discover_zones_rpc(
            &peer.endpoint,
            zm.registry().tls_config(),
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
    if discovered_zone_order.is_empty() {
        return Ok(0);
    }
    // Phase H: fresh joiner via DiscoverZones has no prior role signal —
    // default all-voter, matching the pre-Phase-H hardcoded behaviour.
    // Operators who need learner-first fresh joins use the offline
    // `nexusd-cluster join --as learner` sidecar.
    let learners = vec![false; discovered_zone_order.len()];
    let reconciled = discovered_zone_order.len();
    join_zones_for_boot(
        zm,
        node_id,
        self_address,
        peers,
        contracts::ROOT_ZONE_ID.to_string(),
        data_dir,
        discovered_zone_order,
        discovered_mounts,
        learners,
    )
    .await?;
    Ok(reconciled)
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
    as_learner_per_zone: Vec<bool>,
) -> Result<()> {
    assert_eq!(
        zone_ids.len(),
        as_learner_per_zone.len(),
        "join_zones_for_boot: zone_ids/as_learner_per_zone length mismatch \
         ({} vs {}) — caller violated Phase H parallel-vec invariant",
        zone_ids.len(),
        as_learner_per_zone.len(),
    );
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

    for (zone_id, &as_learner) in zone_ids.iter().zip(as_learner_per_zone.iter()) {
        let zm_for_join = zm.clone();
        let self_addr_for_join = self_address.clone();
        let zone_id_for_join = zone_id.clone();
        let peers_for_join = peers.clone();
        tracing::info!(
            zone = %zone_id,
            as_learner,
            "boot joiner: dispatching bootstrap_or_join_zone with per-zone role",
        );
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
    } = open_zone_manager(&common, None, ZoneLoadPolicy::All)?;

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
        vec![as_learner],
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
/// Operational-verbosity base for the tracing filter applied when
/// `RUST_LOG` is unset. This carries only the daemon's own routine
/// chatter levels — it deliberately says nothing about *criticality*.
///
/// Privacy/audit-critical targets (which the default filter would
/// otherwise drop to ERROR and silently swallow) are declared once in
/// [`contracts::constants::PRIVACY_CRITICAL_LOG_TARGETS`] and folded on
/// top by [`default_log_filter`]. Adding another critical target is a
/// one-line change *there*, not here — the composition root never names
/// which target is privacy-critical.
const DEFAULT_LOG_FILTER_BASE: &str = "nexusd_cluster=info,nexus_raft=info";

/// The effective default filter: [`DEFAULT_LOG_FILTER_BASE`] with every
/// privacy-critical target directive folded on top. Built at startup
/// assembly time (criticality is compile-time, so perf is irrelevant).
/// The `default_filter_admits_transport_observer_warn` test guards that
/// the transport-observer's relay WARN survives the result.
fn default_log_filter() -> String {
    let mut filter = String::from(DEFAULT_LOG_FILTER_BASE);
    for critical in contracts::constants::PRIVACY_CRITICAL_LOG_TARGETS {
        filter.push(',');
        filter.push_str(&critical.directive());
    }
    filter
}

/// Install the log subscriber.
///
/// `logs_to_stderr` for subcommands, whose **stdout is data**: `auth mint`
/// prints a credential and `auth list` prints records, and both are meant to
/// be captured (`KEY=$(nexusd-collaboration auth mint …)`). A log line landing
/// on that stream corrupts the value silently — the caller ends up with a key
/// that has a WARN glued to the front of it.
///
/// The daemon keeps stdout, which is where systemd and Docker look for it.
fn install_tracing(logs_to_stderr: bool) -> tracing_appender::non_blocking::WorkerGuard {
    let sink: Box<dyn std::io::Write + Send> = if logs_to_stderr {
        Box::new(std::io::stderr())
    } else {
        Box::new(std::io::stdout())
    };
    let (non_blocking, guard) = tracing_appender::non_blocking(sink);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_log_filter())),
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

// -- `auth` subcommand: the useradd / passwd side ---------------------
//
// Offline by design. A credential is not a network resource, and minting one
// over the wire would need an admin credential to authorise it -- the
// bootstrap problem no system solves that way. `useradd` writes a file; this
// proposes a raft command against a stopped daemon's data directory.

/// Open the root zone's credential store against a stopped daemon's data dir.
///
/// The root zone always exists (the kernel owns it -- see
/// `BootAction::needs_root_zone`), but on a fresh data directory it has not
/// been founded yet, so this founds it the way boot would.
// Synchronous by design: it builds a `ZoneManager` (which owns a nested tokio
// runtime), so it must run on the blocking pool, never on an async worker of
// the outer `#[tokio::main]` — see `run_auth`. Callers reach it through
// `run_auth_blocking`, itself inside `spawn_blocking`.
fn open_auth_store(
    common: &CommonArgs,
) -> Result<(
    std::sync::Arc<ZoneManager>,
    std::sync::Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    String,
)> {
    let secret = std::env::var("NEXUS_API_KEY_SECRET").map_err(|_| {
        anyhow::anyhow!(
            "NEXUS_API_KEY_SECRET must be set, and must MATCH the daemon's: a key is \
             looked up by its HMAC under that secret, so a mismatch mints a key the \
             daemon will never recognise"
        )
    })?;

    // Open ONLY the root zone. The credential store (`TREE_AUTH_KEYS`) lives in
    // root, and root is SOLO — so loading it is all the mint needs. Loading the
    // FEDERATED zones here would spin each up as a lone node with no reachable
    // peers (the daemon is stopped); that node campaigns and mutates the zone's
    // persisted term/vote, so the real daemon resumes DIVERGED and the founder
    // loses quorum (`raft: proposal dropped`). Root-only keeps offline tooling
    // out of federated raft entirely. See `ZoneLoadPolicy`.
    //
    // Offline tooling cannot open the data dir while the daemon holds its
    // exclusive redb lock — by far the dominant failure here — so name that
    // cause up front rather than leaking a raw redb/OS error.
    let ZoneManagerBundle { zm, .. } = open_zone_manager(
        common,
        None,
        ZoneLoadPolicy::Only(vec![contracts::ROOT_ZONE_ID.to_string()]),
    )
    .context(
        "offline `auth` could not open the data dir; if the daemon is running, \
         stop it first (it holds an exclusive lock)",
    )?;
    if zm.get_zone(contracts::ROOT_ZONE_ID).is_none() {
        zm.create_zone(contracts::ROOT_ZONE_ID, Vec::new())
            .map_err(|e| anyhow::anyhow!("open root zone: {e}"))?;
    }
    let root = zm
        .get_zone(contracts::ROOT_ZONE_ID)
        .ok_or_else(|| anyhow::anyhow!("root zone did not open"))?;

    // Writes go through consensus, so this node has to be able to commit.
    // Root is SOLO (one voter), so leadership is immediate -- but wait for it
    // rather than race the campaign and fail with a confusing `not leader`.
    if !root.wait_for_leader(std::time::Duration::from_secs(10)) {
        return Err(anyhow::anyhow!(
            "root zone has no leader after 10s -- cannot commit a credential"
        ));
    }

    let store = nexus_raft::auth_key_store::RaftAuthKeyStore::new_arc(
        root.consensus_node(),
        root.runtime_handle(),
    );
    Ok((zm, store, secret))
}

/// Parse `--zone sharedzone:rw` into the `(zone_id, perms)` pair the
/// permission gate reads. A bare `--zone eng` grants read-write.
fn parse_zone_grant(spec: &str) -> Result<(String, String)> {
    match spec.split_once(':') {
        Some((zone, perms)) if !zone.is_empty() && !perms.is_empty() => {
            Ok((zone.to_string(), perms.to_string()))
        }
        Some(_) => Err(anyhow::anyhow!(
            "--zone {spec}: expected ZONE:PERMS (e.g. sharedzone:rw)"
        )),
        None if !spec.is_empty() => Ok((spec.to_string(), "rw".to_string())),
        None => Err(anyhow::anyhow!("--zone: empty grant")),
    }
}

async fn run_auth(common: CommonArgs, action: AuthCmd) -> Result<()> {
    // The offline `auth` subcommand builds a ZoneManager, which owns a nested
    // tokio runtime — created, driven, and dropped in this one call. None of
    // that may happen on an async worker thread of the outer `#[tokio::main]`
    // runtime: dropping a runtime there panics ("Cannot drop a runtime in a
    // context where blocking is not allowed"), which is how a still-running
    // daemon (holding the redb data-dir lock) used to surface — a cryptic
    // mid-construction panic on the error path instead of a clean "stop the
    // daemon first". The blocking pool *allows* blocking (and runtime
    // create/drop), so run the whole thing there. Mirrors the daemon-shutdown
    // drain (`spawn_blocking(|| zm.shutdown())`) and `join_zones_for_boot`.
    tokio::task::spawn_blocking(move || run_auth_blocking(common, action))
        .await
        .context("auth subcommand task panicked")?
}

/// Synchronous body of the offline `auth` subcommand — see `run_auth` for why
/// it runs on the blocking pool. Owns the ZoneManager start to finish so its
/// nested runtime is created and dropped off the async worker threads.
fn run_auth_blocking(common: CommonArgs, action: AuthCmd) -> Result<()> {
    let (zm, store, secret) = open_auth_store(&common)?;
    let result = run_auth_action(&store, &secret, action);
    // Release the data directory's lock before returning, or a daemon started
    // right after this exits fails to open redb.
    zm.shutdown();
    result
}

fn run_auth_action(
    store: &std::sync::Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    secret: &str,
    action: AuthCmd,
) -> Result<()> {
    match action {
        AuthCmd::Mint {
            subject_type,
            subject_id,
            zones,
            admin,
            expires_in_days,
            name,
            allow_existing,
        } => {
            let subject_type = match subject_type.as_str() {
                "user" => auth::SubjectType::User,
                "agent" => auth::SubjectType::Agent,
                "service" => auth::SubjectType::Service,
                other => {
                    return Err(anyhow::anyhow!(
                        "--subject-type {other}: expected user, agent or service"
                    ))
                }
            };
            let zone_perms = zones
                .iter()
                .map(|z| parse_zone_grant(z))
                .collect::<Result<Vec<_>>>()?;
            if zone_perms.is_empty() && !admin {
                return Err(anyhow::anyhow!(
                    "a key with no zone grants reaches nothing and is refused at \
                     authentication time. Pass --zone ZONE:PERMS, or --admin for a \
                     global admin (the only principal allowed a zoneless key)."
                ));
            }
            let expires_at_ms = expires_in_days.map(|days| {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                now_ms + days * 24 * 60 * 60 * 1000
            });
            let record = auth::AuthKeyRecord {
                key_id: uuid_v4(),
                name,
                subject_type,
                subject_id,
                is_admin: admin,
                revoked: false,
                expires_at_ms,
                zone_perms,
            };
            let minted = auth::mint_key(store, secret, record, allow_existing)
                .map_err(|e| anyhow::anyhow!("mint: {e}"))?;

            // The one moment the key exists in the clear. On stdout alone, so
            // `KEY=$(nexusd-collaboration auth mint ...)` captures the key and
            // nothing else.
            println!("{}", minted.key);
            eprintln!(
                "minted key_id={} hash={} subject={}:{} zones={:?}",
                minted.record.key_id,
                minted.key_hash,
                minted.record.subject_type.as_str(),
                minted.record.subject_id,
                minted.record.zone_perms,
            );
            eprintln!("This key will not be shown again - it is stored only as an HMAC.");
            Ok(())
        }
        AuthCmd::Revoke { key, key_hash } => {
            let removed = match (key, key_hash) {
                (Some(key), None) => auth::revoke_key(store, secret, &key),
                (None, Some(hash)) => auth::revoke_key_hash(store, &hash),
                _ => {
                    return Err(anyhow::anyhow!(
                        "revoke: pass exactly one of --key or --key-hash"
                    ))
                }
            }
            .map_err(|e| anyhow::anyhow!("revoke: {e}"))?;
            if removed {
                println!("revoked");
            } else {
                println!("no such key (already revoked?)");
            }
            Ok(())
        }
        AuthCmd::List => {
            let records = store.list().map_err(|e| anyhow::anyhow!("list: {e}"))?;
            if records.is_empty() {
                println!("no keys");
                return Ok(());
            }
            for (hash, bytes) in records {
                match auth::AuthKeyRecord::decode(&bytes) {
                    Ok(r) => println!(
                        "{hash}  {}:{}  admin={}  zones={:?}  expires_at_ms={:?}  name={}",
                        r.subject_type.as_str(),
                        r.subject_id,
                        r.is_admin,
                        r.zone_perms,
                        r.expires_at_ms,
                        r.name,
                    ),
                    // A record this build cannot parse still exists and still
                    // authenticates somebody -- say so rather than hide it.
                    Err(e) => println!("{hash}  <undecodable record: {e}>"),
                }
            }
            Ok(())
        }
    }
}

/// Project the CLI onto the pure decision in [`auth_posture`].
///
/// The rule itself lives in that module and is a pure function of these four
/// inputs, so it is testable without a daemon and cannot drift with boot order.
fn auth_posture(common: &CommonArgs) -> Result<AuthPosture> {
    auth_posture::decide(&AuthPostureInputs {
        bind_addr: common.bind_addr.clone(),
        api_key_secret: std::env::var("NEXUS_API_KEY_SECRET").ok(),
        tls_enabled: !common.no_tls,
        insecure_no_auth: common.insecure_no_auth,
    })
}

/// Minimal uuid-v4 for `key_id`. The daemon carries no uuid dep and this is
/// its only caller; a random 128-bit id in the canonical shape is all it needs.
fn uuid_v4() -> String {
    use rand::Rng;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// The transport-observer's relay data-privacy caution is a WARN under the
    /// `transport_observer` target. When `RUST_LOG` is unset the daemon builds
    /// its filter from [`DEFAULT_LOG_FILTER`]; an `EnvFilter` sends any target
    /// with no matching directive to ERROR, which would silently swallow that
    /// WARN and defeat the privacy signal. This exercises the real filter
    /// (not the directive string) and asserts the WARN survives while a
    /// directive-less dependency's INFO does not.
    #[test]
    fn default_filter_admits_transport_observer_warn() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;

        // Capture the (target, level) of every event that clears the filter.
        struct Capture(Arc<Mutex<Vec<(String, tracing::Level)>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let m = event.metadata();
                self.0
                    .lock()
                    .unwrap()
                    .push((m.target().to_string(), *m.level()));
            }
        }

        // Local copy for the runtime assertion comparisons below. The
        // `target:` positions in the macros must stay a const path (tracing
        // builds each callsite's metadata in a `static`), so they reference
        // the const directly rather than this binding.
        let target = contracts::constants::TRANSPORT_OBSERVER_LOG_TARGET;
        let seen = Arc::new(Mutex::new(Vec::new()));
        // EnvFilter installed as a layer filters events for the whole registry.
        // Exercise the *folded* default (base + privacy-critical directives),
        // proving the fold — not a hardcoded literal — admits the WARN.
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(default_log_filter()))
            .with(Capture(seen.clone()));

        tracing::subscriber::with_default(subscriber, || {
            // must survive
            tracing::warn!(target: contracts::constants::TRANSPORT_OBSERVER_LOG_TARGET, "relay caution");
            // below warn → dropped
            tracing::info!(target: contracts::constants::TRANSPORT_OBSERVER_LOG_TARGET, "chatter");
            tracing::info!(target: "nexusd_cluster", "boot"); // explicit info → survives
            tracing::info!(target: "some_unlisted_dep", "noise"); // no directive → ERROR default → dropped
        });

        let seen = seen.lock().unwrap();
        assert!(
            seen.iter()
                .any(|(t, l)| t == target && *l == tracing::Level::WARN),
            "privacy WARN must clear the default filter, saw: {seen:?}",
        );
        assert!(
            !seen
                .iter()
                .any(|(t, l)| t == target && *l == tracing::Level::INFO),
            "the privacy target's INFO is below the warn directive and must stay filtered",
        );
        assert!(
            !seen.iter().any(|(t, _)| t == "some_unlisted_dep"),
            "a target with no directive defaults to ERROR and its INFO must be dropped",
        );
    }

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

    // ── --agent-bind-addr fail-closed posture (Option X: mTLS ⊥ token) ──
    #[test]
    fn agent_bind_unset_is_none() {
        assert!(resolve_agent_bind(None, true).expect("unset ok").is_none());
        assert!(resolve_agent_bind(None, false)
            .expect("unset ok even without a secret")
            .is_none());
    }

    #[test]
    fn agent_bind_requires_token_plane() {
        // Set but no secret → refuse: a NoAuth agent bind resolves every
        // caller as nobody and could never stamp a `from`.
        let err = resolve_agent_bind(Some("127.0.0.1:2130"), false)
            .expect_err("agent bind without the token plane must fail-closed");
        assert!(err.to_string().contains("NEXUS_API_KEY_SECRET"));
    }

    #[test]
    fn agent_bind_must_be_loopback() {
        // Token plane on, but a reachable addr → refuse: a bearer token over
        // plaintext must never leave the host.
        let err = resolve_agent_bind(Some("0.0.0.0:2130"), true)
            .expect_err("non-loopback agent bind must fail-closed");
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn agent_bind_loopback_with_token_resolves() {
        let addr = resolve_agent_bind(Some("127.0.0.1:2130"), true)
            .expect("loopback + token plane is legal")
            .expect("returns a bind addr");
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 2130);
    }

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
        // Phase G: `--bootstrap-mode` deleted — the daemon now
        // auto-detects boot semantics from disk / identity / peers /
        // federation-env inputs via `plan_boot_action`.
        let parsed =
            Args::try_parse_from(["nexusd-cluster", "--advertise-addr", "100.64.0.27:2126"])
                .expect("--advertise-addr must parse on daemon mode");
        assert_eq!(
            parsed.common.advertise_addr.as_deref(),
            Some("100.64.0.27:2126"),
        );
    }
}
