//! Nexus cluster-profile runtime — `nexusd-cluster`.
//!
//! A self-contained ~5 MB Rust binary that brings up:
//!   * [`nexus_raft::ZoneManager`] (multi-zone Raft + gRPC server)
//!   * Day-1 TLS bootstrap (CA + node cert + join token) on first start
//!   * Static topology (founder `--cluster-init` / `--cluster-init-mount`)
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
// Founder topology is parsed from the `--cluster-init` flags via raft's
// env-agnostic `parse_zones_str` / `parse_mounts_str` (called fully-qualified).
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

    /// Bind address for the federation gRPC (mTLS data-plane) server.
    ///
    /// Usually left unset: it DERIVES from `--advertise-addr`'s port (bind all
    /// interfaces on the advertised port) so the operator states ONE address
    /// per node. Set it explicitly only for exotic multi-NIC binds. Falls back
    /// to `DEFAULT_BIND` when neither is given (single-node/loopback tests).
    /// See [`CommonArgs::effective_bind_addr`].
    #[arg(long, env = "NEXUS_BIND_ADDR", global = true)]
    bind_addr: Option<String>,

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

    /// Accept new nodes enrolling into this cluster (founder side).
    ///
    /// The pre-mTLS BOOTSTRAP plane: a brand-new node has no cluster cert, so
    /// it cannot reach the strict-mTLS data-plane bind. This starts a dedicated
    /// PLAINTEXT listener serving ONLY `NodeEnrollmentService.JoinCluster` —
    /// the founder signs a joiner's cert after verifying its join token. Auth
    /// is the token; integrity is the CA fingerprint the joiner pins from the
    /// token; the channel rides the encrypted overlay (k3s/kubeadm model).
    ///
    /// The listener rides a fixed offset above the data-plane port
    /// ([`CommonArgs::effective_enroll_addr`]) so the operator never types a
    /// second address — the joiner derives the same port from `--peers`.
    /// Requires TLS on (the founder must own a CA).
    #[arg(
        long,
        env = "NEXUS_ACCEPT_ENROLLMENTS",
        default_value_t = false,
        global = true
    )]
    accept_enrollments: bool,

    /// Join token for one-shot self-enrollment at boot (joiner side).
    ///
    /// A certless node given a `--token` (from the founder's boot log /
    /// `tls/join-token`) plus `--peers` auto-enrolls BEFORE it joins: it dials
    /// the founder's enrollment port (derived from the first peer), obtains a
    /// CA-signed node cert, then joins over mTLS — the k3s `agent --server
    /// --token` one-command model. No separate `enroll` step. Ignored once this
    /// node already holds a cert (`tls/node.pem`).
    #[arg(long, env = "NEXUS_JOIN_TOKEN", global = true)]
    token: Option<String>,

    /// Found (initialize) these federation zones as this cluster's first
    /// member — the FOUNDER declaration. Repeatable; comma-separated via
    /// `NEXUS_CLUSTER_INIT`.
    ///
    /// This is etcd's `--initial-cluster-state new` / k3s's `--cluster-init`:
    /// it says "I am CREATING this cluster". Mutually exclusive with `--peers`
    /// (which says "I am JOINING an existing cluster") — passing both is a hard
    /// boot error, because two nodes each founding the same zone name produce a
    /// split-brain. A joiner NEVER sets this; it uses `--peers` (+ `--token`).
    #[arg(
        long = "cluster-init",
        env = "NEXUS_CLUSTER_INIT",
        value_delimiter = ',',
        global = true
    )]
    cluster_init: Vec<String>,

    /// Mount a founded zone into the VFS at boot, as `PATH=ZONE` (e.g.
    /// `/shared=sharedzone`). Repeatable; comma-separated via
    /// `NEXUS_CLUSTER_INIT_MOUNTS`. Founder-side, same mutual-exclusion with
    /// `--peers` as `--cluster-init`.
    #[arg(
        long = "cluster-init-mount",
        env = "NEXUS_CLUSTER_INIT_MOUNTS",
        value_delimiter = ',',
        global = true
    )]
    cluster_init_mount: Vec<String>,

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

    /// Effective raft data-plane bind. `--bind-addr` when given; otherwise
    /// DERIVES from `--advertise-addr`'s port (bind all interfaces on the
    /// advertised port), so the operator states ONE address per node. Falls
    /// back to `DEFAULT_BIND` when neither is set (single-node/loopback tests).
    fn effective_bind_addr(&self) -> String {
        if let Some(bind) = &self.bind_addr {
            return bind.clone();
        }
        if let Some(port) = self
            .advertise_addr
            .as_deref()
            .and_then(|a| a.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok())
        {
            return format!("0.0.0.0:{port}");
        }
        DEFAULT_BIND.to_string()
    }

    /// Founder-side node-enrollment listener bind. Convention: the data-plane
    /// port + 1, bound on all interfaces (plaintext, token-gated). The joiner
    /// derives the SAME port from `--peers` via [`enroll_port_addr`], so
    /// neither side ever types a second address.
    fn effective_enroll_addr(&self) -> Result<String> {
        enroll_port_addr(&self.effective_bind_addr())
    }
}

/// The node-enrollment endpoint for a data-plane `host:port` — the SINGLE
/// definition of the "enrollment rides one port above the data plane"
/// convention. The founder binds `enroll_port_addr(<its bind>)`; a joiner dials
/// `enroll_port_addr(<first --peer>)`. Keeping it one function is what lets the
/// two sides agree on the port without the operator ever stating it.
fn enroll_port_addr(host_port: &str) -> Result<String> {
    let (host, port) = host_port
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("address '{host_port}' is not host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|e| anyhow::anyhow!("address '{host_port}' has a non-numeric port: {e}"))?;
    let enroll_port = port.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("data-plane port {port} leaves no room for the +1 enrollment port")
    })?;
    Ok(format!("{host}:{enroll_port}"))
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
    /// Revoke a credential — an `sk-` key (by key or hash), or an agent cert
    /// (by name).
    Revoke {
        /// The `sk-` key, if you hold it.
        #[arg(long, conflicts_with_all = ["key_hash", "agent"])]
        key: Option<String>,
        /// The key's hash, as shown by `auth list` — the shape an admin uses,
        /// working from the audit view rather than from a key they do not have.
        #[arg(long, conflicts_with_all = ["key", "agent"])]
        key_hash: Option<String>,
        /// The agent NAME, to revoke its cert instead of an `sk-` key. Reads the
        /// serial from the minted bundle and adds it to the cluster CRL (the CA
        /// plane), so it takes effect on every node after a CRL refresh. This
        /// path is file-based — no store lock — so it works while the daemon runs.
        #[arg(long, conflicts_with_all = ["key", "key_hash"])]
        agent: Option<String>,
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
    /// Mint an EXTRA join token for THIS cluster (founder), and print it.
    ///
    /// Usually unnecessary: the day-1 TLS bootstrap already mints a token, and
    /// a founder started with `--accept-enrollments` prints a ready-to-paste
    /// join command (token included) at boot. Use this only to ROTATE the token
    /// or mint an additional one. Ensures this data dir has a cluster CA
    /// (bootstraps one if absent), mints a fresh token bound to that CA's
    /// fingerprint, records its hash where `--accept-enrollments` reads it, and
    /// prints the token to stdout. k3s/kubeadm model.
    EnrollToken {},
    /// PRE-provision this node's mTLS cert from a founder using a join token.
    ///
    /// Usually unnecessary: passing `--token` (+ `--peers`) to the daemon
    /// auto-enrolls at boot in one command. Use this standalone form only to
    /// provision the cert ahead of time. Connects (plaintext, over the
    /// encrypted overlay) to the founder's enrollment port, presents the join
    /// token, verifies the returned CA against the fingerprint pinned in the
    /// token, and writes `ca.pem`/`node.pem`/`node-key.pem` into
    /// `<data-dir>/tls/`. Distinct from `join` (which joins a specific ZONE
    /// over already-established mTLS).
    Enroll {
        /// Founder's DATA-PLANE address as `host:port` (its `--advertise-addr`,
        /// same value as `--peers`; e.g. an overlay IP `100.64.0.27:2126`). The
        /// enrollment port is derived from it by convention (`port + 1`).
        peer_addr: String,
        /// Join token minted by the founder (`enroll-token`, or from its boot
        /// log) — `K10<pw>::server:SHA256:<ca-fp>`.
        token: String,
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
/// Boot-derived config the composition's service-decl builder reads to
/// parameterise each service (e.g. a2a's fail-closed posture). Populated by
/// [`run_with_services`] at the point services are brought up.
pub struct ServiceBootCtx {
    /// True iff an auth provider is armed (sk- API-key auth). a2a uses it
    /// as its from-stamp fail-closed posture.
    pub auth_armed: bool,
}

/// Boxed service-decl builder — threaded from [`run_with_services`] into
/// `run_daemon` (the daemon path) so the generic bound doesn't ripple
/// through every async boot fn. Consumed once at bring-up (`FnOnce`).
type BoxedServiceDeclsBuilder =
    Box<dyn FnOnce(&ServiceBootCtx) -> Vec<kernel::kernel::ServiceDecl> + Send>;

/// Default cluster daemon entry — supplies the nexus-vfs-native service
/// set (a2a). A fuller assembly binary (which links additional service
/// crates) calls [`run_with_services`] with a larger decl list instead.
pub fn run() -> Result<()> {
    run_with_services(|ctx| vec![a2a::service_decl(ctx.auth_armed)])
}

/// Cluster daemon entry, parameterised by the service set. Boots the
/// kernel + federation, hands the declared services to
/// `Kernel::bring_up_services` (the ServiceRegistry is the single service
/// authority — no per-service install code lives in this boot path), then
/// serves. `build_decls` is invoked once, after the kernel + auth are up,
/// with a [`ServiceBootCtx`] carrying boot-derived config.
pub fn run_with_services<F>(build_decls: F) -> Result<()>
where
    F: FnOnce(&ServiceBootCtx) -> Vec<kernel::kernel::ServiceDecl> + Send + 'static,
{
    // Box the builder so it can be threaded through the async dispatch into
    // `run_daemon` (the daemon path) without a generic bound rippling
    // through every async fn.
    let build_decls: BoxedServiceDeclsBuilder = Box::new(build_decls);
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
                None => run_daemon(args.common, build_decls).await,
                Some(Cmd::ServeLocal { port }) => {
                    // Force the trusted-local-backend posture: loopback
                    // bind + plaintext. auth_posture then grants the
                    // no-auth start without `--insecure-no-auth`.
                    let mut common = args.common;
                    common.bind_addr = Some(format!("127.0.0.1:{port}"));
                    common.no_tls = true;
                    run_daemon(common, build_decls).await
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
                Some(Cmd::EnrollToken {}) => run_enroll_token(&args.common),
                Some(Cmd::Enroll { peer_addr, token }) => {
                    // `join_cluster_and_provision_tls` spins its own runtime and
                    // `block_on`s it, so it must run OFF this async worker or it
                    // panics with the nested-runtime error. Move it to the
                    // blocking pool (same shape as offline `auth mint`, #176).
                    tokio::task::spawn_blocking(move || {
                        run_enroll(&args.common, &peer_addr, &token)
                    })
                    .await
                    .context("enroll task panicked")?
                }
            }
        })
}

/// `enroll-token` — mint an EXTRA CA-fingerprint-pinned join token (founder).
///
/// The day-1 TLS bootstrap already mints one and `--accept-enrollments` prints
/// it at boot, so this is only for rotating / adding a token. Bootstraps this
/// data dir's cluster CA if absent, mints a fresh token, records its hash where
/// `--accept-enrollments` reads it, and prints the token to stdout (everything
/// else goes to stderr).
fn run_enroll_token(common: &CommonArgs) -> Result<()> {
    let tls_dir = common.data_dir.join("tls");
    std::fs::create_dir_all(&tls_dir)
        .with_context(|| format!("create tls dir {}", tls_dir.display()))?;
    let ca_path = tls_dir.join("ca.pem");
    let ca_key_path = tls_dir.join("ca-key.pem");
    if !ca_path.exists() {
        let (ca_pem, ca_key_pem) = nexus_raft::transport::generate_zone_ca(contracts::ROOT_ZONE_ID)
            .map_err(|e| anyhow::anyhow!("generate cluster CA: {e}"))?;
        std::fs::write(&ca_path, &ca_pem)
            .with_context(|| format!("write {}", ca_path.display()))?;
        std::fs::write(&ca_key_path, &ca_key_pem)
            .with_context(|| format!("write {}", ca_key_path.display()))?;
        tracing::info!(ca = %ca_path.display(), "bootstrapped cluster CA for enrollment");
    }
    let ca_pem = std::fs::read(&ca_path).with_context(|| format!("read {}", ca_path.display()))?;
    let (token, hash) = nexus_raft::transport::generate_join_token(&ca_pem)
        .map_err(|e| anyhow::anyhow!("mint join token: {e}"))?;
    std::fs::write(tls_dir.join("join-token-hash"), &hash)
        .with_context(|| "write join-token-hash")?;
    // Token is DATA → stdout; guidance → stderr, so a caller can capture just
    // the token.
    println!("{token}");
    eprintln!(
        "join token minted (pinned to this cluster's CA). On the new node run one command:\n  \
         nexusd-cluster --advertise-addr <THAT_NODE_OVERLAY:PORT> \
         --peers <FOUNDER_OVERLAY:PORT> --token <token>"
    );
    Ok(())
}

/// `enroll` — PRE-provision a signed mTLS node cert from a founder (joiner).
///
/// Thin CLI over [`nexus_raft::join_cluster_and_provision_tls`]: `peer_addr` is
/// the founder's DATA-PLANE address (same as `--peers`); the enrollment port is
/// derived from it ([`enroll_port_addr`], `+1`). Presents the join token,
/// verifies the returned CA against the fingerprint pinned in the token, and
/// writes the bundle into `<data-dir>/tls/`. Usually unnecessary — the daemon
/// auto-enrolls from `--token` at boot; this only pre-provisions the cert.
fn run_enroll(common: &CommonArgs, peer_addr: &str, token: &str) -> Result<()> {
    let hostname = resolve_hostname(common.hostname.as_deref());
    let tls_dir = common.data_dir.join("tls");
    let tls_dir_str = tls_dir.to_str().context("tls dir must be UTF-8")?;
    let enroll_target = enroll_port_addr(peer_addr)?;
    nexus_raft::join_cluster_and_provision_tls(&enroll_target, token, &hostname, tls_dir_str)
        .map_err(|e| anyhow::anyhow!("enroll against {enroll_target}: {e}"))?;
    eprintln!(
        "enrolled: cluster cert written to {}. This node can now boot into the mTLS \
         federation — set `--peers <cluster-member>` and start it normally.",
        tls_dir.display()
    );
    Ok(())
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
    ///       here + `--cluster-init` set = both-founder
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
    let effective_bind = common.effective_bind_addr();
    let bind_port = effective_bind
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
        &effective_bind,
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

async fn run_daemon(common: CommonArgs, build_decls: BoxedServiceDeclsBuilder) -> Result<()> {
    let hostname = resolve_hostname(common.hostname.as_deref());
    tracing::info!(
        hostname = %hostname,
        bind = %common.effective_bind_addr(),
        data_dir = %common.data_dir.display(),
        "nexusd-cluster starting (daemon mode)",
    );

    // S3 Phase G: single boot decision layer.  No more explicit
    // `--bootstrap-mode` from the operator — the daemon reads the
    // authoritative signals (`data_dir_has_root`, identity contents,
    // CLI `--peers`, `--cluster-init`) and dispatches through
    // `plan_boot_action`.  See `nexus_raft::bootstrap` for the full
    // decision matrix.
    let data_dir_has_root = common.data_dir.join("root").join("raft").exists();
    let peers_non_empty = common.peers.split(',').any(|s| !s.trim().is_empty());
    tracing::info!(
        peers_non_empty,
        data_dir_has_root,
        "boot inputs — see nexus_raft::bootstrap::plan_boot_action for dispatch",
    );

    // One-shot self-enrollment at boot (joiner side, k3s `agent --server
    // --token`). A certless node given `--token` + `--peers` provisions its
    // mTLS cert BEFORE `open_zone_manager` brings up the data plane: it dials
    // the founder's enrollment port (derived from the first peer via the same
    // `+1` convention the founder's listener uses — [`enroll_port_addr`]) and
    // writes ca/node/node-key into `<data-dir>/tls/`. `bootstrap_tls` then
    // REUSES that bundle instead of self-signing a fresh (unrelated) CA.
    // Skipped once a cert already exists, so restarts do not re-enroll.
    let use_tls = !common.no_tls;
    if use_tls && common.token.is_some() && peers_non_empty {
        let tls_dir = common.data_dir.join("tls");
        let already_enrolled = tls_dir.join("node.pem").exists() && tls_dir.join("ca.pem").exists();
        if already_enrolled {
            tracing::info!("--token ignored: this node already holds a cluster cert");
        } else {
            let first_peer = NodeAddress::parse_peer_list_operator(&common.peers, use_tls)
                .map_err(|e| anyhow::anyhow!("--peers parse for auto-enroll: {e}"))?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("--token given but --peers is empty"))?;
            let enroll_target = enroll_port_addr(&first_peer.to_operator_str())?;
            let token = common.token.clone().expect("token present by guard");
            let tls_dir_str = tls_dir
                .to_str()
                .context("tls dir must be UTF-8")?
                .to_string();
            let hostname_for_enroll = hostname.clone();
            tracing::info!(%enroll_target, "no cluster cert on disk — auto-enrolling at boot");
            // `join_cluster_and_provision_tls` spins its own runtime + block_on,
            // so it must run OFF this async worker (nested-runtime panic; #176).
            let target_for_task = enroll_target.clone();
            tokio::task::spawn_blocking(move || {
                nexus_raft::join_cluster_and_provision_tls(
                    &target_for_task,
                    &token,
                    &hostname_for_enroll,
                    &tls_dir_str,
                )
            })
            .await
            .context("auto-enroll task panicked")?
            .map_err(|e| anyhow::anyhow!("auto-enroll against {enroll_target}: {e}"))?;
            tracing::info!("auto-enroll complete — cluster cert provisioned");
        }
    }

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
    // Self-provision the cluster api-key secret BEFORE reading the auth posture,
    // so an auth-on founder arms `sk-` auth on its own and the enrollment
    // listener (below) has a secret to distribute — the minimal-info contract
    // (#185). This lives ONLY here on the daemon boot, never in the shared
    // `open_zone_manager`, so an offline `auth mint` / `share` / `join` can't
    // persist a throwaway env (the #186 guarantee). Auth-off (`--no-tls`) needs
    // no secret. Founder = the CA holder: `--cluster-init` on first boot, or a
    // persisted `ca-key.pem` on resume; `NEXUS_API_KEY_SECRET` wins else random.
    if !common.no_tls {
        let tls_dir = common.data_dir.join("tls");
        let is_founder = !common.cluster_init.is_empty() || tls_dir.join("ca-key.pem").exists();
        if provision_api_key_secret(
            &tls_dir,
            is_founder,
            std::env::var("NEXUS_API_KEY_SECRET").ok(),
        )
        .with_context(|| format!("persist {}", tls_dir.join("api-key-secret").display()))?
        {
            tracing::info!(dir = %tls_dir.display(), "founder provisioned cluster api-key secret");
        }
    }

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

    // Remote agent-cert mint (task #40): the CA holder installs an `AgentMinter`
    // into the raft gRPC server's slot, so `auth mint --subject-type agent` on
    // ANY node just-works — a node without the CA key forwards to the founder
    // over mTLS (`mint_agent_via_founder`) and the founder signs + records the
    // agent here. Gated on holding the CA private key; every other node leaves
    // the slot empty and its MintAgent RPC replies "does not hold the cluster
    // CA". Auth-off (`--no-tls`) has no CA at all, so nothing is installed.
    if !common.no_tls {
        let tls_dir = common.data_dir.join("tls");
        if tls_dir.join("ca-key.pem").exists() {
            let minter: Arc<dyn nexus_raft::agent_minter::AgentMinter> =
                Arc::new(FounderAgentMinter {
                    store: auth::KernelSlotStore::new_arc(Arc::clone(&kernel)),
                    tls_dir,
                });
            *zm.agent_minter_slot().write() = Some(minter);
            tracing::info!("CA holder armed MintAgent RPC (remote agent-cert mint)");
        }
    }

    // Founder node-enrollment listener (pre-mTLS BOOTSTRAP plane). With
    // `--accept-enrollments` and TLS on, serve `NodeEnrollmentService` on a
    // dedicated PLAINTEXT bind (data-plane port + 1, see `effective_enroll_addr`
    // — the operator never types it) so a certless new node can obtain a signed
    // cert with a join token. It reads the cluster CA + the accepted token hash
    // from this node's TLS bundle. Kept OFF the strict-mTLS data-plane bind on
    // purpose (a certless joiner cannot complete that handshake).
    if common.accept_enrollments {
        if common.no_tls {
            tracing::warn!(
                "--accept-enrollments ignored: enrollment signs mTLS certs but --no-tls is set, \
                 so this node has no CA to sign with"
            );
        } else {
            let tls_dir = common.data_dir.join("tls");
            let ca_pem = std::fs::read(tls_dir.join("ca.pem")).with_context(|| {
                format!("accept-enrollments: read {}/ca.pem", tls_dir.display())
            })?;
            let ca_key_pem = std::fs::read(tls_dir.join("ca-key.pem")).with_context(|| {
                format!("accept-enrollments: read {}/ca-key.pem", tls_dir.display())
            })?;
            let hash_path = tls_dir.join("join-token-hash");
            let join_token_hash = std::fs::read_to_string(&hash_path).with_context(|| {
                format!(
                    "accept-enrollments: read {} — the TLS bootstrap mints one on first boot; \
                     run `nexusd-cluster enroll-token` to (re)mint",
                    hash_path.display()
                )
            })?;
            let enroll_addr = common.effective_enroll_addr()?;
            let addr: std::net::SocketAddr = enroll_addr
                .parse()
                .map_err(|e| anyhow::anyhow!("enrollment listener addr '{enroll_addr}': {e}"))?;
            // Serve the cluster API-key secret to enrollees over this same
            // token-gated channel as the CA. Resolved read-only (env on a founder,
            // else this node's own enrolled file) and served verbatim — the
            // enrollee persists what it receives, so nothing is written here.
            // `None` ⇒ auth-off: the response omits it and joiners stay auth-off too.
            let api_key_secret = effective_api_key_secret(&tls_dir);
            // The founder holds the CA, so it also serves the CRL: GetCrl reads
            // this file live and CA-signs a fresh CRL, so an offline `auth
            // revoke` takes effect without a restart.
            let revoked_path = nexus_raft::transport::revoked_serials_path(&common.data_dir);
            zm.runtime_handle().spawn(async move {
                if let Err(e) = nexus_raft::transport::serve_node_enrollment(
                    addr,
                    ca_pem,
                    ca_key_pem,
                    join_token_hash.trim().to_string(),
                    api_key_secret,
                    Some(revoked_path),
                    std::future::pending::<()>(),
                )
                .await
                {
                    tracing::error!(error = %e, "node-enrollment listener terminated");
                }
            });
            tracing::info!(%enroll_addr, "node-enrollment listener up (plaintext, token-gated)");

            // Surface the join token as a ready-to-paste joiner command, so the
            // operator never has to know to run `enroll-token` first. The
            // plaintext token is written by the day-1 TLS bootstrap
            // (`tls/join-token`); the joiner dials this founder's data-plane
            // address (`--peers`) and derives the enrollment port itself.
            let data_port = common
                .effective_bind_addr()
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .unwrap_or(2126);
            let peers_hint = common
                .advertise_addr
                .clone()
                .unwrap_or_else(|| format!("<FOUNDER_OVERLAY_IP:{data_port}>"));
            match std::fs::read_to_string(tls_dir.join("join-token")) {
                Ok(token) => tracing::info!(
                    "cluster accepts enrollments. To add a node, run THERE:\n  \
                     nexusd-cluster --advertise-addr <THAT_NODE_OVERLAY:PORT> \
                     --peers {peers_hint} --token {}",
                    token.trim(),
                ),
                Err(_) => tracing::info!(
                    "cluster accepts enrollments, but no join token is stored here — \
                     mint one with `nexusd-cluster enroll-token` and hand it to the new node."
                ),
            }
        }
    }

    // CRL refresh: keep this node's revoked-serial set current from the CA
    // plane (not raft). Only when auth is on — auth-off has no cert-agents to
    // revoke. The founder holds the revoked-serial file and reads it directly;
    // a joiner fetches the CA-signed CRL from the founder's enroll addr (derived
    // from the first peer the way boot-time enrollment is) and verifies it.
    if let Some(provider) = api_key_auth.clone() {
        let ca_key_holder = common.data_dir.join("tls").join("ca-key.pem").exists();
        let founder_enroll = if ca_key_holder {
            None
        } else {
            NodeAddress::parse_peer_list_operator(&common.peers, !common.no_tls)
                .ok()
                .and_then(|peers| peers.into_iter().next())
                .and_then(|peer| enroll_port_addr(&peer.to_operator_str()).ok())
        };
        zm.runtime_handle().spawn(crl_refresh_loop(
            provider,
            common.data_dir.clone(),
            ca_key_holder,
            founder_enroll,
        ));
    }

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
    // Founder declaration comes from the `--cluster-init` / `--cluster-init-mount`
    // flags (clap also honours the matching `NEXUS_CLUSTER_INIT*` envs), parsed
    // with raft's env-agnostic string parsers so the mount diagnostics below
    // still apply. This is the FOUNDER intent ("I am creating this cluster");
    // `--peers` is the JOINER intent — see the mutual-exclusion guard.
    let init_zones = nexus_raft::federation::parse_zones_str(&common.cluster_init.join(","));
    let init_mounts =
        nexus_raft::federation::parse_mounts_str(&common.cluster_init_mount.join(","));
    let founder_declared = !init_zones.is_empty() || !init_mounts.mounts.is_empty();

    // --cluster-init ⊥ --peers — the found-vs-join hard互斥. `--cluster-init`
    // says "I am FOUNDING this cluster", `--peers` says "I am JOINING an
    // existing one"; two nodes each founding the same zone name deterministically
    // produce two disjoint raft groups that can never merge (split-brain). This
    // is etcd's `--initial-cluster-state new` vs `existing` / k3s's
    // `--cluster-init` vs `--server`: the intent is explicit and exclusive.
    // Refuse at boot rather than roll the dice. `plan_boot_action` rows 5/6 keep
    // this as defense-in-depth; this is the earliest, clearest surface. Gated on
    // `!data_dir_has_root` — a restart with persisted state resumes and the
    // flags are advisory (row 0 Resume).
    if founder_declared && peers_non_empty && !data_dir_has_root {
        return Err(anyhow::anyhow!(
            "--cluster-init and --peers are mutually exclusive: --cluster-init declares \
             'I am FOUNDING this cluster', --peers declares 'I am JOINING an existing one'. \
             Two nodes each founding the same zone name produce a split-brain (two disjoint \
             raft groups sharing a zone name, whose histories can never merge). Choose one:\n  \
             (a) FOUNDER — keep --cluster-init (+ --accept-enrollments), drop --peers.\n  \
             (b) JOINER  — keep --peers (+ --token), drop --cluster-init.",
        ));
    }

    // Surface every dropped `--cluster-init-mount` entry so the operator sees
    // them in boot logs.  When the input was non-empty but the parser ate
    // everything (the Mac↔Win L1 smoke wedge: Windows MSYS Git Bash mangling
    // `/shared=sharedzone` into `C:/Program Files/Git/shared=sharedzone`),
    // refuse to boot — a silent `mount_count=0` federation leaves the operator
    // chasing downstream raft-replication symptoms for hours.
    for d in &init_mounts.dropped {
        tracing::error!(
            raw = %d.raw,
            reason = d.reason,
            flag = "--cluster-init-mount",
            "cluster-init mount entry dropped at parse",
        );
    }
    if init_mounts.is_silent_dropall() {
        return Err(anyhow::anyhow!(
            "--cluster-init-mount parsed to zero mounts despite non-empty input — refusing \
             to start with a silently broken federation topology.  Inspect the per-entry \
             reasons logged above (one common trigger is MSYS path conversion on Windows \
             Git Bash; export MSYS_NO_PATHCONV=1 or single-quote the value).",
        ));
    }

    // Preserved PR #112 split-brain guard — backstops the FailLoud arm of
    // `plan_boot_action` (row 5, identity-peers + founder decl) with a longer,
    // operator-actionable hint. Distinct from the --peers互斥 above: this fires
    // when a node that ALREADY knows peers from a prior boot (identity.json) is
    // (re)started with --cluster-init. Gated on `!data_dir_has_root` — a restart
    // with authoritative persisted state resumes; flags are advisory (row 0).
    if founder_declared && !identity_persisted_peers.is_empty() && !data_dir_has_root {
        return Err(anyhow::anyhow!(
            "split-brain guard: --cluster-init is set (zones={:?}) but identity.json \
                 already lists peers={:?}.  Founding a SOLO zone on a node that already \
                 knows peers is the both-founder misconfig — it produces two independent \
                 raft clusters sharing the same zone name whose leader histories cannot \
                 merge.  Choose one role:\n  \
                 (a) FOUNDER — this node is the source of truth.  Remove the persisted \
                 peers first: rm -f IDENTITY_DIR/identity.json (leave data_dir alone if you \
                 have prior state to reuse), then re-run.\n  \
                 (b) JOINER — the persisted peers are the actual founders. Drop \
                 --cluster-init and let the daemon rejoin them (add --peers/--token only \
                 if identity was also wiped).",
            init_zones,
            identity_persisted_peers,
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
        federation_zones: init_zones.clone(),
        federation_mounts: init_mounts.mounts.clone(),
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
                "Bootstrapping static topology from --cluster-init / --cluster-init-mount",
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
            // ── Founder's OWN declared topology — re-assert ONLY when peerless ──
            // `--cluster-init` zones + `--cluster-init-mount` mounts declare a
            // founder's OWN intent.  Re-asserting them on Resume is load-bearing
            // because `plan_boot_action` returns `Resume` whenever `root` is
            // already on disk (e.g. an offline `auth mint` created it before the
            // first daemon boot), SKIPPING the `StaticFounder` arm — so otherwise
            // the declared zone is never founded and `/agents/*` silently falls
            // back to node-local root (an A2A mailbox there binds root and never
            // replicates cross-machine).
            //
            // BUT re-founding must NOT assume "this node is always the founder":
            // a founder can go offline while its voter joiners keep the zone
            // alive (normal in a multi-party cluster), and on return it must
            // REJOIN — never re-found a SOLO zone of the same name, which would
            // split-brain against the survivors (raft §4).  Two guards keep this
            // safe: (1) gate on `resume_peers.is_empty()` — if this node knows
            // ANY peer/member (CLI --peers / identity.peers / identity.zones[]
            // .members), the zone lives on them, so the
            // `reconcile_federation_from_peers` call below REJOINS it and we skip
            // founding here; (2) even when peerless, `bootstrap_static` skips any
            // zone already on disk, so a normal restart only re-stages the
            // (idempotent) mount and never re-founds.  Net: a SOLO re-found
            // happens ONLY for a genuinely peerless founder whose declared zone
            // was never persisted — exactly the mint-before-boot bug.  Reuses the
            // SAME `bootstrap_static_async` as the `StaticFounder` arm (DRY: one
            // founding path, the two boot arms cannot diverge).
            if founder_declared && resume_peers.is_empty() {
                zm.bootstrap_static_async(
                    init_zones.clone(),
                    Vec::new(),
                    init_mounts.mounts.clone(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("resume re-assert founder topology: {}", e))?;
            }

            let reconciled = reconcile_federation_from_peers(
                zm.clone(),
                node_id,
                self_address.clone(),
                common.data_dir.clone(),
                resume_peers,
            )
            .await?;
            tracing::info!(
                cluster_init_zones = ?init_zones,
                own_topology_reasserted = founder_declared,
                reconciled_zones = reconciled,
                "boot resumed from disk — re-asserted founder's own declared \
                 topology (fstab model, peer-independent) + reconciled \
                 peer-reported zones",
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

    // Control zone (B2): the single REPLICATED home for the cluster-control
    // store (auth records + cross-org anchors), bound just below. The founder
    // founds it sole-voter; a joiner joins as a LEARNER (auth is founder-centric
    // — writes go to the founder, reads hit each node's local replica); a lone
    // founder founds it solo. Headless — no VFS mount. Must be OPEN before the
    // auth-store bind. Only with TLS (auth needs a CA); an auth-off node has no
    // control zone and binds the store to per-node `root` exactly as before
    // (no cluster, nothing to replicate). `ca-key.pem` is the founder signal
    // (same as the mint path): present ⇒ found sole-voter, absent ⇒ enrolled
    // joiner ⇒ learn. The learner join retries (`max_attempts`) so it self-heals
    // the boot race where a joiner starts before the founder's control zone is up.
    if !common.no_tls {
        let is_founder = common.data_dir.join("tls").join("ca-key.pem").exists();
        let zm_cz = zm.clone();
        let self_addr_cz = self_address.clone();
        let peers_cz = cli_peer_addrs.clone();
        let control_zone = contracts::CONTROL_ZONE_ID.to_string();
        tokio::task::spawn_blocking(move || {
            let peers: &[NodeAddress] = if is_founder { &[] } else { &peers_cz };
            nexus_raft::distributed_coordinator::bootstrap_or_join_zone(
                zm_cz.as_ref(),
                &control_zone,
                node_id,
                &self_addr_cz,
                peers,
                /* bootstrap_new */ is_founder,
                /* max_attempts  */ if is_founder { None } else { Some(15) },
                /* as_learner    */ !is_founder,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("control-zone bring-up task panicked: {e}"))?
        .map_err(|e| anyhow::anyhow!("bring up control zone: {e}"))?;
        tracing::info!(
            zone = %contracts::CONTROL_ZONE_ID,
            founder = is_founder,
            "control zone up — cluster-control store home (auth records + anchors)"
        );
    }

    // Auth-key store (Control-Plane HAL §3.B.3) + the cache eviction that
    // makes a revocation take effect without waiting out a TTL.
    //
    // Bound to the CONTROL zone's consensus: credentials are a cluster-wide
    // namespace, so a key minted on the founder must resolve on every node —
    // the control zone is replicated to every member (founder voter + learners),
    // whereas per-node `root` would silently give each node its own key space.
    // Auth-off has no control zone, so it falls back to `root` (no cluster,
    // nothing to replicate; `root` is always open, kernel-owned).
    //
    // The store is bound REGARDLESS of the auth posture. It costs one Arc and is
    // what lets `/__sys__/auth/keys/` answer and an operator mint keys on a
    // daemon that is not yet authenticating — the usual order of operations when
    // turning auth on for the first time. Only the cache-eviction observer is
    // conditional, because only a provider has a cache.
    {
        let auth_zone = if common.no_tls {
            contracts::ROOT_ZONE_ID
        } else {
            contracts::CONTROL_ZONE_ID
        };
        let cred_zone = zm.get_zone(auth_zone).ok_or_else(|| {
            anyhow::anyhow!(
                "credential-store zone '{auth_zone}' is not open — cannot bind the auth key \
                 store. The control zone is brought up just above (or `root`, kernel-owned, \
                 under --no-tls)."
            )
        })?;
        let consensus = cred_zone.consensus_node();
        let store = nexus_raft::auth_key_store::RaftAuthKeyStore::new_arc(
            consensus.clone(),
            cred_zone.runtime_handle(),
        );
        kernel.set_auth_key_store(Arc::clone(&store));

        // Arm the sk- MintKey/RevokeKey RPC on every auth-on node: the CLI dials
        // the LOCAL daemon and the store write forwards to the control-zone
        // leader, so `auth mint --subject-type user|service` / `revoke` work
        // WITHOUT stopping the daemon (matching the agent path). Auth-off has no
        // sk- plane — the slot stays empty and both RPCs return success=false.
        if !common.no_tls {
            if let Some(secret) = effective_api_key_secret(&common.data_dir.join("tls")) {
                let minter: Arc<dyn nexus_raft::key_minter::KeyMinter> =
                    Arc::new(DaemonKeyMinter {
                        store: Arc::clone(&store),
                        secret,
                    });
                *zm.key_minter_slot().write() = Some(minter);
                tracing::info!("sk- MintKey/RevokeKey RPC armed (mint while the daemon is up)");
            }
        }

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
                        // Evict the auth provider's cache only for AUTH-namespace
                        // control records; a foreign-ca anchor put/delete on the
                        // same command pair is not this provider's concern.
                        let key_hash = match &entry.command {
                            nexus_raft::prelude::Command::PutControlState {
                                namespace,
                                key,
                                ..
                            }
                            | nexus_raft::prelude::Command::DeleteControlState { namespace, key }
                                if namespace.as_str() == contracts::CONTROL_NS_AUTH =>
                            {
                                key
                            }
                            _ => return,
                        };
                        provider_for_evict.invalidate(key_hash);
                    },
                ));
                tracing::info!(zone = %auth_zone, "sk- API-key auth armed (credential store bound)");
            }
            None => {
                tracing::info!(
                    zone = %auth_zone,
                    "credential store bound; no auth provider installed, nothing resolves yet"
                );
            }
        }

        // Cross-org foreign-CA trust: the same control-zone consensus that homes
        // auth records also homes the foreign-CA anchors (CONTROL_NS_FOREIGN_CA).
        // Wire the shared client-cert verifier so a `RegisterForeignCa` /
        // unregister replicates and HOT-SWAPS the trusted client-auth set on
        // every node with no restart. Only auth-on (the verifier exists only
        // under TLS). Load already-registered anchors once at boot (a restart
        // re-derives the live set from the replicated store), then refresh on
        // each foreign-ca apply — mirroring the auth eviction observer above.
        if let Some(verifier) = zm.foreign_ca_verifier() {
            let fca_store = Arc::new(nexus_raft::foreign_ca_store::RaftForeignCaStore::new(
                consensus.clone(),
                cred_zone.runtime_handle(),
            ));
            match fca_store.list() {
                Ok(anchors) => {
                    if let Err(e) = verifier.set_foreign_cas(&anchors) {
                        tracing::warn!(error = %e, "initial foreign-CA trust load failed");
                    } else if !anchors.is_empty() {
                        tracing::info!(
                            count = anchors.len(),
                            "loaded registered foreign-CA anchors into the client-cert verifier"
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e, "could not list foreign-CA anchors at boot"),
            }
            let verifier_for_obs = verifier.clone();
            let store_for_obs = Arc::clone(&fca_store);
            consensus.register_apply_observer(Arc::new(
                move |entry: &nexus_raft::prelude::AppliedEntry| {
                    let is_foreign_ca = matches!(
                        &entry.command,
                        nexus_raft::prelude::Command::PutControlState { namespace, .. }
                            | nexus_raft::prelude::Command::DeleteControlState { namespace, .. }
                            if namespace.as_str() == contracts::CONTROL_NS_FOREIGN_CA
                    );
                    if !is_foreign_ca {
                        return;
                    }
                    // Full re-list → set_foreign_cas is idempotent across
                    // register (put) and unregister (delete).
                    match store_for_obs.list() {
                        Ok(anchors) => {
                            let _ = verifier_for_obs.set_foreign_cas(&anchors);
                        }
                        Err(e) => tracing::warn!(error = %e, "foreign-CA refresh: list failed"),
                    }
                },
            ));
            tracing::info!(
                "cross-org foreign-CA trust wired (hot-swap client-cert verifier on register/unregister)"
            );
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
    // Bring up the declared services through the ServiceRegistry — the
    // single authority for services. No per-service install code lives in
    // this boot path; `build_decls` (supplied by the entry point) hands us
    // the ordered set, parameterised by boot-derived config. a2a's
    // fail-closed posture is tied to auth (see the ServiceBootCtx doc): it
    // stamps `from` only-enforcing under auth, behaviour-preserving under
    // NoAuth (empty agent_id ⇒ fail-open ⇒ no rewrite).
    let svc_ctx = ServiceBootCtx {
        auth_armed: api_key_auth.is_some(),
    };
    kernel
        .bring_up_services(build_decls(&svc_ctx))
        .map_err(|e| anyhow::anyhow!("bring up services: {e}"))?;

    // (2) Arm the cross-machine stream-wakeup observer PER ZONE: a
    // replicated `AppendStreamEntry` (a chat-with-me DT_STREAM write on a
    // peer) wakes a `sys_watch` parked on this replica. The observer is a
    // generic raft primitive (`nexus_raft::stream_wakeup`), armed here —
    // NOT in a2a — because it needs a `Weak<Kernel>` (the `Arc` lives
    // here). It self-recovers the watched path from the wal-stream key, so
    // no per-zone mapping is threaded in. Root covers node-local
    // `/agents`; every federation mount (`--cluster-init-mount
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
        // `--cluster-init-mount`: a JOINER reaches its shared zones via
        // DiscoverZones / identity.zones with no `--cluster-init` (a
        // `--cluster-init` alongside `--peers` is a fail-loud ambiguous
        // boot — see `plan_boot_action` row 6), so keying off the init mounts
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
    //      declared zones + cross-zone mounts (`--cluster-init*`)
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
        // itself is created elsewhere — via `--cluster-init`
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
                 declare via --cluster-init (founder) or run \
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

    // An agent reaches the kernel over the same `--bind-addr` mTLS bind as
    // cluster peers, presenting its identity cert (SAN nexus://agent/{name});
    // `peer_identity` resolves the SAN to an `agent_id` and its mailbox writes
    // carry an unforgeable `from`. Nodes and agents share the bind — `resolve()`
    // tells them apart by SAN type — so there is no separate agent bind.
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
/// (multi-zone from `--cluster-init-mount` / identity.zones).
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
    // Resolve the cluster API-key secret from the SAME SSOT the daemon uses
    // (`effective_api_key_secret`): the persisted `tls/api-key-secret` if present
    // (written by enrollment on a joiner), else `NEXUS_API_KEY_SECRET`. So a node
    // that has enrolled can mint with NO env at all — closing the last
    // secret-coordination gap (the daemon already needs none). The key is looked
    // up by its HMAC under this secret, so it MUST match the cluster's.
    let secret = effective_api_key_secret(&common.data_dir.join("tls")).ok_or_else(|| {
        anyhow::anyhow!(
            "no cluster API-key secret found: set NEXUS_API_KEY_SECRET, or run this on a \
             node that has enrolled (enrollment writes tls/api-key-secret). A key is \
             looked up by its HMAC under that secret, so a mismatch mints a key the \
             daemon will never recognise"
        )
    })?;

    // Which zone holds the credential store depends on the posture, and it must
    // match what the daemon binds (B2):
    //   * auth-on  → the replicated CONTROL zone, founder-founded sole-voter. An
    //     offline mint here is the FOUNDER cold-start / DR path — safe because
    //     the founder is the zone's only voter (no concurrent voter to diverge
    //     against).
    //   * auth-off → per-node `root` (no cluster, nothing to replicate); the
    //     daemon binds root too under `--no-tls`.
    // We open ONLY that one zone: loading the federated shares would spin each up
    // as a lone node and mutate its term/vote so the real daemon resumes DIVERGED
    // (the #24 hazard). See `ZoneLoadPolicy`.
    //
    // Refuse offline auth on an ENROLLED JOINER — precisely `node.pem` present
    // (a cluster-issued cert) AND `ca-key.pem` absent (not the CA holder). Such a
    // node founding a control zone offline would split-brain the cluster's auth
    // state, so it must forward to the live daemon instead. This is the SAME
    // signal the `run_auth` intercept uses. A CA holder (`ca-key.pem` present)
    // AND a fresh founder-to-be dir (neither file — `open_zone_manager`
    // bootstraps its CA below) are BOTH allowed: the latter is a founder's
    // legitimate cold-start (`auth mint` before the first daemon boot).
    let auth_zone = if common.no_tls {
        contracts::ROOT_ZONE_ID
    } else {
        let tls_dir = common.data_dir.join("tls");
        let enrolled_joiner =
            tls_dir.join("node.pem").exists() && !tls_dir.join("ca-key.pem").exists();
        if enrolled_joiner {
            return Err(anyhow::anyhow!(
                "this node is an enrolled joiner (holds a node cert but not the cluster CA \
                 key); offline `auth` cannot write cluster auth state here. Run the mint \
                 against the live daemon (start it — the write forwards to the founder over \
                 consensus), or run it on the founder."
            ));
        }
        contracts::CONTROL_ZONE_ID
    };

    // Offline tooling cannot open the data dir while the daemon holds its
    // exclusive redb lock — by far the dominant failure here — so name that
    // cause up front rather than leaking a raw redb/OS error.
    let ZoneManagerBundle { zm, .. } = open_zone_manager(
        common,
        None,
        ZoneLoadPolicy::Only(vec![auth_zone.to_string()]),
    )
    .context(
        "offline `auth` could not open the data dir; if the daemon is running, \
         stop it first (it holds an exclusive lock)",
    )?;
    // Found-on-demand as a SOLO voter: correct for both `root` (per-node, always
    // solo) and the founder's control zone (founder = sole voter). Idempotent
    // with a later daemon boot, which resumes the on-disk zone rather than
    // re-founding it.
    if zm.get_zone(auth_zone).is_none() {
        zm.create_zone(auth_zone, Vec::new())
            .map_err(|e| anyhow::anyhow!("open {auth_zone} zone: {e}"))?;
    }
    let cred_zone = zm
        .get_zone(auth_zone)
        .ok_or_else(|| anyhow::anyhow!("{auth_zone} zone did not open"))?;

    // Writes go through consensus, so this node has to be able to commit. The
    // zone is SOLO here (root per-node, or the founder's sole-voter control
    // zone), so leadership is immediate -- but wait for it rather than race the
    // campaign and fail with a confusing `not leader`.
    if !cred_zone.wait_for_leader(std::time::Duration::from_secs(10)) {
        return Err(anyhow::anyhow!(
            "{auth_zone} zone has no leader after 10s -- cannot commit a credential"
        ));
    }

    let store = nexus_raft::auth_key_store::RaftAuthKeyStore::new_arc(
        cred_zone.consensus_node(),
        cred_zone.runtime_handle(),
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

/// Write an agent's signed bundle (`agent.pem` / `agent-key.pem` / `ca.pem`)
/// under `<data_dir>/agents/<subject_id>/` and return the directory. The one
/// on-disk layout the local mint (`run_auth_action`) and the remote mint
/// (`mint_agent_via_founder`) share — extracted so the two paths cannot drift.
fn write_agent_bundle(
    data_dir: &std::path::Path,
    subject_id: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
) -> Result<std::path::PathBuf> {
    let out_dir = data_dir.join("agents").join(subject_id);
    std::fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    std::fs::write(out_dir.join("agent.pem"), cert_pem)
        .with_context(|| format!("write {}/agent.pem", out_dir.display()))?;
    std::fs::write(out_dir.join("agent-key.pem"), key_pem)
        .with_context(|| format!("write {}/agent-key.pem", out_dir.display()))?;
    std::fs::write(out_dir.join("ca.pem"), ca_pem)
        .with_context(|| format!("write {}/ca.pem", out_dir.display()))?;
    Ok(out_dir)
}

/// Founder-side [`nexus_raft::agent_minter::AgentMinter`]: signs an agent
/// identity cert with the cluster CA and records it in the replicated auth
/// store, serving a remote `MintAgent` call from another node. Installed ONLY
/// on the CA holder (see the founder-install block in `run_daemon`).
///
/// This is the SAME two reusable units the local CLI agent-mint path calls
/// (`generate_agent_cert` + `mint_agent_authz`), so the remote and local paths
/// stay byte-identical by construction — they differ only in WHERE the CA key
/// is read and the bundle is written. The caller is gated to a cluster NODE:
/// mTLS already proved the client leaf chains to the cluster CA; we additionally
/// require it be a node identity, so an agent cert (a pure identity) can never
/// be leveraged into minting further agents (privilege confinement).
struct FounderAgentMinter {
    store: Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    tls_dir: PathBuf,
}

#[tonic::async_trait]
impl nexus_raft::agent_minter::AgentMinter for FounderAgentMinter {
    async fn mint(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        subject_id: &str,
        display_name: &str,
        allow_existing: bool,
    ) -> std::result::Result<nexus_raft::agent_minter::AgentBundle, String> {
        // Gate: node-only. An agent cert carries no authorization, so a valid
        // agent cert must never be leverageable into minting more agents.
        gate_node_caller(caller_cert_der, "MintAgent")?;

        let ca_pem = std::fs::read(self.tls_dir.join("ca.pem"))
            .map_err(|e| format!("read {}/ca.pem: {e}", self.tls_dir.display()))?;
        let ca_key_pem = std::fs::read(self.tls_dir.join("ca-key.pem"))
            .map_err(|e| format!("read {}/ca-key.pem: {e}", self.tls_dir.display()))?;
        let (cert_pem, key_pem) =
            nexus_raft::transport::generate_agent_cert(subject_id, &ca_pem, &ca_key_pem)
                .map_err(|e| format!("generate agent cert: {e}"))?;

        // The record is uniqueness + audit only for agents (the cert itself
        // governs authentication and its own lifetime), so the remote path
        // carries no expiry — matching the local mint, whose `--expires-in-days`
        // sets only this audit field and never the cert validity.
        let record = auth::AuthKeyRecord {
            key_id: uuid_v4(),
            name: display_name.to_string(),
            subject_type: auth::SubjectType::Agent,
            subject_id: subject_id.to_string(),
            is_admin: false,
            revoked: false,
            expires_at_ms: None,
            zone_perms: Vec::new(),
        };
        auth::mint_agent_authz(&self.store, record, allow_existing)
            .map_err(|e| format!("record agent: {e}"))?;

        Ok(nexus_raft::agent_minter::AgentBundle {
            cert_pem,
            key_pem,
            ca_pem,
        })
    }
}

/// Gate a control-plane mint RPC to a cluster NODE caller: the mTLS client leaf
/// must parse to a node identity. Minting a credential (agent cert or sk- key)
/// is a node/admin operation, so a bare agent cert — a pure identity — must
/// never be leverageable into it. Shared by `FounderAgentMinter` and
/// `DaemonKeyMinter` so both gates read identically.
fn gate_node_caller(caller_cert_der: Option<Vec<u8>>, op: &str) -> std::result::Result<(), String> {
    let der = caller_cert_der.ok_or_else(|| format!("{op} requires an mTLS client certificate"))?;
    let peer = transport::peer_identity::from_der(&der)
        .ok_or_else(|| format!("{op}: client certificate did not parse"))?;
    if peer.node_id.is_none() {
        return Err(format!(
            "{op} is a node-only operation; caller {} is not a cluster node",
            peer.display_id(),
        ));
    }
    Ok(())
}

/// Validate + build an `sk-` (user/service) auth record from the raw mint
/// params. The ONE place the subject-type parse, zone-grant parse, and the
/// "no grants ⇒ refused" rule live — shared by the offline path
/// (`run_auth_action`) and the live-daemon [`DaemonKeyMinter`], so they cannot
/// drift. Rejects `agent` (cert-only, minted via [`FounderAgentMinter`]).
fn build_sk_record(
    subject_type: &str,
    subject_id: String,
    zones: &[String],
    admin: bool,
    expires_at_ms: Option<u64>,
    name: String,
) -> Result<auth::AuthKeyRecord> {
    let subject_type = match subject_type {
        "user" => auth::SubjectType::User,
        "service" => auth::SubjectType::Service,
        "agent" => {
            return Err(anyhow::anyhow!(
                "an agent's credential is a CA-signed cert, not an sk- key — mint it with \
                 `--subject-type agent` (handled on the cert plane), not here"
            ))
        }
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
            "a key with no zone grants reaches nothing and is refused at authentication \
             time. Pass --zone ZONE:PERMS, or --admin for a global admin (the only \
             principal allowed a zoneless key)."
        ));
    }
    Ok(auth::AuthKeyRecord {
        key_id: uuid_v4(),
        name,
        subject_type,
        subject_id,
        is_admin: admin,
        revoked: false,
        expires_at_ms,
        zone_perms,
    })
}

/// Live-daemon [`nexus_raft::key_minter::KeyMinter`]: mints / revokes `sk-`
/// credentials against the running daemon's control-zone auth store, so
/// `auth mint --subject-type user|service` and `auth revoke` work WITHOUT
/// stopping the daemon. The write goes through consensus (the store's `put` /
/// `delete` forwards to the control-zone leader), so an install on ANY auth-on
/// node serves it. Node-cert gated (an admin op). Installed on every auth-on
/// daemon (see the install block in `run_daemon`).
struct DaemonKeyMinter {
    store: Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    secret: String,
}

#[tonic::async_trait]
impl nexus_raft::key_minter::KeyMinter for DaemonKeyMinter {
    async fn mint_key(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        params: nexus_raft::key_minter::MintKeyParams,
    ) -> std::result::Result<String, String> {
        gate_node_caller(caller_cert_der, "MintKey")?;
        let expires_at_ms = if params.expires_at_ms == 0 {
            None
        } else {
            Some(params.expires_at_ms)
        };
        let record = build_sk_record(
            &params.subject_type,
            params.subject_id,
            &params.zones,
            params.admin,
            expires_at_ms,
            params.name,
        )
        .map_err(|e| e.to_string())?;
        let minted = auth::mint_key(&self.store, &self.secret, record, params.allow_existing)
            .map_err(|e| e.to_string())?;
        Ok(minted.key)
    }

    async fn revoke_key(
        &self,
        caller_cert_der: Option<Vec<u8>>,
        key: Option<String>,
        key_hash: Option<String>,
    ) -> std::result::Result<bool, String> {
        gate_node_caller(caller_cert_der, "RevokeKey")?;
        match (key, key_hash) {
            (Some(key), None) => auth::revoke_key(&self.store, &self.secret, &key),
            (None, Some(hash)) => auth::revoke_key_hash(&self.store, &hash),
            _ => return Err("revoke: pass exactly one of --key or --key-hash".to_string()),
        }
        .map_err(|e| e.to_string())
    }

    async fn list_keys(
        &self,
        caller_cert_der: Option<Vec<u8>>,
    ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
        gate_node_caller(caller_cert_der, "ListKeys")?;
        // A read of the local applied replica (no leader round-trip); on a
        // learner it returns that node's replicated records.
        self.store.list().map_err(|e| e.to_string())
    }
}

/// mTLS endpoint URLs to try for a remote agent mint: the union of `--peers`
/// and the persisted `identity.json` peer address book, parsed the same way the
/// daemon seeds its transport peer map. The founder is whichever one holds the
/// CA (its `MintAgent` slot is armed); the rest reply "does not hold the cluster
/// CA" and the caller moves on.
fn founder_candidate_endpoints(common: &CommonArgs) -> Result<Vec<String>> {
    let mut seed: Vec<String> = common
        .peers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let identity_dir = common
        .identity_dir
        .clone()
        .unwrap_or_else(nexus_raft::identity::default_identity_dir);
    if let Ok(ident) = nexus_raft::identity::load(&identity_dir) {
        for p in ident.peers {
            if !seed.iter().any(|s| s == &p) {
                seed.push(p);
            }
        }
    }
    if seed.is_empty() {
        return Ok(Vec::new());
    }
    let parsed = NodeAddress::parse_peer_list_operator(&seed.join(","), /* use_tls */ true)
        .map_err(|e| anyhow::anyhow!("parse peers for remote agent mint: {e}"))?;
    Ok(parsed.into_iter().map(|p| p.endpoint).collect())
}

/// This node's OWN daemon data-plane endpoint on loopback. Prepended to the mint
/// candidates so an agent mint reaches the local daemon's `MintAgent` first — it
/// is armed on a founder (so the founder mints via its own running daemon, no
/// store lock) and declines on a joiner (falls through to a founder peer). The
/// discriminator is thus daemon-reachability, not "do I hold the CA key".
///
/// The port is resolved from `effective_bind_addr` — the daemon's env or the
/// `2126` default — a kubectl-style ops contract: run `auth` in the same
/// environment the daemon booted with (`NEXUS_ADVERTISE_ADDR`/`NEXUS_BIND_ADDR`),
/// or on the default port. If the daemon runs on a NON-default port and the CLI's
/// env omits it, the self-dial misses and (for a CA holder) falls back to an
/// offline sign, which then fails loud on the daemon's redb lock — never a silent
/// wrong result. A runtime addr sidecar would drop even that env dependency, but
/// the daemon's live listen addr is ephemeral runtime state that has no business
/// in the persistent data dir (principle 5); the env contract is the deliberate
/// trade.
fn self_daemon_endpoint(common: &CommonArgs) -> Option<String> {
    let bind = common.effective_bind_addr();
    let port = bind
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())?;
    Some(format!("https://127.0.0.1:{port}"))
}

/// How a forwarded agent mint ended, so `run_auth` can decide between surfacing
/// the error and falling back to an offline cold-start sign.
enum MintForwardError {
    /// A CA-holder daemon was reached and authoritatively refused (name already
    /// taken, caller not a node, `--zone`/`--admin` misuse). Never retried, never
    /// fallen back — the answer is final.
    Refused(String),
    /// No CA-holder daemon was reachable (every candidate was unreachable or
    /// replied "not the CA holder"). The caller MAY fall back to an offline sign
    /// — but only if it holds the CA key itself (a founder at cold-start, daemon
    /// down); otherwise this is terminal.
    Unreachable(String),
}

/// Mint an agent cert through a live cluster daemon over mTLS: the local daemon
/// first (armed on a founder → mints via itself, no store lock; declines on a
/// joiner), then founder peers. The CA holder signs + records the agent through
/// its running raft (cluster-wide name uniqueness + audit live there); this node
/// writes the returned bundle to `<data_dir>/agents/<subject_id>/`, byte-
/// identical to an offline local mint. Works whether or not THIS node's own
/// daemon is up. See [`MintForwardError`] for how the outcome is classified.
async fn mint_agent_via_founder(
    common: &CommonArgs,
    action: &AuthCmd,
) -> std::result::Result<(), MintForwardError> {
    let AuthCmd::Mint {
        subject_id,
        zones,
        admin,
        name,
        allow_existing,
        ..
    } = action
    else {
        unreachable!("mint_agent_via_founder called with a non-Mint action");
    };
    // Same pure-identity refusal as the local agent-mint path — an authoritative
    // user error, surfaced before any RPC (never a fallback).
    if !zones.is_empty() || *admin {
        return Err(MintForwardError::Refused(
            "an agent cert is a pure identity and carries no authorization; \
             --zone / --admin do not apply. Mint a --subject-type user or service \
             key for a principal that needs zone grants."
                .to_string(),
        ));
    }
    let display_name = if name.is_empty() {
        subject_id.as_str()
    } else {
        name.as_str()
    };

    // The client identity is this node's cluster node cert; the daemon's
    // MintAgent gate requires a NODE caller. A read failure here is local
    // misconfiguration, not "unreachable" — surface it (no offline fallback).
    let tls =
        load_node_tls(&common.data_dir).map_err(|e| MintForwardError::Refused(e.to_string()))?;

    // Candidates: this node's own daemon first (loopback), then --peers ∪
    // identity. A malformed --peers is a user error → Refused.
    let mut candidates: Vec<String> = Vec::new();
    if let Some(s) = self_daemon_endpoint(common) {
        candidates.push(s);
    }
    for e in
        founder_candidate_endpoints(common).map_err(|e| MintForwardError::Refused(e.to_string()))?
    {
        if !candidates.contains(&e) {
            candidates.push(e);
        }
    }
    if candidates.is_empty() {
        return Err(MintForwardError::Unreachable(
            "no local daemon or peer known to mint the agent through".to_string(),
        ));
    }

    let mut last_err = String::new();
    for endpoint in &candidates {
        match nexus_raft::transport::call_mint_agent_rpc(
            endpoint,
            subject_id,
            display_name,
            *allow_existing,
            Some(tls.clone()),
            /* timeout_secs */ 15,
        )
        .await
        {
            Ok(result) if result.success => {
                let out_dir = write_agent_bundle(
                    &common.data_dir,
                    subject_id,
                    &result.agent_cert_pem,
                    &result.agent_key_pem,
                    &result.ca_pem,
                )
                .map_err(|e| MintForwardError::Refused(e.to_string()))?;

                // The bundle directory on stdout alone, identical to the local
                // path so `DIR=$(nexusd-cluster auth mint --subject-type agent
                // NAME ...)` captures it on any node.
                println!("{}", out_dir.display());
                eprintln!(
                    "minted agent cert subject=agent:{subject_id} via {endpoint} -> {}",
                    out_dir.display()
                );
                eprintln!(
                    "The agent presents agent.pem + agent-key.pem and trusts the server via ca.pem."
                );
                return Ok(());
            }
            Ok(result) => {
                // Reached a daemon, but it refused. "does not hold the cluster CA"
                // ⇒ not the CA holder, try the next; any other refusal (name
                // taken, caller not a node, …) is authoritative — surface it.
                let msg = result.error.unwrap_or_default();
                if msg.contains("does not hold the cluster CA") {
                    last_err = format!("{endpoint}: {msg}");
                    continue;
                }
                return Err(MintForwardError::Refused(format!(
                    "{endpoint} refused agent mint: {msg}"
                )));
            }
            Err(e) => {
                last_err = format!("{endpoint}: {e}");
                continue;
            }
        }
    }
    Err(MintForwardError::Unreachable(format!(
        "no reachable CA-holder daemon (last: {last_err}); tried: {}",
        candidates.join(", ")
    )))
}

/// Load this node's cluster node-cert TLS bundle (`node.pem` / `node-key.pem` /
/// `ca.pem`) — the mTLS client identity the CLI presents when dialing a live
/// daemon's node-cert-gated admin RPCs (`MintAgent` / `MintKey` / `RevokeKey`).
/// Shared by every daemon-routed `auth` path.
fn load_node_tls(data_dir: &std::path::Path) -> Result<nexus_raft::transport::TlsConfig> {
    let tls_dir = data_dir.join("tls");
    let read =
        |p: std::path::PathBuf| std::fs::read(&p).with_context(|| format!("read {}", p.display()));
    Ok(nexus_raft::transport::TlsConfig {
        cert_pem: read(tls_dir.join("node.pem"))?,
        key_pem: read(tls_dir.join("node-key.pem"))?,
        ca_pem: read(tls_dir.join("ca.pem"))?,
    })
}

/// Outcome of trying an `sk-` mint/revoke against the LOCAL live daemon.
enum DaemonOutcome {
    /// The daemon handled it (success already printed).
    Handled,
    /// The local daemon was unreachable — the caller may fall back to the
    /// offline path (founder cold-start). Carries context for logging.
    Unreachable(String),
}

/// Route an `sk-` mint / revoke through this node's LIVE daemon over loopback
/// mTLS (`MintKey` / `RevokeKey`). The daemon HMACs + writes through consensus
/// (the write forwards to the control-zone leader), so it works on any auth-on
/// node without stopping the daemon. `Err` = the daemon reached us and refused
/// authoritatively (never fall back); `Ok(Unreachable)` = no daemon (fall back
/// to offline). Dials the local daemon only — propose-forwarding reaches the
/// leader, so no founder discovery is needed for the sk- plane.
async fn sk_via_daemon(common: &CommonArgs, action: &AuthCmd) -> Result<DaemonOutcome> {
    let tls = load_node_tls(&common.data_dir)?;
    let endpoint = self_daemon_endpoint(common)
        .ok_or_else(|| anyhow::anyhow!("cannot derive the local daemon endpoint from bind addr"))?;
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
            let expires_at_ms = expires_in_days
                .map(|days| {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    now_ms + days * 24 * 60 * 60 * 1000
                })
                .unwrap_or(0);
            let args = nexus_raft::transport::MintKeyArgs {
                subject_type,
                subject_id,
                zones: zones.clone(),
                admin: *admin,
                expires_at_ms,
                name,
                allow_existing: *allow_existing,
            };
            match nexus_raft::transport::call_mint_key_rpc(&endpoint, args, Some(tls), 15).await {
                Ok(Ok(key)) => {
                    // The one moment the key exists in the clear — stdout alone,
                    // so `KEY=$(nexusd-cluster auth mint ...)` captures it.
                    println!("{key}");
                    eprintln!("minted sk- key via the local daemon {endpoint} (replicated to the cluster control zone)");
                    eprintln!("This key will not be shown again - it is stored only as an HMAC.");
                    Ok(DaemonOutcome::Handled)
                }
                Ok(Err(msg)) => Err(anyhow::anyhow!("{endpoint} refused mint: {msg}")),
                Err(e) => Ok(DaemonOutcome::Unreachable(format!("{endpoint}: {e}"))),
            }
        }
        AuthCmd::Revoke { key, key_hash, .. } => {
            match nexus_raft::transport::call_revoke_key_rpc(
                &endpoint,
                key.clone(),
                key_hash.clone(),
                Some(tls),
                15,
            )
            .await
            {
                Ok(Ok(removed)) => {
                    println!(
                        "{}",
                        if removed {
                            "revoked"
                        } else {
                            "no such key (already revoked?)"
                        }
                    );
                    Ok(DaemonOutcome::Handled)
                }
                Ok(Err(msg)) => Err(anyhow::anyhow!("{endpoint} refused revoke: {msg}")),
                Err(e) => Ok(DaemonOutcome::Unreachable(format!("{endpoint}: {e}"))),
            }
        }
        AuthCmd::List => {
            match nexus_raft::transport::call_list_keys_rpc(&endpoint, Some(tls), 15).await {
                Ok(Ok(records)) => {
                    print_key_records(records);
                    Ok(DaemonOutcome::Handled)
                }
                Ok(Err(msg)) => Err(anyhow::anyhow!("{endpoint} refused list: {msg}")),
                Err(e) => Ok(DaemonOutcome::Unreachable(format!("{endpoint}: {e}"))),
            }
        }
    }
}

async fn run_auth(common: CommonArgs, action: AuthCmd) -> Result<()> {
    // Agent-cert mint (task #40): route through a LIVE cluster daemon whenever
    // one is reachable, so `auth mint --subject-type agent NAME` just-works on
    // ANY enrolled node — founder or joiner — regardless of whether the local
    // daemon is up. The discriminator is daemon-reachability, NOT "do I hold the
    // CA key": `mint_agent_via_founder` tries this node's own daemon first (armed
    // on a founder → mints via itself with no store lock; declines on a joiner)
    // then founder peers. It dials RPCs only (no local store / ZoneManager), so
    // it runs HERE in the async context and never contends the redb lock.
    //
    // Only an ENROLLED node (has a cluster-issued `node.pem`) can present the
    // node identity the mint gate requires, so a fresh/unenrolled dir (no
    // node.pem) and an auth-off (`--no-tls`) node fall through to the offline
    // path, where `open_zone_manager` bootstraps this node's own CA as a
    // founder-to-be. `ca-key.pem` is no longer a routing input — it only decides
    // whether an UNREACHABLE forward may fall back to an offline cold-start sign
    // (legal solely for the CA holder, and only while no daemon is up).
    let enrolled = !common.no_tls && common.data_dir.join("tls").join("node.pem").exists();
    let has_ca_key = common.data_dir.join("tls").join("ca-key.pem").exists();
    match &action {
        // Agent-cert mint: try the daemon (self → founder peers), else offline
        // cold-start sign (CA holder only).
        AuthCmd::Mint { subject_type, .. } if subject_type == "agent" && enrolled => {
            match mint_agent_via_founder(&common, &action).await {
                Ok(()) => return Ok(()),
                Err(MintForwardError::Refused(msg)) => return Err(anyhow::anyhow!("{msg}")),
                Err(MintForwardError::Unreachable(ctx)) => {
                    if has_ca_key {
                        tracing::info!(
                            reason = %ctx,
                            "no reachable cluster daemon; signing the agent offline as the CA holder (cold-start)"
                        );
                        // fall through to the offline path
                    } else {
                        return Err(anyhow::anyhow!(
                            "{ctx}; and this node holds no CA key to sign the agent offline"
                        ));
                    }
                }
            }
        }
        // sk- (user/service) mint + sk- revoke: route through the LOCAL daemon
        // (the write forwards to the control-zone leader), so it works without
        // stopping the daemon. Unreachable ⇒ fall back to the offline path
        // (founder cold-start; a joiner is refused there). Agent revoke
        // (`--agent`) is CRL-file-based and handled offline below.
        AuthCmd::Mint { subject_type, .. } if subject_type != "agent" && enrolled => {
            match sk_via_daemon(&common, &action).await? {
                DaemonOutcome::Handled => return Ok(()),
                DaemonOutcome::Unreachable(ctx) => {
                    tracing::info!(reason = %ctx, "no reachable local daemon; minting sk- key offline");
                }
            }
        }
        AuthCmd::Revoke { agent: None, .. } if enrolled => {
            match sk_via_daemon(&common, &action).await? {
                DaemonOutcome::Handled => return Ok(()),
                DaemonOutcome::Unreachable(ctx) => {
                    tracing::info!(reason = %ctx, "no reachable local daemon; revoking sk- key offline");
                }
            }
        }
        // list reads the LOCAL daemon's replica (no leader round-trip), so an
        // enrolled joiner can inspect its own replicated records without opening
        // the store offline (which its gate refuses). Unreachable ⇒ offline
        // (works on a founder; a joiner is refused there, pointing at the daemon).
        AuthCmd::List if enrolled => match sk_via_daemon(&common, &action).await? {
            DaemonOutcome::Handled => return Ok(()),
            DaemonOutcome::Unreachable(ctx) => {
                tracing::info!(reason = %ctx, "no reachable local daemon; listing keys offline");
            }
        },
        _ => {}
    }

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
    // Agent-cert revocation is file-based (no redb): it appends the cert's
    // serial to the founder's revoked-serial file, which the running GetCrl
    // endpoint reads live. So it takes no store lock and works while the daemon
    // is up — unlike the `sk-` paths below, which open the replicated store.
    if let AuthCmd::Revoke {
        agent: Some(name), ..
    } = &action
    {
        return revoke_agent_cert(&common.data_dir, name);
    }
    let (zm, store, secret) = open_auth_store(&common)?;
    let result = run_auth_action(&store, &secret, &common.data_dir, action);
    // Release the data directory's lock before returning, or a daemon started
    // right after this exits fails to open redb.
    zm.shutdown();
    result
}

/// Keep the auth provider's revoked-serial set current from the cluster CRL —
/// the CA's own trust plane, orthogonal to raft. The founder reads its
/// revoked-serial file directly (it is the SSOT); a joiner fetches the
/// CA-signed CRL from the founder's enroll addr and verifies it against its own
/// CA before applying it, so a forged CRL can neither un-revoke nor falsely
/// revoke. A fetch or verify failure keeps the last known set rather than
/// clearing it — a transient founder outage must not un-revoke an agent.
async fn crl_refresh_loop(
    provider: std::sync::Arc<auth::ApiKeyAuthProvider>,
    data_dir: std::path::PathBuf,
    ca_key_holder: bool,
    founder_enroll: Option<String>,
) {
    const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
    let ca_path = data_dir.join("tls").join("ca.pem");
    loop {
        let serials: Option<Vec<Vec<u8>>> = if ca_key_holder {
            let path = nexus_raft::transport::revoked_serials_path(&data_dir);
            Some(nexus_raft::transport::read_revoked_serials(&path))
        } else if let Some(addr) = &founder_enroll {
            match nexus_raft::transport::call_get_crl(addr, 10).await {
                Ok(crl) => match std::fs::read(&ca_path) {
                    Ok(ca) => match nexus_raft::transport::crl_revoked_serials(&crl, &ca) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            tracing::warn!(error = %e, "CRL failed CA verification; keeping current set");
                            None
                        }
                    },
                    Err(e) => {
                        tracing::debug!(error = %e, "CRL refresh: CA cert unreadable");
                        None
                    }
                },
                Err(e) => {
                    tracing::debug!(error = %e, "CRL fetch failed; keeping current set");
                    None
                }
            }
        } else {
            None
        };
        if let Some(serials) = serials {
            provider.set_revoked_serials(serials.into_iter().collect());
        }
        tokio::time::sleep(REFRESH_INTERVAL).await;
    }
}

/// Revoke an agent's cert: read its serial from the minted bundle and append it
/// to the founder's revoked-serial file (the CA-plane CRL source). File-based,
/// so it needs no store lock; the founder's GetCrl serves the updated CRL and
/// every node drops the agent after its next CRL refresh. Runs on the founder,
/// where the bundle was minted and the CA lives.
fn revoke_agent_cert(data_dir: &std::path::Path, name: &str) -> Result<()> {
    let cert_path = data_dir.join("agents").join(name).join("agent.pem");
    let cert_pem = std::fs::read(&cert_path).with_context(|| {
        format!(
            "revoke agent {name}: read {} — revocation runs on the founder, where the cert \
             bundle was minted",
            cert_path.display()
        )
    })?;
    let serial = nexus_raft::transport::serial_from_cert_pem(&cert_pem)
        .map_err(|e| anyhow::anyhow!("read serial from {}: {e}", cert_path.display()))?;
    let path = nexus_raft::transport::revoked_serials_path(data_dir);
    nexus_raft::transport::add_revoked_serial(&path, &serial)
        .map_err(|e| anyhow::anyhow!("record revoked serial: {e}"))?;
    let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!(
        "revoked agent cert subject=agent:{name} serial={serial_hex} -> {}",
        path.display()
    );
    println!("revoked");
    Ok(())
}

fn run_auth_action(
    store: &std::sync::Arc<dyn kernel::hal::auth_key_store::AuthKeyStore>,
    secret: &str,
    data_dir: &std::path::Path,
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
            let expires_at_ms = expires_in_days.map(|days| {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                now_ms + days * 24 * 60 * 60 * 1000
            });

            // An agent's credential IS a CA-signed identity cert, never an
            // `sk-` token: the cert both authenticates it over mTLS and signs
            // its messages, so a consumer on another node — a different trust
            // domain — verifies the `from` against the cluster CA without
            // trusting whoever ingested it (Nexus Auth Architecture §5). One
            // subject type, one credential kind: `--subject-type agent` issues a
            // cert; `user` / `service` keep the `sk-` token plane below.
            //
            // The cert is a pure identity (a DID): it carries no authorization,
            // so a valid agent cert is simply a mailbox principal (rw the A2A
            // area — the resolver grants that fixed scope). `--zone` / `--admin`
            // do not apply; a principal that needs zone grants holds a `user` /
            // `service` key instead. The founder-local record below exists for
            // cluster-wide name uniqueness + audit, not for resolution.
            //
            // Placement: the reusable units live in libraries — `generate_agent_cert`
            // (raft::transport) and `mint_agent_authz` (auth). Only this operator-CLI
            // glue (on-disk bundle layout + the stdout path contract) is
            // profile-resident, because it is CLI-specific. A runtime service that
            // provisions agents programmatically calls those two units directly and
            // returns the bytes in memory rather than writing a bundle.
            if subject_type == auth::SubjectType::Agent {
                if !zones.is_empty() || admin {
                    return Err(anyhow::anyhow!(
                        "an agent cert is a pure identity and carries no authorization; \
                         --zone / --admin do not apply. Mint a --subject-type user or \
                         service key for a principal that needs zone grants."
                    ));
                }
                let name_id = subject_id.clone();
                let record = auth::AuthKeyRecord {
                    key_id: uuid_v4(),
                    name,
                    subject_type,
                    subject_id,
                    is_admin: false,
                    revoked: false,
                    expires_at_ms,
                    zone_perms: Vec::new(),
                };
                let tls_dir = data_dir.join("tls");
                let ca_pem = std::fs::read(tls_dir.join("ca.pem")).with_context(|| {
                    format!(
                        "agent certs are issued on the founder (it holds the CA): reading {}/ca.pem",
                        tls_dir.display()
                    )
                })?;
                let ca_key_pem = std::fs::read(tls_dir.join("ca-key.pem")).with_context(|| {
                    format!(
                        "agent certs need the CA private key, present only on the founder: reading {}/ca-key.pem",
                        tls_dir.display()
                    )
                })?;
                let (cert_pem, key_pem) =
                    nexus_raft::transport::generate_agent_cert(&name_id, &ca_pem, &ca_key_pem)
                        .map_err(|e| anyhow::anyhow!("generate agent cert: {e}"))?;
                auth::mint_agent_authz(store, record, allow_existing)
                    .map_err(|e| anyhow::anyhow!("mint agent: {e}"))?;

                let out_dir = write_agent_bundle(data_dir, &name_id, &cert_pem, &key_pem, &ca_pem)?;

                // The bundle directory on stdout alone, so
                // `DIR=$(nexusd-cluster auth mint --subject-type agent NAME ...)`
                // captures it and nothing else.
                println!("{}", out_dir.display());
                eprintln!(
                    "minted agent cert subject=agent:{name_id} -> {}",
                    out_dir.display()
                );
                eprintln!(
                    "The agent presents agent.pem + agent-key.pem and trusts the server via ca.pem."
                );
                return Ok(());
            }

            // The `sk-` token plane: user / service keys. Built through the same
            // `build_sk_record` the live-daemon `DaemonKeyMinter` uses, so the
            // offline and daemon-up paths validate + shape the record identically.
            let record = build_sk_record(
                subject_type.as_str(),
                subject_id,
                &zones,
                admin,
                expires_at_ms,
                name,
            )?;

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
        // `agent` is handled file-based in `run_auth_blocking` before the store
        // opens, so here it is always `None`.
        AuthCmd::Revoke {
            key,
            key_hash,
            agent: _,
        } => {
            let removed = match (key, key_hash) {
                (Some(key), None) => auth::revoke_key(store, secret, &key),
                (None, Some(hash)) => auth::revoke_key_hash(store, &hash),
                _ => {
                    return Err(anyhow::anyhow!(
                        "revoke: pass exactly one of --key, --key-hash, or --agent"
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
            print_key_records(records);
            Ok(())
        }
    }
}

/// Render `(key_hash, record_bytes)` pairs to stdout — the one `auth list`
/// output format, shared by the offline store path (`run_auth_action`) and the
/// live-daemon `ListKeys` path so the two cannot drift.
fn print_key_records(records: Vec<(String, Vec<u8>)>) {
    if records.is_empty() {
        println!("no keys");
        return;
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
}

/// The effective cluster API-key HMAC secret, from the single SSOT
/// `<tls_dir>/api-key-secret`.
///
/// Precedence: the **persisted file wins** when present — keys minted under it
/// must keep resolving, exactly as the persisted CA is authoritative over any
/// env. Otherwise `NEXUS_API_KEY_SECRET` bootstraps it first-time and is
/// persisted (0600) so the enroll handler can serve it and a restart stays
/// stable without re-exporting the env. `None` ⇒ auth-off.
///
/// A joiner never sets the env: `join_cluster_and_provision_tls` writes this
/// file from the founder's enroll response (over the token-gated channel, like
/// the CA), and this reads it back — so the joiner authenticates cluster-minted
/// `sk-` keys with zero local auth config. Read-only: safe to call from the
/// enrollment-listener setup and from `auth_posture` — it never writes.
fn effective_api_key_secret(tls_dir: &std::path::Path) -> Option<String> {
    resolve_api_key_secret(tls_dir, std::env::var("NEXUS_API_KEY_SECRET").ok())
}

/// Pure decision behind [`effective_api_key_secret`]: `env_secret` is passed in
/// (not read here) so the (persisted-file, env) resolution is unit-testable
/// without mutating process env — mirroring `auth_posture::decide`.
///
/// READ-ONLY by contract. A persisted `tls/api-key-secret` (written by the
/// enrollment client on a joiner — see `join_cluster_and_provision_tls`) wins
/// for stability, like the persisted CA; else the env. It deliberately does NOT
/// write: the daemon serves the resolved value directly and the joiner's file is
/// enrollment-owned, so persisting here is both unneeded and harmful — an offline
/// `auth mint` passes a throwaway `NEXUS_API_KEY_SECRET`, and stamping that into
/// the node's SSOT would flip a later daemon boot from auth-off to auth-on under
/// the wrong secret (regression guarded by `federation_survives_joiner_restart`).
fn resolve_api_key_secret(tls_dir: &std::path::Path, env_secret: Option<String>) -> Option<String> {
    let path = tls_dir.join("api-key-secret");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    env_secret.filter(|s| !s.is_empty())
}

/// Project the CLI onto the pure decision in [`auth_posture`].
///
/// The rule itself lives in that module and is a pure function of these four
/// inputs, so it is testable without a daemon and cannot drift with boot order.
fn auth_posture(common: &CommonArgs) -> Result<AuthPosture> {
    auth_posture::decide(&AuthPostureInputs {
        bind_addr: common.effective_bind_addr(),
        api_key_secret: effective_api_key_secret(&common.data_dir.join("tls")),
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

/// A random 128-bit cluster api-key HMAC secret as 32 lowercase hex chars.
/// The founder mints one at bootstrap when the operator supplies no
/// `NEXUS_API_KEY_SECRET`; it is distributed to joiners verbatim over the
/// enroll plane and powers sk- token HMACs. Agents never see it (cert-only).
fn generate_api_key_secret() -> String {
    use rand::Rng;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Persist a secret file with owner-only perms (0600 on unix), mirroring the
/// enrollment joiner's `tls/api-key-secret` write in `zone_manager`.
fn write_secret_file(path: &std::path::Path, secret: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(secret.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, secret.as_bytes())
    }
}

/// Idempotent: persist the durable cluster api-key HMAC secret. Called ONLY on
/// the daemon boot path (never the shared `open_zone_manager`, so an offline
/// `auth mint` / `share` / `join` cannot trigger it and stamp a throwaway env
/// into the node SSOT — the regression #186 guarded). `is_founder` (the CA
/// holder: `--cluster-init` on first boot or a persisted `ca-key.pem` on resume)
/// gates it; a joiner inherits the secret over the enroll plane instead. A no-op
/// when a secret already exists (resume) or on a non-founder. `env_secret` wins
/// (BYO / vault); else a random 128-bit secret is minted. Returns whether it
/// wrote one. Distinct from `resolve_api_key_secret`, which stays read-only.
fn provision_api_key_secret(
    tls_dir: &std::path::Path,
    is_founder: bool,
    env_secret: Option<String>,
) -> std::io::Result<bool> {
    let secret_path = tls_dir.join("api-key-secret");
    if !is_founder || secret_path.exists() {
        return Ok(false);
    }
    std::fs::create_dir_all(tls_dir)?;
    let secret = env_secret
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(generate_api_key_secret);
    write_secret_file(&secret_path, &secret)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// `resolve_api_key_secret` precedence — the (persisted-file, env) SSOT
    /// decision. File WINS (stability, like the persisted CA); else env, used
    /// READ-ONLY (never persisted); neither ⇒ auth-off (None). Env passed as a
    /// param, so no process-env mutation (no parallel-test flakiness).
    #[test]
    fn resolve_api_key_secret_precedence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path();
        let secret_file = p.join("api-key-secret");

        // 1. Neither file nor env ⇒ None (auth-off), and nothing is written.
        assert_eq!(resolve_api_key_secret(p, None), None);
        assert!(!secret_file.exists(), "None case must not create the file");

        // 2. No file + env ⇒ returns env, and is READ-ONLY: nothing is written.
        //    An offline `auth mint` passes a throwaway secret; persisting it would
        //    flip a later daemon boot's auth posture (the joiner-restart regress).
        assert_eq!(
            resolve_api_key_secret(p, Some("from-env".into())).as_deref(),
            Some("from-env")
        );
        assert!(
            !secret_file.exists(),
            "resolve must be read-only — env must not be persisted"
        );

        // 3. File present ⇒ file WINS even if env differs — keys minted under the
        //    persisted secret must keep resolving; env cannot silently rotate it.
        //    In production the file is enrollment-written; seed it directly here.
        std::fs::write(&secret_file, "from-file\n").expect("seed persisted secret");
        assert_eq!(
            resolve_api_key_secret(p, Some("different-env".into())).as_deref(),
            Some("from-file")
        );

        // 4. Empty env is treated as unset.
        let empty = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            resolve_api_key_secret(empty.path(), Some(String::new())),
            None
        );
    }

    /// The founder-side agent minter: the node-only gate refuses a caller that
    /// is not a cluster node (no cert, or an agent cert — an agent is a pure
    /// identity and must never mint agents), and the happy path signs a real
    /// cluster-CA agent cert and records the agent with cluster-wide uniqueness.
    /// Exercises the SAME units the offline CLI and the remote MintAgent RPC
    /// drive, without a live daemon.
    #[tokio::test]
    async fn founder_agent_minter_gates_to_nodes_and_signs() {
        use kernel::hal::auth_key_store::{AuthKeyStore, AuthKeyStoreError};
        use nexus_raft::agent_minter::AgentMinter;
        use nexus_raft::transport::{generate_agent_cert, generate_node_cert, generate_zone_ca};

        #[derive(Default)]
        struct MemStore {
            records: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
        }
        impl AuthKeyStore for MemStore {
            fn get(&self, k: &str) -> Result<Option<Vec<u8>>, AuthKeyStoreError> {
                Ok(self.records.lock().unwrap().get(k).cloned())
            }
            fn put(&self, k: &str, r: &[u8]) -> Result<(), AuthKeyStoreError> {
                self.records
                    .lock()
                    .unwrap()
                    .insert(k.to_string(), r.to_vec());
                Ok(())
            }
            fn delete(&self, k: &str) -> Result<bool, AuthKeyStoreError> {
                Ok(self.records.lock().unwrap().remove(k).is_some())
            }
            fn list(&self) -> Result<Vec<(String, Vec<u8>)>, AuthKeyStoreError> {
                Ok(self
                    .records
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(h, r)| (h.clone(), r.clone()))
                    .collect())
            }
        }

        // A real cluster CA on disk — the minter reads ca.pem + ca-key.pem.
        let (ca_pem, ca_key_pem) = generate_zone_ca("root").expect("ca");
        let dir = tempfile::tempdir().expect("tempdir");
        let tls_dir = dir.path().join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("ca.pem"), &ca_pem).unwrap();
        std::fs::write(tls_dir.join("ca-key.pem"), &ca_key_pem).unwrap();

        let store: Arc<dyn AuthKeyStore> = Arc::new(MemStore::default());
        let minter = FounderAgentMinter { store, tls_dir };

        let der = |p: &[u8]| ::pem::parse(p).unwrap().contents().to_vec();
        let (node_cert, _k) =
            generate_node_cert(7, "root", &ca_pem, &ca_key_pem, &[], Some("box")).unwrap();
        let (agent_cert, _k2) = generate_agent_cert("intruder", &ca_pem, &ca_key_pem).unwrap();

        // No client cert ⇒ refused.
        assert!(minter.mint(None, "w1", "w1", false).await.is_err());

        // An agent cert ⇒ refused: an agent cannot mint further agents.
        // (Match rather than `expect_err`: `AgentBundle` holds a private key, so
        // it deliberately derives no `Debug` that could `{:?}`-leak the key.)
        let e = match minter.mint(Some(der(&agent_cert)), "w1", "w1", false).await {
            Err(e) => e,
            Ok(_) => panic!("an agent cert must not mint agents"),
        };
        assert!(e.contains("node-only"), "unexpected gate error: {e}");

        // A node cert ⇒ signs a bundle and records the agent.
        let bundle = minter
            .mint(Some(der(&node_cert)), "w1", "w1", false)
            .await
            .expect("a node caller mints");
        assert!(!bundle.cert_pem.is_empty() && !bundle.key_pem.is_empty());
        assert_eq!(bundle.ca_pem, ca_pem, "the bundle ships the cluster CA");
        // The minted cert is a real agent identity chaining to the cluster CA.
        let id =
            transport::peer_identity::from_der(&der(&bundle.cert_pem)).expect("minted cert parses");
        assert_eq!(id.agent_name.as_deref(), Some("w1"));

        // Cluster-wide uniqueness is enforced through the record: a second mint
        // of the same name without --allow-existing is refused.
        let dup = match minter.mint(Some(der(&node_cert)), "w1", "w1", false).await {
            Err(e) => e,
            Ok(_) => panic!("duplicate agent name must be refused"),
        };
        assert!(
            dup.contains("already has an active credential"),
            "unexpected dup error: {dup}"
        );
    }

    /// The founder self-provisions the durable api-key secret on the daemon boot;
    /// a non-founder does not, resume is a no-op, an operator env is persisted
    /// verbatim, and the tls dir is created if absent. Mirrors the daemon gate.
    #[test]
    fn provision_api_key_secret_founder_only() {
        // Non-founder ⇒ skip; nothing written.
        let joiner = tempfile::tempdir().expect("tempdir");
        assert!(
            !provision_api_key_secret(joiner.path(), false, None).expect("provision"),
            "a non-founder must not self-generate"
        );
        assert!(!joiner.path().join("api-key-secret").exists());

        // Founder + no env ⇒ mint a random 128-bit secret, creating the tls dir.
        let fdir = tempfile::tempdir().expect("tempdir");
        let ftls = fdir.path().join("tls");
        assert!(
            provision_api_key_secret(&ftls, true, None).expect("provision"),
            "founder with no secret must mint one"
        );
        let minted = std::fs::read_to_string(ftls.join("api-key-secret")).expect("read");
        assert_eq!(minted.len(), 32, "random secret is 32 hex chars (128 bits)");
        assert!(minted.chars().all(|c| c.is_ascii_hexdigit()));

        // Resume: a secret already exists ⇒ no-op; value preserved, env ignored.
        assert!(
            !provision_api_key_secret(&ftls, true, Some("different".into())).expect("provision"),
            "existing secret must be preserved on resume"
        );
        assert_eq!(
            std::fs::read_to_string(ftls.join("api-key-secret")).expect("read"),
            minted
        );

        // BYO: founder + env, no prior secret ⇒ env value persisted verbatim.
        let bdir = tempfile::tempdir().expect("tempdir");
        let btls = bdir.path().join("tls");
        assert!(
            provision_api_key_secret(&btls, true, Some("operator-secret".into()))
                .expect("provision")
        );
        assert_eq!(
            std::fs::read_to_string(btls.join("api-key-secret")).expect("read"),
            "operator-secret"
        );
    }

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

    fn common_from(args: &[&str]) -> CommonArgs {
        let mut full = vec!["nexusd-cluster"];
        full.extend_from_slice(args);
        Args::try_parse_from(full).expect("args parse").common
    }

    /// The one-address contract: `--advertise-addr` alone determines the bind
    /// (all interfaces on the advertised port), so the operator never states a
    /// second address. Explicit `--bind-addr` still wins; neither ⇒ the default.
    #[test]
    fn effective_bind_derives_from_advertise_then_honours_explicit_then_default() {
        // Advertise only → bind all interfaces on the advertised port.
        assert_eq!(
            common_from(&["--advertise-addr", "100.64.0.27:2200"]).effective_bind_addr(),
            "0.0.0.0:2200",
        );
        // Explicit --bind-addr wins over the derivation (exotic multi-NIC).
        assert_eq!(
            common_from(&[
                "--advertise-addr",
                "100.64.0.27:2200",
                "--bind-addr",
                "10.0.0.5:9999",
            ])
            .effective_bind_addr(),
            "10.0.0.5:9999",
        );
        // Neither → historical default.
        assert_eq!(common_from(&[]).effective_bind_addr(), DEFAULT_BIND);
    }

    /// The enrollment-port convention is ONE function so both sides agree:
    /// the founder binds `data + 1`, and a joiner derives the same from its
    /// first `--peer`. Guards the `+1` offset and the malformed-input errors.
    #[test]
    fn enroll_port_is_one_above_the_data_port() {
        assert_eq!(
            enroll_port_addr("100.64.0.27:2126").unwrap(),
            "100.64.0.27:2127"
        );
        assert_eq!(enroll_port_addr("0.0.0.0:2200").unwrap(), "0.0.0.0:2201");
        // Composed accessor uses the same convention on the effective bind.
        assert_eq!(
            common_from(&["--advertise-addr", "100.64.0.27:2126"])
                .effective_enroll_addr()
                .unwrap(),
            "0.0.0.0:2127",
        );
        // Malformed inputs are rejected, not silently mis-parsed.
        assert!(enroll_port_addr("no-port").is_err());
        assert!(enroll_port_addr("host:not-a-number").is_err());
        assert!(enroll_port_addr("host:65535").is_err(), "no room for +1");
    }
}
