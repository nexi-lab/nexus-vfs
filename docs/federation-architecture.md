# Federation Architecture Memo

**Date:** 2026-03-01 (Last updated)
**Status:** Design SSOT (Single Source of Truth)

> **Contributing**: Living design document. Prefer **in-place edits** over appending.
> Keep it concise — rationale > code. No task tracking here.

---

## 1. Architecture Components

### Raft Consensus Core (Rust)
- `ZoneConsensus` wrapping tikv/raft-rs `RawNode` with async propose API
- `RaftStorage` backed by redb (persistent log, hard state, snapshots, compaction)
- `FullStateMachine` (metadata + locks) and `WitnessStateMachine` (vote-only)

### gRPC Transport Bindings
`KernelClient` class for Python→Rust kernel access via gRPC (~1ms/op):
metadata ops, lock ops (mutex + semaphore), snapshot/restore.

### RaftMetadataStore (Python)
gRPC mode (kernel subprocess). Same interface as SQLAlchemyMetadataStore.

### Distributed Locks
`RaftLockManager` — locks in Metastore (redb), replicated via Raft (SC). Cross-zone locks route via gRPC. RedisLockManager deprecated for Raft-enabled deployments.

### gRPC Transport
Inter-node Raft replication via `ZoneTransportService` + `ZoneApiService`.

---

## 2. Target Architecture (Production Federation)

```
              Zone: us-west-1
  ┌─────────────────────────────────────────────┐
  │ Node A (Leader)    Node B (Follower)  Node C│
  │ ┌──────────┐       ┌──────────┐     (Witness)
  │ │ NexusFS  │ gRPC  │ NexusFS  │  ┌────────┐│
  │ │ + Raft   │◄─────►│ + Raft   │──│Vote-only│
  │ │ + redb   │       │ + redb   │  │ redb(log)│
  │ └──────────┘       └──────────┘  └────────┘│
  └─────────────────────────────────────────────┘
                        │ (nexus-to-nexus mount)
              Zone: eu-central-1 (same structure)
```

**Node composition** (single process): NexusFS + gRPC + ZoneConsensus + redb. Leader/Follower run same binary (`nexusd-cluster`); role by Raft election. Witness: vote-only, no state machine, minimal footprint (`RaftConfig::witness(id, peers)`).

---

## 3. Data Architecture

### 3.1 Design Principles
Every data type justified across 8 property dimensions (R/W perf, consistency, query pattern, size, cardinality, durability, scope). Storage mediums must not overlap in purpose.

### 3.2 Storage Layer Decisions

#### **SQLAlchemy (PostgreSQL/SQLite) = RecordStore** — 22 types
Relational queries, FK, unique constraints, vector search, encryption, BRIN indexes.

| Category | Data Types |
|----------|-----------|
| Users & Auth | UserModel, UserOAuthAccountModel, OAuthCredentialModel |
| ReBAC | ReBACTupleModel, ReBACGroupClosureModel, ReBACChangelogModel |
| Memory | MemoryModel, MemoryConfig, TrajectoryModel, PlaybookModel |
| Versioning | VersionHistoryModel, WorkspaceSnapshotModel |
| Semantic Search | DocumentChunkModel (pgvector/sqlite-vec) |
| Workflows | WorkflowModel, WorkflowExecutionModel |
| Zones | ZoneModel, EntityRegistryModel, ExternalUserServiceModel |
| Audit | OperationLogModel |
| Other | SandboxMetadataModel, PathRegistrationModel |

#### **Metastore (Ordered KV — redb)** — 5 types
| Data Type | Rationale |
|-----------|-----------|
| FileMetadata (merged FilePathModel, DirectoryEntryModel) | Core metadata, KV by path, SC via Raft |
| FileMetadataModel (custom KV) | Arbitrary user-defined KV metadata |
| ReBACNamespaceModel | KV by namespace_id, low cardinality |
| SystemSettingsModel | KV by key, low cardinality |
| ContentChunkModel | CAS dedup index, KV by content_hash, immutable (local only) |

#### **CacheStore (Ephemeral KV + Pub/Sub)** — 4 types
PermissionCacheProtocol, TigerCacheProtocol (TTL), UserSessionModel (TTL), FileEvent (pub/sub).

**Full analysis**: `docs/architecture/data-storage-matrix.md`

---

## 4. Kernel Architecture

See **[Kernel Architecture](../README.md)** (SSOT) for the OS-inspired layered architecture.

### 4.1 Raft Dual Mode: Strong vs Eventual Consistency

| Mode | Writes | Reads | Latency | Use case |
|------|--------|-------|---------|----------|
| **SC** (default) | Raft consensus (majority ACK) | Linearizable | ~5-10ms intra-DC | sys_setattr / sys_unlink metadata, locks, CAS, stream WALs, control-plane |
| **EC** (opt-in via `zone_handle::set_metadata(.., Consistency::Ec)`) | Local WAL append + sync state-machine apply; async drain to peers | Eventual | ~5-50µs (local redb) | High-throughput callers that can tolerate async cross-node visibility (media-style workloads); **not yet wired into the kernel hot path** |

Per-call routing — same zone exposes both surfaces, the call site picks via the `Consistency` parameter on `zone_handle.rs::set_metadata` / `delete_metadata`.  Today the kernel hot path (`ZoneMetaStore::put` / `delete`, which `sys_setattr` / `sys_unlink` drive) hardcodes `Sc`; an attempt to route it through `Ec` is blocked on the EC drain hardening (see *EC kernel-hot-path activation* below).

#### EC kernel-hot-path activation (deferred)

nexi-lab/nexus-vfs PR #61 attempted to route `ZoneMetaStore::put` / `delete` through `propose_ec_local` so the cc-tasks-share Mac↔Win symmetric peer workflow could write metadata without quorum (Mac as a Learner blocks on `NotLeader` under SC).  The activation exposed correctness / liveness issues in `transport_loop.rs::replicate_ec_entries` that only surface in a 1-voter + 1-learner topology: after a larger founder-side write attempt, subsequent founder→learner sys_setattr writes stop reaching the learner's local state machine within typical wait-budgets — per-peer exponential backoff accumulates without recovery.

Until the EC drain is hardened (separate substrate work), the kernel hot path stays on SC.  Operators reach the cc-tasks-share-style symmetric peer pattern via `nexusd-cluster join --as voter` so both peers can propose SC writes (PR #62 finalised the `--as` CLI surface).

---

## 5. Write Flow

```
5.1 Single-Node:        Client → NexusFS.write() → SQLAlchemyMetadataStore → Backend.write()
5.2 Raft Local:         Client → NexusFS.write() → RaftMetadataStore (gRPC ~1ms) → redb → Backend
5.3 Raft Distributed:   Client → NexusFS.write() → ZoneConsensus.propose() → gRPC replicate
                                                 → Majority ACK → StateMachine.apply() on all → redb
                                                 → per-voter dcache.evict(key)  ← cache coherence
```

raft-rs only handles consensus (log replication, election). Transport (gRPC) is our responsibility.

Cache coherence: every voter's `StateMachine.apply` fires the invalidation callback the kernel DLC installed at mount time (see [README](../README.md) §4 DLC row), so a leader-forwarded follower write — or any replicated mutation — evicts stale dcache entries on nodes that didn't originate the write. Without this step, `sys_stat` / `sys_read` on non-writer voters would keep returning the pre-write `etag` from local dcache even after raft applied the new state.

---

## 6. Zone Model

### 6.1 Core Decision: Zone = Consensus Domain

A Zone is both a **logical namespace** and a **consensus boundary**:
- Each Zone has its own **independent Raft group** with its own redb database
- Zones do NOT share metadata — separate, non-replicated redb stores
- Cross-zone access requires gRPC (DT_MOUNT resolution)

**Why not replicate all metadata to all nodes?**
Security (GDPR data sovereignty), space (millions of users), latency (cross-continent Raft).

**Spanner comparison**: Spanner Universe → Federation, Spanner Zone → Zone, Paxos Group → Raft group. Key difference: Spanner's Paxos Group and Zone are orthogonal; in NexusFS, Zone and Raft group are 1:1 (Multi-Raft sharding within a zone possible later).

### 6.2 Mount = Create New Zone, Operator-Chosen Membership Role

**NFS-style UX:**
```bash
nexus mount /my-project bob:/my-project
```

Creates a **new independent zone**.  Permissions (read-only vs read-write) live in ReBAC, not Raft roles — so membership role is an availability tradeoff, not an authorization tradeoff:

| Role | Quorum impact | Wipe-rejoin | When to pick |
|------|---------------|-------------|--------------|
| **Voter** | Counts toward quorum | Hard — re-introducing a wiped voter with stale ConfState risks `not leader` deadlock until manual recovery | Symmetric peer workflows (cc-tasks-share: Mac↔Win mutually sharing CC task dirs).  Each side has equal SC-write authority.  EC-routed sys_setattr (the kernel hot path; see §4.1) means a voter can still write metadata locally when peers are offline. |
| **Learner** (default) | Zero quorum impact | Safe — losing or replacing a learner leaves the owner-side commit ability untouched | Owner-pattern share-with-readers (one authoritative writer publishes a subtree, many machines mirror).  SSD swap / OS reinstall / device migration is operator-trivial. |

| Aspect | Behavior |
|--------|----------|
| Read latency | ~5µs (local redb) — always local |
| Write latency | Raft propose → commit (~5–10ms intra-DC) |
| Consistency | Linearizable (kernel hot path is SC today; EC is per-call opt-in via `zone_handle::set_metadata(.., Consistency::Ec)` — see §4.1) |
| Data locality | Full metadata replica in local redb |

**Why not redirect + cache?** Redirect = gRPC every read (~200ms). Client cache = re-inventing weaker Raft. Raft already solves consistent multi-party views.

**Sharer side**: `nexusd-cluster share <path> --zone-id <id> [--mount-at <local-path>]` creates the new zone's raft group as the single founding voter + copies the subtree's metadata in; with `--mount-at` it also writes the DT_MOUNT entry under the parent zone in the same operation. **Joiner side**: `nexusd-cluster join <peer> <zone> <local-path> [--as voter|learner]` subscribes to the zone's raft replica set + writes the same DT_MOUNT entry; `--as voter` is the default (symmetric-peer pattern, what the cc-tasks-share and corp-zone partition workflows we ship for need), `--as learner` is the owner-pattern opt-in. The mount entry lives in the parent zone's raft state, so every member converges to the same mount table without separate coordination — symmetric semantics either side. Decision logic: contributes new metadata + wants symmetric write authority (default) → join `--as voter`; only consumes (or contributes but wants owner-pattern wipe-rejoin safety) → join `--as learner`.

### 6.3 Peer Discovery: No Custom DNS

Standard OS DNS + bootstrap + Raft membership exchange covers all scenarios.

| Layer | Mechanism | When |
|-------|-----------|------|
| Bootstrap | `NEXUS_BOOTSTRAP_NEW=1` (founder) or JoinZone RPC against `NEXUS_PEERS` (joiner) | First cluster formation |
| First contact | OS DNS (hostname → IP) | `join_zone(peers=["bob:2126"])` |
| After join | Leader snapshot installs authoritative `ConfState` | After AddNode commits |
| Ongoing | Raft `ConfChange` | Automatic membership propagation |

Path resolution across zones is **all local** (~5us per hop) because mounting = Voter = full local replica. No network hops on the read path.

#### 6.3.1 Bootstrap

Etcd / TiKV-style opaque IDs + leader-driven `AddNode`.

- **Identity** — `node_id` is an opaque random `u64` minted at first daemon boot, persisted as 8 bytes BE u64 to `<NEXUS_DATA_DIR>/.node_id`.  Decoupling identity from hostname lets a wiped follower rejoin under a fresh ID; the leader's `Progress[new_id]` is created with `matched=0` by `AddNode`, so the first heartbeat carries `m.commit=0` — within `RaftLog::commit_to`'s safe range on a fresh follower (`last_index=0`).  Pinned by [`test_handle_heartbeat_on_empty_follower_with_stale_commit_panics`](../../rust/raft/src/raft/storage.rs).  `<NEXUS_DATA_DIR>` wipe MUST rotate `node_id` — reusing the old id against a leader that still remembers `Progress[old_id].matched > 0` trips exactly this panic (heartbeat commit lands above the fresh follower's `last_index=0`).
- **Address book** — `NEXUS_PEERS` (or `--peers`) is a hostname → endpoint mapping for OTHER nodes only that seeds the transport peer map.  Entries are `"host:port"` strings — peer `node_id` is opaque, random per boot, and never carried in the address book (`learn_peer_address` in `transport/server.rs` populates the real id from the first inbound raft message).  Persisted separately at node-bound `identity.json` (Windows `%LOCALAPPDATA%\Nexus\identity.json`, macOS `~/Library/Application Support/Nexus/identity.json`, Linux `$XDG_DATA_HOME/nexus/identity.json`) so a cache-cleaner removing `<NEXUS_DATA_DIR>` does not force the operator to re-specify `--peers` on next boot.  Boot merges CLI/env peers with identity's persisted `peers[]` and rewrites identity monotonically when the CLI set widens.  Self joins the cluster through `create_zone(self)` (founder) or `AddNode(self)` on the leader (joiner) — never through the address book.  Boot fails loud (`peer list contains self ...`) when the merged peer list includes the local node so the joiner-loop self-RPC stall surfaces at parse time, not after `Zone 'root' registered`.  `ConfState` lives in raft storage and is mutated only by `ConfChange` (AddNode / RemoveNode) driven by JoinZone; `identity.json`'s `peers[]` is a *transport seed*, not a `ConfState` shadow.

- **Advertise address — `--advertise-addr` decoupled from `--hostname`** — `--hostname` / `NEXUS_HOSTNAME` is the display label only (ZoneManager registry + TLS cert SANs).  The reachable network endpoint this node broadcasts to peers as `StepMessage.sender_address` comes from `--advertise-addr` / `NEXUS_ADVERTISE_ADDR` instead, defaulting to `<hostname>:<bind_port>` for backward compatibility.  Cross-machine federation over overlay networks (Tailscale, WireGuard, VPN) MUST pin `--advertise-addr` to the overlay IP — the OS hostname does not resolve through the overlay, so the joiner's initial `JoinZone` RPC succeeds (the caller passed the peer addr directly) but subsequent raft heartbeats / log replication target `http://<peer-hostname>:2126` and fail at the DNS layer, surfacing minutes later as silent "ConfState install timeout". Boot logs a warning when the resolved advertise address looks unreachable (`0.0.0.0:*`, loopback with peers, or bare hostname with peers configured on a remote machine) so the misconfiguration surfaces immediately rather than after long timeouts.
- **Bootstrap mode** — operator declares intent up front via `NEXUS_BOOTSTRAP_MODE` (or `--bootstrap-mode` for `nexusd-cluster`).  The validator runs once at boot and rejects any state × flag combination that does not match the declared mode, so misconfiguration surfaces before the gRPC server starts rather than as a silent stall later.  See [`BootstrapMode`](../../rust/raft/src/distributed_coordinator.rs).

  | Mode | Required state | Required flags | Forbidden flags | Bootstrap dispatch |
  |------|---------------|----------------|-----------------|---------------------|
  | `static` | Empty data dir | `NEXUS_BOOTSTRAP_NEW=1` (founder) | `NEXUS_PEERS` non-empty (root is per-node SOLO — see below) | Founder: `create_zone("root")` 1-voter |
  | `dynamic` | Empty data dir | — | `NEXUS_BOOTSTRAP_NEW`, `NEXUS_PEERS` | Daemon comes up rootless; runtime API (`nexusd-cluster share`/`join`, Python `federation_create_zone`) drives zone formation |
  | `restart` | Data dir holds `<dir>/root/raft/` | — | `NEXUS_BOOTSTRAP_NEW`, `NEXUS_PEERS` | Resume from persisted ConfState — state on disk is the SSOT, env flags would be ambiguous |

- **Root is per-node SOLO** — every nexus daemon owns its OWN 1-voter `root` zone.  Federation between independent nodes happens through NAMED zones (e.g. `sharedzone`), joined via the `nexusd-cluster join` sidecar — NEVER by adding another node into a peer's root cluster.  `NEXUS_PEERS` is reserved for in-cluster transport seeding; setting it at boot time on a fresh data dir is rejected with a clear error (`bootstrap_or_join_zone` SOLO-invariant gate) so the operator-facing misconfig "I want to federate with `<peer>`, so I set `NEXUS_PEERS=<peer>`" surfaces at boot rather than cascading through ConfChange / heartbeat / cross-federation pollution.  HA scenarios use named zones: 3 nodes wanting shared data create + join `dc1-namespace`; their per-node roots stay independent.  Pinned by [`test_root_zone_solo_contract`](../../rust/raft/tests/test_root_zone_solo_contract.rs).

- **`nexusd-cluster join` auto-bootstraps the parent zone** — the join sidecar writes a DT_MOUNT entry into `<parent_zone>` (defaults to root) to stitch the remote zone into local namespace at `<local_path>`.  That DT_MOUNT propose lands in the parent zone's raft log, so the parent zone MUST be loaded locally before the mount step.  Pre-this-contract behaviour assumed the operator had bootstrapped the parent zone via a prior step (`nexusd-cluster --bootstrap-mode static` once, then `join`); the sidecar would silently no-op on the mount propose when called against a fresh data dir, producing an empty `<local_path>` namespace and the "wire_mount: root zone not loaded — distributed locks NOT installed" warn that wedged the Mac↔Win cc-tasks-share L1 smoke.  The sidecar now SOLO-bootstraps the parent zone (empty peers, matching the per-node SOLO contract above) when `<data_dir>/<parent_zone>/raft/` is missing — idempotent (no-op when the zone already exists), so the join CLI runs end-to-end against a brand-new data dir without an operator pre-step.

- **`join <peer_addr>` — `host:port` is the ONLY accepted form** — operators DO NOT sync opaque `node_id` between peers.  `nexusd-cluster join 100.64.0.27:2126 sharedzone /shared` is the shape; the peer's real `node_id` (random per boot under PR #3996) is learned from the first inbound `MsgSnapshot.sender_address` via [`learn_peer_address`](../../rust/raft/src/transport/server.rs) and populates the peer_map entry outbound raft replies route through.  The legacy `<id>@host:port` form is hard-rejected at parse time with a migration message pointing at the bare form (see `PeerAddress::parse`) — carrying an explicit id in the address book had no protocol purpose and misled operators into thinking a peer rebuild required an id lookup ceremony.  Operational implication: cross-peer coordination for `join` reduces to sharing the leader's TCP endpoint plus the zone name, matching the Docker Swarm `docker swarm join <addr>` / Consul `consul join <addr>` UX curve.

- **Wipe-rejoin** — wiping `<NEXUS_DATA_DIR>` mints a fresh `node_id` on the next boot; the daemon JoinZones, the leader commits `AddNode(new_id)`.  The persisted peer address book at `identity.json` survives — so `--peers` does not need re-specifying at wipe-rejoin, only `NEXUS_BOOTSTRAP_MODE=static` (or `dynamic`) with the same env otherwise.  Identity-and-data-dir both wiped is equivalent to a first-time install; identity survives and data_dir wiped is the routine cache-loss recovery.

##### S3 完全体 — Unified bring-up decision layer

The daemon reads `(identity.peers, --peers, NEXUS_FEDERATION_ZONES)` at boot and dispatches deterministically via [`nexus_raft::bootstrap::plan_boot_action`](../../rust/raft/src/bootstrap.rs).  Six-row matrix; two rows fail loud (both-founder / ambiguous-fresh-founder), three rows drive the pre-refactor primitives (`bootstrap_static_async` for the founder, `bootstrap_or_join_zone` for the joiner), one row is a no-op.  Replaces three separate operator ceremonies (daemon founder, daemon joiner, offline `join` sidecar) with one command.

| # | `identity.peers` | CLI `--peers` | `NEXUS_FEDERATION_ZONES` | Action |
|---|---|---|---|---|
| 1 | empty     | empty     | set     | `StaticFounder` — auto-create SOLO |
| 2 | empty     | empty     | unset   | `RootlessDynamic` — daemon up, no zone auto-boot |
| 3 | empty     | non-empty | unset   | `JoinFederationZones` — joiner (fresh) |
| 4 | non-empty | any       | unset   | `JoinFederationZones` — joiner (return) |
| 5 | non-empty | any       | set     | `FailLoud` — split-brain trap |
| 6 | empty     | non-empty | set     | `FailLoud` — ambiguous |

##### S3 Phase B — Identity carries per-zone membership

Every successful ConfChange apply on this node fires an in-driver callback that mirrors the fresh `ConfState` into `identity.json`'s `zones` array (schema v2 — see [`Identity`](../../rust/raft/src/identity.rs)).  Payload per entry:

- `zone_id` — the zone this node participates in
- `members` — `voters ∪ learners` projected through the peer map to bare `host:port`
- `as_role` — `voter` if `self_id ∈ voters`, else `learner`
- `last_confirmed_unix_secs` — coarse mtime, diagnostic only

Boot dispatch consumes this: matrix row 4 (returning joiner) becomes `JoinFederationZones { zones: identity.zones[*].zone_id }` instead of the empty Phase-A no-op.  When neither `--peers` nor `identity.peers` are populated, the JoinZone probe list falls back to `identity.zones[i].members` — so a wipe that took `data_dir` + `--peers` but preserved `identity.json` still has enough seed information to reach a live peer.

Coverage today (S3 Phase A + B + C-lite + D + F + G):
- **Learner wipe-rejoin — auto-heals** under the existing rotate-on-wipe rule.  Wiped learner boots with fresh `node_id`, `plan_boot_action` returns `JoinFederationZones{zones=[…]}` from identity, `bootstrap_or_join_zone` sends JoinZone as learner.  The AddLearnerNode ConfChange on the leader does NOT require the wiped node's ack (learners never count toward quorum), so it commits with just the live voter side.  Old learner id lingers in ConfState as a ghost (harmless — no quorum contribution).
- **Voter wipe-rejoin — genuinely NOT covered by S3 A-G.**  Correcting an earlier over-claim in this memo (2026-07-05): the claim "cluster expands to `[A, B_old_ghost, B_new]` and quorum stays 2-of-3" was **wrong**.  Reaching a 3-voter state requires committing `AddNode(B_new)`, and that ConfChange needs a quorum of the CURRENT voters `[A, B_old]`.  With B_old dead post-wipe, A alone is 1-of-2 — no majority — the AddNode cannot commit and the cluster wedges.
  * **`remove-voter` (Phase C-lite) does not rescue this case either** — RemoveNode(B_old) is also a ConfChange requiring the same broken quorum.  The tool is useful for pruning dead voters when quorum IS intact (e.g., healthy 3-voter cluster where one dies → RemoveNode commits via A + C without B's ack).
  * **Operator escape hatch for a wedged 2-voter cluster is external state surgery** — restore from backup, or delete the failed node's data on the surviving side and re-form as SOLO founder (loses uncommitted state but recovers the cluster).
- **Ghost cleanup on healthy 3+-voter clusters** — `nexusd-cluster remove-voter <peer> <zone> --target <old_id>` prunes a genuinely-dead voter when quorum is intact.  Straight `RemoveNode` ConfChange through raft-rs's public API; no protocol surgery.
- **Operator guidance for symmetric-peer topologies (cc-tasks-share Mac↔Win)** — pure 2-voter is wipe-fragile as documented above.  Prefer:
  1. **1-voter + N learners**: single writer (voter) side, learners read via Phase D auto-discovery + local metastore replicas.  Learner wipe-rejoin auto-heals.  Trade-off: only the voter side can propose writes.
  2. **3-voter with witness**: add the standalone witness binary as a third voter.  Any single voter can wipe + rejoin without wedging quorum.  See `nexus/dockerfiles/docker-compose.federation-runbook.yml` for the witness topology.
  3. **Wait for Phase C proper** (below) — the three-part protocol is designed exactly for 2-voter symmetric-write safety.

##### S3 Phase C — Same-id wipe recovery (deferred design)

The current implementation (S3 Phase A + B + Phase C-lite) uses **rotate-on-wipe**: every wiped daemon mints a fresh `node_id`.  That preserves the `RaftLog::commit_to` safety invariant (`commit = min(Progress[peer].matched, leader_committed)` starts at 0 for freshly added peers) and allows both learner and voter wipe-rejoin without protocol changes.  Cluster hygiene (dropping the ghost id from `ConfState`) is an operator-triggered `RemoveVoter` RPC.

The one property rotate-on-wipe does NOT deliver is **stable node identity across wipes** — useful for tracing, cross-machine correlation, and Task #69's "same node_id across wipe cycles" property.  Delivering that requires reusing the id after a wipe, which brings back the `commit_to` panic scenario and needs a three-part protocol:

1. **Move `.node_id` into `identity.json`** — schema v3 adds `pub node_id: Option<u64>`.  Wiped voter reboots with the SAME id (identity survives).
2. **Inbound quiescence on the wiped follower** — the transport layer holds inbound `MsgHeartbeat` / `MsgAppend` for the zones the boot decision marks "wipe-recovering" (identity had the zone but data_dir is empty) until it observes its own `AddNode` entry commit locally via snapshot install.  Without this the leader's first heartbeat with `m.commit > 0` panics `commit_to` on the empty follower.
3. **Leader-side same-id ConfChange** — the JoinZone RPC handler detects `Progress[joiner_id].matched > 0` (returning wipe rejoin, not fresh join) and proposes `RemoveNode(joiner_id)` first, waits for commit, then proposes `AddNode(joiner_id)`.  `Changer::simple` rejects two voter changes per proposal, so this must be sequential — or via a single `ConfChangeV2` in joint consensus mode.

Together these three restore commit-log linearity across the wipe boundary without changing raft-rs's `RaftLog::commit_to` safety invariant.  Deferred to a dedicated PR because the three parts must ship together to preserve safety, and the design needs review time before code lands.

Cross-refs (raft-rs 0.7 source at `~/.cargo/registry/src/index.crates.io-*/raft-0.7.0/src/`): `commit_to` invariant at `raft_log.rs:286`; leader-side heartbeat commit computation at `raft.rs:868`; `ProgressTracker::apply_conf` drop+insert at `tracker.rs:370` and `Progress::new` matched-zero init at `tracker/progress.rs:60-72`.

##### Witness

The standalone witness binary derives `node_id = hostname_to_node_id(hostname)` (SHA-256 of hostname).  Witnesses live at well-known addresses, so binding identity to hostname is sufficient for them.

#### 6.3.2 Federation Control-Plane API Surface

The federation control plane has two layers; they are NOT shortcuts for each other and live at different trust boundaries.

| Operation | Syscall path (preferred) | RPC path (legacy / pending migration) | Notes |
|-----------|--------------------------|----------------------------------------|-------|
| **Create zone (mount-tied)** | `sys_setattr(path, DT_MOUNT, zone_id, source=None)` | `federation_create_zone(zone_id)` + `federation_mount(parent, path, zone)` | Syscall is the architectural target — service tier should always go through syscall. The two-step RPC pattern remains for legacy callers. |
| **Join zone (mount-tied)** | `sys_setattr(path, DT_MOUNT, zone_id, source="http://leader:2126")` | `federation_join(peer_addr, remote_path, local_path)` (share-registry-based) | Syscall covers raw cluster join via leader address; the RPC covers subtree share/join via the raft-replicated share registry — two distinct workflows. |
| **Unmount zone** | `sys_unlink(mount_path)` | `federation_unmount(parent_zone, path)` | Equivalent surfaces. |
| **Remove zone (standalone)** | (no syscall — zone removal without a path has no filesystem analog) | `federation_remove_zone(zone_id, force=false)` | Cluster-control plane only. Cascade-unmount happens inside the impl. |
| **Read replicated state** | `sys_read(path)` / `sys_stat(path)` / `sys_readdir(path)` | — | Filesystem syscalls reach federated zones via the mount table; no special federation API needed. |

The `_nr.federation_create_zone` / `federation_remove_zone` / `federation_join_zone` PyO3 bindings are direct service-tier shortcuts to the `DistributedCoordinator` HAL trait. They predate the syscall-only contract and are scheduled for removal once all callers migrate. **Do not add new callers** — go through `sys_setattr` / `sys_unlink` instead.

Architectural principle: service tier (`@rpc_expose` methods in `nexus.server.rpc.services.*`) interacts with the kernel **only** through syscalls — same trust boundary as any external user. Direct PyO3 trait shortcuts collapse the boundary and make permission / audit / hook injection harder to reason about.

### 6.4 DT_MOUNT Entry Structure

```python
class DT_MOUNT:
    name: str               # Mount point name in parent directory
    entry_type: "DT_MOUNT"  # Alongside DT_DIR, DT_REG
    target_zone_id: str     # Target zone UUID (no address: Voter has local replica)
```

Mount shadows existing DT_DIR (NFS-compliant). DT_REG conflict rejected.
Zone lifecycle uses hard-link model with `i_links_count` (shared_ptr semantics).
Orphaned zones → `/nexus/trash/`, explicit `nexus zone destroy` to delete.

### 6.5 Inter-Zone Architecture

Zones are physically flat and isolated. The global namespace tree is an illusion of DT_MOUNT entries:

```
Physical (what Raft sees):              Logical (what users see):
  Zone_A: /, docs/, hr/                  /company/
  Zone_B: /, code/, design/                ├── engineering/ → [Zone_B]
  Zone_C: /, photos/                       └── ceo_wife/    → [Zone_C]
```

Mixed consistency: Zone A (EC), Zone B (SC) — each Raft group independent.

**Permissions**: Parent zone controls mount point visibility; target zone controls entry (ReBAC at boundary). **User-centric root**: Each user's `/` determined by zone registry scan — no complex ACL to hide upper directories.

### 6.6 Federation as Optional DI Subsystem

Federation is **NOT kernel**. NexusFS without federation degrades to remote mode (`nexus.connect()`) or standalone.

```
NexusFS (kernel)           Federation (optional subsystem)
NexusFilesystem (ABC)      — (inherently asymmetric)
NexusFS                    NexusFederation (orchestration)
MetastoreABC               ZoneManager (wraps gRPC client)
RaftMetadataStore          PyZoneManager (Rust/redb/Raft)
```

**API Privilege Levels**: File I/O (agents/users) → Federation ops (`share/join`) → Zone lifecycle (admin). Agents do NOT get mount/unmount APIs.

### 6.7 Cross-Node Read Paths — Two Modes, One Routing Pointer

A cross-node `sys_read` on a federated path resolves through one of two paths.  Both consult the same SSOT (`FileMetadata.last_writer_address`) so the metadata-driven fast path and the cold fan-out path stay aligned on which peer holds the bytes.

**Mode A — `try_remote_fetch` (metadata-driven fast path).**  The reader's local metastore has a `FileMetadata` entry for the path.  `last_writer_address` names the node that wrote it.  `sys_read` sends `ReadBlob(content_id)` directly to that peer; the peer's `BlobFetcher::read` path-routes through its own VFSRouter (CAS hash or backend path, opaque to the kernel) and returns bytes.  One round-trip, no peer enumeration.

This is the path Federation E2E's L1 cross-machine read uses: every `sys_write` carries `last_writer_address` set from the writer's `self_address`, so subsequent peer reads have a routing pointer baked in.

**Mode B — `zone_peers` fan-out (cold cross-node first read).**  There is no metadata yet — typical when a workflow writes bytes directly to host fs outside Nexus (Claude Code dropping `~/.claude/tasks/<n>.json`).  The reader's metastore miss falls through to its local backend (miss — bytes are on a peer's host fs); the kernel fans out via `DistributedCoordinator::zone_peers(zone_id)` and dials each non-self, non-witness peer's `BlobFetcher::read`.  The peer that hits its own backend serves the bytes and runs `observe_backend_content`, which:

  1. **Sets `last_writer_address = self_address`** on the synthesised metadata, materialising the routing pointer that Mode A consumes on every subsequent read.
  2. **Leaves `content_id` empty** — the substrate explicitly does not assume any local addressing scheme.  The reader-side path handles this by treating empty `content_id` as a "no local addressing key" signal and letting control flow fall through to `try_remote_fetch`, which uses the global VFS path as the peer fetch key (`unwrap_or(path)` fallback).

Cold fan-out cost is paid **once** per `(path, reader)` pair: the second read on the same path takes Mode A.

**Wiring invariants** (production failures here surface as `peer_count=0` empty fan-out or `FileNotFound` on metadata-present reads):

  * `RaftDistributedCoordinator::install_with_kernel` wires the kernel's `DistributedCoordinator` slot via `Kernel::set_distributed_coordinator(Arc::clone(self))`.  Without this, `kernel.distributed_coordinator().zone_peers(...)` returns `NoopDistributedCoordinator`'s default empty `Vec`, and Mode B's fan-out enumerates zero peers — silently broken regardless of how many peers ConfState actually contains.  Federation E2E (Mode A only) sails past this; cc-tasks-share (Mode B) is the canonical regression catcher.
  * `--mount-driver` defers when its target zone is not yet loaded on this node.  The kernel-internal "create-on-mount" branch in `sys_setattr DT_MOUNT` is reserved for the operator-driven joiner / creator flow (`mount addr:/zone /local` or explicit founder bootstrap); driver mounts are intent-orthogonal to zone creation, so triggering it from `--mount-driver` would solo-bootstrap a parallel raft group on a joiner that's supposed to JOIN.  Surfaces as a split-brain — two same-named raft groups, diverging silently.
  * Driver mounts inside a federated zone inherit the federation mount's `Arc<dyn MetaStore>` via `MountOptions::with_metastore`.  Two `ZoneMetaStore` instances rooted at different mount points (one at `/<zone_id>` from `metastore_for_zone`, one at the federation's global path from `wire_mount_core::install_metastore`) translate the same VFS path to *different* state-machine keys — writes through one anchor live under keys reads through the other never look up.  Single SSOT eliminates that.

The Docker-compose cc-tasks-share E2E (`tests/e2e/docker/test_cc_tasks_share_e2e.py`) pins Mode B end-to-end against this invariant set; the cross-machine federation runbook (`docs/federation-cross-machine-runbook.md`) continues to pin Mode A as the L1 byte-exact target.

---

## 7. Extended Design Topics

### 7a. Write Performance (~30ms/op)

redb is ~0.014ms/op; 99.95% overhead is Python/NexusFS (CAS hash, cache invalidation, SQLAlchemy, permission checks, directory indexing). Future: batch API, async checks, redb-native metadata.

### 7b. Multi-Node Deployment

Full Node Docker image: single container runs `nexusd-cluster` (NexusFS + gRPC + ZoneConsensus + redb). Same image for dev (`docker-compose.dynamic-federation-test.yml`) and production.

### 7c. Dragonfly Role Post-Raft

Redis deprecated → Dragonfly only. Distributed locks → Raft. Permission/Tiger caches, FileEvent pub/sub, UserSession → CacheStore (Dragonfly prod / In-Memory dev). Dragonfly is optional (NullCacheStore fallback).

### 7d. Cross-Zone 2PC (Plan B)

If atomic cross-zone writes needed: coordinator runs 2PC across zone leaders (prepare → commit). Plan A (nexus-to-nexus mount) covers most cases.

### 7e. Future Design Topics

Documented in `document-ai/notes/` discussions; brief summary for reference:

- **Microkernel extraction**: Kernel = local RPC router (VFS + IPC + Raft + Permission Gate). Storage/Timer/HTTP/Auth = user-mode drivers.
- **Memory/Cache tiering**: L0 kernel (redb ~50ns), L1 Dragonfly (~1ms), L2 PostgreSQL (~5ms). L0 stays in kernel; L1/L2 hot-pluggable.
- **Identity: PCB-based binding**: Immutable identity at process spawn. Progressive isolation: Host Process → Docker → Wasm.
- **Auth: Verify/Sign split**: Kernel = `verify_token()` ~50ns. Driver = `login()` ~50-500ms (DB + OAuth).
- **Container I/O monopoly**: `--network none`, single mount `/mnt/nexus`, `--read-only`.
- **Runtime hot-swapping**: Linux `modprobe`/`rmmod` semantics for drivers. Phases: Constructor DI → DriverRegistry → state migration.

### 7f. Federation Content CRUD: Implementation & Caveats

#### Architecture Alignment: HDFS/GFS, Not UNIX ext4

Nexus's metadata/content separation (Metastore + ObjectStore) aligns with distributed filesystem
best practices, not traditional single-machine OS design:

| System | Metadata Plane | Content Plane | Separation |
|--------|---------------|---------------|------------|
| **HDFS** | NameNode (ClientProtocol) | DataNode (DataTransferProtocol) | Two independent RPC protocols |
| **GFS** | Master | ChunkServer | Two independent services |
| **Nexus** | Metastore (redb/Raft) | ObjectStore (CAS/S3/GCS) | Two independent pillar ABCs |
| Linux ext4 | inode | data blocks | Same driver (single machine) |

HDFS exposes metadata-only and content-only interfaces as **separate first-class protocols** at
the kernel primitive level — not just a convenience layer. Our Metastore + ObjectStore split
follows this same pattern. Consequences:
- `sys_write` orchestrates both planes (like HDFS DFSClient), but the planes are independent
- Cross-plane coordination (orphan cleanup) is async, not synchronous (see Caveat 4)
- Content never flows through the metadata plane (like HDFS: "user data never flows through NameNode")

Federation has two I/O planes with different routing strategies:

| Plane | Pattern | Mechanism |
|-------|---------|-----------|
| **Metadata** | Transparent DI proxy | `FederatedMetadataProxy` wraps MetastoreABC, zone-routes all ops |
| **Content** | PRE-DISPATCH resolver | `FederationContentResolver` intercepts read/delete before kernel |

**Zone-aware path routing:** PathRouter canonicalizes all paths to
`/{zone_id}/{path}` and does zone-canonical LPM. For local-zone paths,
FederationContentResolver fast-exits without metadata lookup (~0 cost).
Cross-zone paths still require metadata lookup to determine content locality
(CAS blobs are node-specific). See [README](../README.md) §4.

#### Content CRUD Status

| Operation | Mechanism | Routing |
|-----------|-----------|---------|
| **Read** | `FederationContentResolver.try_read()` | Local zone: fast-exit (no metadata lookup). Remote: gRPC Read/StreamRead RPC |
| **Write** | Always local (by design) | `FederatedMetadataProxy` enriches `backend_name` with node address (`local@host:port`) |
| **Delete** | `FederationContentResolver.try_delete()` | Local zone: fast-exit. Remote: gRPC Delete RPC delegates `sys_unlink` to origin peer |
| **Rename** | Metadata-only (CAS content stays at same hash) | Cross-zone rename blocked by `FederatedMetadataProxy` |

Streaming reads: `FederationContentResolver.try_read()` uses a size threshold —
< 1MB: unary gRPC `Read` RPC; >= 1MB: `StreamRead` RPC (chunked, CAS-aware for
CDC files). No local persistence on read — content stays on the origin node only.

#### CAS Semantics in Federation

CAS stores each file as **one immutable blob keyed by SHA-256 hash**. "Modifying" a file (including `append()`) creates a **new blob with a new hash**. Properties: no partial reads, safe remote read (hash-verified), conflicts only at metadata level.

#### Caveat 1: Concurrent Multi-Node Write (Last-Writer-Wins)

Two nodes writing to the same path: Raft totally orders the two metadata proposals. Last committed write wins; losing node's CAS blob becomes orphaned (see Caveat 4).

**Mitigation**: `sys_write(if_match=etag)` provides OCC. Because metadata is Raft-replicated (all nodes see same etag), `if_match` correctly detects conflicts.

#### Caveat 2: Cross-Node Append = Full Read-Modify-Write

`append()` = `sys_read()` + concatenate + `sys_write()`. In federation, appending 1 byte to a 100MB file on another node transfers the entire file over the network, creates a new complete blob, and orphans the old blob.

Acceptable for v1: most federation is read-heavy; frequent cross-node appends are rare.

#### Caveat 3: Content Availability on Writer Node Failure

Content exists only on writer's CAS until another node reads it. Writer failure before any read → `NexusFileNotFoundError`. Future: eager replication, CacheStore L2, WAL read-repair.

#### Caveat 4: CAS Orphan Accumulation (Standard Pattern — Needs GC)

`sys_write` does NOT release old blobs on overwrite. This is **not a bug** — it follows the
HDFS/GFS standard pattern where metadata changes are synchronous and content cleanup is
asynchronous via background GC.

**HDFS/GFS precedent**:
- GFS (paper §4.4): delete renames file to hidden name; background scan removes metadata after 3 days;
  ChunkServer heartbeat reports chunks; Master identifies orphans and instructs deletion.
- HDFS: NameNode adds blocks to `invalidateBlocks` queue; DataNode heartbeat picks up delete commands;
  BlockManager periodically reconciles blocks against namespace references.

Both systems explicitly accept temporary orphans as a design choice. Synchronous cross-plane
cleanup (releasing content during metadata write) is NOT how distributed filesystems work.

**Nexus behavior**:
```
write("Hello")  → store(hash_A) on ObjectStore, metadata.put(etag=hash_A) on Metastore
write("World")  → store(hash_B) on ObjectStore, metadata.put(etag=hash_B) on Metastore
                   hash_A: no metadata reference, still in ObjectStore → orphan (temporary)
```

**Federation amplifies**: cross-node writes leave orphans on the original writer's ObjectStore.
The writing node's Raft follower receives metadata updates but does not trigger ObjectStore cleanup.

**Resolution: ContentGarbageCollector** (like HDFS BlockManager):
```
referenced_hashes = metastore.all_etags()          # metadata plane
existing_hashes   = objectstore.all_content_hashes() # content plane
orphans           = existing - referenced
for hash in orphans: objectstore.delete_content(hash) # async cleanup
```

Single-node GC is straightforward (scan local ObjectStore vs local Metastore).
Federation GC requires node-level reconciliation: each node scans its local ObjectStore
against the Raft-replicated Metastore to find locally-held orphans.

### 7g. Client Boot-Serving Invariant

`nexusd-cluster` opens its co-hosted VFS + raft gRPC port inside
`ZoneManager::with_node_id` (spawned by `open_zone_manager` in
`rust/profiles/cluster/src/lib.rs::run_daemon`), which happens BEFORE
`RaftDistributedCoordinator::install_with_kernel` runs its atomic
"install + catch up on past DT_MOUNT entries" pass. Concretely:

1. `open_zone_manager` — VFS routes + raft server go live (~seconds into boot)
2. `plan_boot_action` + `bootstrap_or_join_zone` — root zone reaches quorum
3. `install_with_kernel` — coordinator wired, DT_MOUNT replay walks every zone,
   `federation_client` + peer-blob fetcher bound to the kernel
4. `transport::transport_observer::install(&kernel)` — post-transport observability armed

**The port answers as soon as (1) completes**, so a client that races the
daemon boot between (1) and (3) can hit VFS handlers before DT_MOUNT
entries for federation sub-mounts have been re-wired. Read semantics
during that window are safe by construction (missing sub-mount ⇒ path
resolves to the parent mount ⇒ `NotFound` for the not-yet-replayed
sub-path — the correct answer under eventual consistency). **Write
semantics have a narrow physical-layout race**: a `sys_write` to a
sub-mount path that has not yet been replayed lands on the parent
mount's backend (typically `data_dir/root_fs/…`) instead of the
federation sub-mount's backend (typically `data_dir/<zone>/…`), so a
subsequent read after replay resolves via the sub-mount route and sees
`NotFound` even though the bytes exist at the wrong physical location.

**Client contract**: mutating RPCs (`Write`, `Delete`, `Setattr`,
`Mkdir`, `Rename`, `Copy`, `Lock`, `SetXattr`, `BatchWrite`, `Call`,
stream/pipe close, `StreamWriteNowait`) must wait for the
`"transport_observer armed"` info-level log line (or an equivalent
readiness signal that fires only after step 4) before issuing the
first write. Read-only RPCs (`Read`, `Stat`, `Readdir`, `BatchRead`,
`BatchStat`, `GetXattr`, `Watch`, `Ping`, stream/pipe read) can be
issued as soon as the port is dialable — a boot-window `NotFound` is
a legitimate eventual-consistency answer that the client should
tolerate + retry.

Same-machine clients (FUSE mount, `sudocode`, `moss`) already respect
this by waiting on daemon-side log tails or on named-pipe readiness
handshakes before issuing writes. Cross-machine clients cannot reach
us in the (1)→(3) window because their peer address book learns our
endpoint via post-`install_with_kernel` peer-map propagation, so they
inherit the invariant for free. `grpcurl` and other ad-hoc clients
issuing writes during boot are responsible for waiting on the log
signal themselves — this is the client-side half of the boot-serving
contract, deliberately kept out of the handler layer to avoid a
readiness-flag check on every hot-path VFS RPC.

Tracked at [issue #44](https://github.com/nexi-lab/nexus-vfs/issues/44):
the alternative of gating every mutating handler on an `Arc<AtomicBool>`
`ready` flag was considered and rejected — the race window is narrow
(seconds), no production trigger has been observed, and a
docker-compose-based E2E test tight enough to reproduce the natural
timing would be flaky by construction (either passes without the fix
by luck, or requires an artificial boot delay that itself becomes
test-only code). Documented invariant wins over test-only-observable
gate.

### 7j. DT_PIPE / DT_STREAM Federation Design

Both IPC primitives have Raft-replicated metadata but in-process heap data
(MemoryPipeBackend for DT_PIPE, StreamBuffer for DT_STREAM). Federation extends
IPC I/O transparently via origin-aware routing. DT_STREAM uses the same
`stream@host:port` pattern as DT_PIPE's `pipe@host:port`.

#### Metadata: `backend_name` Encoding

PipeManager embeds the creator node's advertise address in `backend_name`:

| Mode | `backend_name` | Meaning |
|------|---------------|---------|
| Single-node | `pipe` / `stream` | No origin, always local |
| Federated | `pipe@host:port` / `stream@host:port` | Origin node address for remote proxy |

#### Read/Write Routing

`BackendAddress.parse(backend_name)` extracts the origin. NexusFS dispatches:

- **Local** (`origin == self` or no origin): Direct MemoryPipeBackend via PipeManager (~0.5us)
- **Remote** (`origin != self`): gRPC `Call` RPC to origin node, which executes
  `sys_read`/`sys_write` locally and returns the result

The remote path reuses existing gRPC auth/zone/error infrastructure — no new proto RPCs.

#### sys_write: Always Local (Design Decision)

`sys_write` is always local by design. The writer node becomes the content origin:
- Regular files: `FederatedMetadataProxy` enriches `backend_name` with writer's address
- Pipes: PipeManager embeds `self_address` in `backend_name` at creation time

Remote nodes read from the origin. There is no write-forwarding or write-proxying.
This is consistent with HDFS/GFS where writes go to a local DataNode/ChunkServer.

---

## 8. Key Files Reference

| Component | File |
|-----------|------|
| Raft node | `rust/nexus_raft/src/raft/node.rs` |
| Raft storage | `rust/nexus_raft/src/raft/storage.rs` |
| State machine | `rust/nexus_raft/src/raft/state_machine.rs` |
| Raft PyO3 bindings | `rust/nexus_raft/src/pyo3_bindings.rs` |
| Raft proto | `rust/nexus_raft/proto/raft.proto` |
| RaftMetadataStore | `src/nexus/storage/raft_metadata_store.py` |
| SQLAlchemyMetadataStore | `src/nexus/storage/sqlalchemy_metadata_store.py` |
| Docker Compose | `dockerfiles/docker-compose.cross-platform-test.yml` |
| FederatedMetadataProxy | `src/nexus/raft/federated_metadata_proxy.py` |
| FederationContentResolver | `src/nexus/raft/federation_content_resolver.py` |
| ZonePathResolver | `src/nexus/raft/zone_path_resolver.py` |
| BackendAddress | `src/nexus/contracts/backend_address.py` |
| ChannelFactory | `src/nexus/grpc/channel_factory.py` |
| PipeManager | `src/nexus/core/pipe_manager.py` |
| VFS gRPC proto | `proto/nexus/grpc/vfs/vfs.proto` |
| VFS gRPC servicer | `src/nexus/grpc/servicer.py` |
| Data architecture | `docs/architecture/data-storage-matrix.md` |
