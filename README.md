# nexus-vfs

Rust VFS kernel workspace extracted from the [nexus](https://github.com/nexi-lab/nexus) monorepo.

## Crates

| Crate | Path | Description |
|-------|------|-------------|
| `contracts` | `rust/contracts` | Types, enums, constants (zero deps) |
| `lib` | `rust/lib` | Algorithms + transport primitives |
| `transport` | `rust/transport` | gRPC transport layer |
| `kernel` | `rust/kernel` | VFS kernel (syscalls, metastore, drivers) |
| `backends` | `rust/backends` | Storage backend implementations |
| `services` | `rust/services` | Service-tier (password vault, etc.) |
| `raft` | `rust/raft` | Raft consensus for federation |
| `nexus-cluster` | `rust/profiles/cluster` | Standalone cluster binary (`nexusd-cluster`) |
| `nexus-vault` | `rust/profiles/vault` | Password vault binary (`nexusd-vault`) |

## Build

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace
```

## Option B: In-process Cargo git dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
kernel = { git = "https://github.com/nexi-lab/nexus-vfs", default-features = false }
```

This compiles the kernel as an rlib linked directly into your binary --
no gRPC, no subprocess. The consumer changes only the git URL.

## Option C: gRPC subprocess (production default)

Build and run `nexusd-cluster`:

```bash
cargo build --release -p nexus-cluster
./target/release/nexusd-cluster --help
```

The Python app layer connects via gRPC (`RPCTransport`).

---

# Kernel Architecture

Kernel architecture SSOT. Keep small and precise — prefer inplace edits over
additions. Delegate details to `docs/federation-architecture.md` and
`docs/syscall-design.md`.

---

## 1. Design Philosophy

NexusFS follows an **OS-inspired layered architecture**.

```
┌──────────────────────────────────────────────────────────────┐
│  SERVICES (user space)                                       │
│  Installable/removable. ReBAC, Auth, Agents, Scheduler, etc. │
└──────────────────────────────────────────────────────────────┘
                          ↓ protocol interface
┌──────────────────────────────────────────────────────────────┐
│  KERNEL                                                      │
│  Minimal compilable unit. VFS, MetaStore,                    │
│  ObjectStore interface definitions.                          │
└──────────────────────────────────────────────────────────────┘
                          ↓ dependency injection
┌──────────────────────────────────────────────────────────────┐
│  DRIVERS                                                     │
│  Pluggable at startup. redb, S3, LocalDisk, gRPC, etc.       │
└──────────────────────────────────────────────────────────────┘
```

### Interface Taxonomy

Every kernel interface belongs to exactly one of four categories:

| Category | Direction | Audience | Kernel relationship | API tier |
|----------|-----------|----------|---------------------|----------|
| **User Contract** (§2) | ↑ upward | Users, AI, agents, services | Kernel **implements** | Tier 1: Syscalls (`sys_*`) |
| **HAL — Driver Contract** (§3) | ↓ downward | Driver implementors | Kernel **requires** | Tier 2: 3 pillar traits |
| **Kernel Primitive** (§4) | internal | Kernel-internal only | Kernel **owns** | Tier 3: Kernel Module API (`create_from_backend`, `register_resolver`) |
| **Kernel-Authored Standard** (§5) | sideways | Services | Kernel **defines** but doesn't own | — (service standards, not kernel API) |

Tier 1 is the only user-facing interface. Tier 3 is for trusted kernel modules
(federation resolvers, ACP) — analogous to Linux `EXPORT_SYMBOL`.

### Swap Tiers

Follows Linux's monolithic kernel model, not microkernel:

| Tier | Swap time | Nexus | Syscall | Linux analogue |
|------|-----------|-------|---------|----------------|
| Static kernel | Never | MetaStore, VFS `route()`, syscall dispatch | — | vmlinuz core (scheduler, mm, VFS) |
| Drivers | Runtime mount/unmount | redb, S3, PostgreSQL, Dragonfly, SearchBrick | `sys_setattr(DT_MOUNT)` / `rmdir` | `mount`/`umount` |
| Services | Runtime register/swap/unregister | 40+ protocols (ReBAC, Auth, Agents, Search, Skills, ...) | `sys_setattr("/__sys__/services/X")` / `sys_unlink` | `insmod`/`rmmod` |

**Invariant:** Services depend on kernel interfaces, never the reverse.
The kernel operates with zero services loaded. Services flow through
`sys_setattr("/__sys__/services/X")` — factory uses the same syscall API
as runtime callers (factory = first user).

**Drivers** are mounted at runtime via `sys_setattr(entry_type=DT_MOUNT, backend=...)`,
unmounted via `rmdir`. MetaStore is the only startup-time driver (sole
kernel init param). Other drivers are mounted post-init by factory or at runtime.

---

## 2. User Contract — Syscall Interface

**Category:** User Contract (↑) | **Audience:** Users, AI, agents

### 2.1 NexusFilesystem — Published Contract

The published user-facing contract is `NexusFilesystem`:

| Tier | Content | Caller responsibility |
|------|---------|----------------------|
| **Tier 1 (abstract)** | `sys_*` kernel syscalls | Implementors MUST override |
| **Tier 2 (concrete)** | Convenience methods composing Tier 1 (`mkdir`, `rmdir`, `read`, `write`, ...) | Inherit — no override needed |

Relationship: POSIX spec (contract) vs Linux kernel (implementation) — clients
program against the contract, kernel implements it.

### 2.2 Kernel Syscalls — POSIX-Aligned, Path-Addressed

`Kernel` is the implementation of `NexusFilesystem`. It wires
primitives (§4) into user-facing operations. The kernel contains **no service
business logic**.

All kernel methods are synchronous. Blocking waits (advisory locks,
stream reads, `sys_watch`) use Rust Condvar. Async exists only at the
transport layer (gRPC, HTTP).

Kernel syscalls, all POSIX-aligned, all path-addressed:

| Plane | Syscalls |
|-------|----------|
| **Metadata** | `sys_stat`, `sys_setattr`, `sys_rename`, `sys_unlink`, `sys_readdir` |
| **Content** | `sys_read` (pread), `sys_write` (pwrite — file must exist), `sys_copy` |
| **Locking** | `sys_lock` (acquire + extend), `sys_unlock` (release + force) |
| **Watch** | `sys_watch` (inotify) |

\* **Vectored syscalls:** `sys_read`, `sys_write`, and `sys_unlink` accept a
slice of request structs (`&[ReadRequest]`, `&[WriteRequest]`, `&[UnlinkRequest]`)
and return `Vec<Result<Sys*Result, KernelError>>` — one result per request,
positionally matched. `reqs.len() == 1` takes a zero-overhead fast path;
`reqs.len() > 1` takes the batch path (rayon parallel read, sorted-lock write,
sequential unlink). Per-item errors are isolated.

`sys_setattr` is the universal creation/management syscall:
`mkdir` = `sys_setattr(entry_type=DT_DIR)`, `create` = `sys_setattr(entry_type=DT_REG)` (upsert — creates regular file if absent, updates metadata if present; accepts `content_id`, `size`, `version`, `created_at_ms`, `owner_id`),
`mount` = `sys_setattr(entry_type=DT_MOUNT, backend=...)`,
`umount` = `rmdir` on DT_MOUNT path, `symlink` = `sys_setattr(entry_type=DT_LINK, link_target=...)`.

Lock operations are consolidated into two syscalls (POSIX `fcntl(F_SETLK)` pattern):
- `sys_lock(path, lock_id=None)` — acquire (lock_id=None) or extend TTL (lock_id=existing)
- `sys_unlock(path, lock_id=None, force=False)` — release by lock_id or force-release all holders
- Lock state: `sys_stat(path, include_lock=True)` — zero cost when False (default)
- Lock listing: `sys_readdir("/__sys__/locks/")` — virtual namespace (like `/proc/locks`)
`/__sys__/` paths are kernel management operations (not filesystem metadata):
`sys_setattr("/__sys__/services/X", service=inst)` registers,
`sys_unlink("/__sys__/services/X")` unregisters.

**Primitive usage pattern:**

- **Mutating syscalls** (write, unlink, rename, copy): full pipeline — VFSRouter →
  VFSLock → KernelDispatch (3-phase) → Metastore → FileEvent
- **DT_PIPE / DT_STREAM I/O**: the routed metastore detects entry_type early in
  sys_read/sys_write and dispatches to PipeManager/StreamManager inline — no
  VFS lock, no metastore update, no observer dispatch (matching Linux `write(2)`
  on a pipe not triggering inotify)
- **DT_LINK**: route() follows the link target one hop with self-loop rejection (§4.4);
  hooks fire on the resolved target path so audit and access checks behave identically
  to a direct write
- **Read**: same pipeline minus FileEvent (reads are not mutations)
- **Read-only metadata** (stat, access, readdir, is_directory): direct Metastore
  lookup only — no routing, locking, or dispatch
- **setattr**: Metastore-only. DT_REG upsert (creates if absent, updates metadata if present). Tier 2 `mkdir` adds routing + hooks

See `docs/syscall-design.md` for the full per-syscall primitive matrix.

### 2.3 Tier 2 Convenience Methods

Tier 2 methods compose Tier 1 syscalls — concrete implementations in `NexusFilesystem`:

| Half | Examples | Addressing |
|------|----------|-----------|
| **VFS half** (POSIX-aligned) | `mkdir()`, `rmdir()`, `read()`, `write()`, `append()`, `edit()`, `write_batch()`, `access()`, `is_directory()`, `lock()`, `locked()`, `glob()`, `grep()`, `service()` | Path-addressed, delegates to `sys_*`. `glob` / `grep` are search-tier convenience built atop `sys_readdir` + filter/regex |
| **Xattr** (extended attributes) | `get_xattr(path, key)`, `set_xattr(path, key, value)`, `get_xattr_bulk(paths, key)` | Direct metastore `get_file_metadata`/`set_file_metadata` — no hooks, no routing, no permission gate. Rust `KernelConvenience` trait |
| **HDFS half** (driver-level, kernel-internal) | `read_content()`, `write_content()`, `stream()`, `stream_range()`, `write_stream()` | Hash-addressed (etag/CAS), direct to ObjectStore |

The HDFS half bypasses path resolution and metadata lookup — CAS is a driver
detail. Like HDFS separates ClientProtocol (NameNode, path-based) from
DataTransferProtocol (DataNode, block-based). The metadata layer above ensures
etag ownership and zone isolation.

The HDFS half is kernel-internal — see §2.5 for the contract. Service-tier
callers go through `sys_read(path)` with optional content_hash verification;
features that need stable historical bytes express them as paths (workspace
snapshots, version history) and read those paths through the syscall surface.

**Kernel-managed metadata side effects** (POSIX `generic_write_end` pattern):
kernel updates mtime, size, version, etag in VFS lock after
`backend.write_content()`. Drivers only manage content.
Consistency is zone-level (configured at metastore layer), not per-write.

### 2.4 VFS Dispatch (KernelDispatch)

The kernel provides callback-based dispatch at 6 VFS operation points (read,
write, delete, rename, mkdir, copy) plus driver lifecycle events (mount,
unmount). These are kernel-owned callback lists (implemented by
`KernelDispatch`, §4) that any authorized caller populates.

**Three-phase dispatch per VFS operation:**

| Phase | Semantics | Short-circuit? | Linux Analogue |
|-------|-----------|----------------|----------------|
| **PRE-DISPATCH** | First-match short-circuit | Yes (skips pipeline) | VFS `file->f_op` dispatch (procfs, sysfs) |
| **INTERCEPT** | Synchronous, ordered (pre + post) | Yes (abort/policy) | LSM security hooks |
| **OBSERVE** | Fire-and-forget | No | `fsnotify()` / `notifier_call_chain()` |

**Driver lifecycle hooks:**

| Phase | Semantics | Short-circuit? | Linux Analogue |
|-------|-----------|----------------|----------------|
| **MOUNT** | Fire-and-forget on backend mount | No | `file_system_type.mount()` |
| **UNMOUNT** | Fire-and-forget on backend unmount | No | `kill_sb()` |

Mount/unmount hooks are dispatched by `DriverLifecycleCoordinator` (§4) via
KernelDispatch. Backends declare mount hooks via `hook_spec()` (same pattern
as VFS hooks). CASAddressingEngine uses `on_mount` for mount-time logging.

**PRE-DISPATCH**: `VFSPathResolver` instances checked in order; first match
handles entire operation. Each resolver owns its own permission semantics.

**INTERCEPT**: Per-operation `VFS*Hook` protocols. Hooks receive a typed context
dataclass, can modify context or abort. POST hooks support sync and async
(classified by Rust `HookRegistry`). Audit is a factory-registered interceptor,
not a kernel built-in.

**OBSERVE**: `VFSObserver` instances receive frozen `FileEvent` (§4.3) on all
mutations. Strictly fire-and-forget — failures never abort the syscall.
Observers needing causal ordering belong in INTERCEPT post-hooks, not OBSERVE.

**Registration API:** Each phase has a symmetric `register_*()` /
`unregister_*()` pair — runtime-callable by any authorized caller.

#### 2.4.1 The 4 Dispatch Contracts

Each dispatch phase is a formal contract between the kernel and its callers.
These contracts define ordering, error semantics, and performance guarantees.

| # | Contract | Phase | Trait | Dispatch semantics | Error handling |
|---|----------|-------|-------|-------------------|----------------|
| 1 | **RESOLVE** (PRE-DISPATCH) | Before pipeline | `PathResolver` trait | PathTrie O(depth) lookup, then fallback linear scan. First resolver whose `try_*(path)` returns non-None handles the entire operation — normal VFS pipeline is skipped. | Resolver errors propagate to caller (resolver owns error semantics). |
| 2 | **INTERCEPT PRE** | Before HAL I/O | `InterceptHook` trait | Serial, ordered. All registered pre-hooks run in registration order. | Any hook may abort by returning `Err` — error propagates to caller, operation is cancelled. |
| 3 | **INTERCEPT POST** | After HAL I/O | `InterceptHook` trait | Serial, fire-and-forget via Rust `dispatch_post_hooks()`. | Failures are logged and swallowed — never affect the caller or the operation result. |
| 4 | **OBSERVE** | After lock release | `VFSObserver` | Inline observers: synchronous on caller thread. Deferred observers: submitted to kernel observer ThreadPoolExecutor (4 threads, `observe` prefix). Event mask bitmask filtering at registration time. | Failures are caught and logged — never abort the syscall. Observers needing causal ordering belong in INTERCEPT POST, not OBSERVE. |

**Ordering guarantee:** RESOLVE > Permission Gate > INTERCEPT PRE > HAL I/O > INTERCEPT POST > OBSERVE.
OBSERVE always fires after VFS lock release (like Linux inotify after `i_rwsem`).

**Permission Gate** (Linux analogue: `security_inode_permission()`):
Kernel-level permission check called before INTERCEPT PRE on every `sys_*`
with `OperationContext`. Decision cascade (short-circuits on first decisive
step): `/__sys__/` path bypass → `is_system` bypass → no-provider fast-path
(~1ns `AtomicBool`) → lease cache hit (~100-200ns `DashMap` per depth level) →
admin bypass → `zone_perms` federation grant → `PermissionProvider.check()`.
Pluggable `PermissionProvider` trait registered once at boot; implementations
live in the services tier. `PermissionLeaseCache`: inheritance-aware `(path,
agent_id) → TTL` DashMap cache; parent directory lease covers child files.
`Permission` enum: `Read`, `Write`, `Traverse`.
Source of truth: `rust/kernel/src/kernel/dispatch.rs` (gate),
`rust/kernel/src/core/permission_cache.rs` (lease cache),
`rust/kernel/src/core/dispatch/mod.rs` (trait + enums).

**Why separate the Permission Gate from INTERCEPT PRE?** The gate runs in
~100-200ns pure Rust (AtomicBool + DashMap lease cache); full ReBAC evaluation
in INTERCEPT PRE requires metadata access. Separating them lets cached
grants bypass INTERCEPT entirely.

**Per-syscall dispatch matrix** (source of truth: `io.rs`):

| Syscall | Permission Gate | INTERCEPT PRE | INTERCEPT POST | OBSERVE |
|---------|:---:|:---:|:---:|:---:|
| `sys_read` | Read | ReadHookCtx | — | — |
| `sys_write` | Write | WriteHookCtx | WriteHookCtx | FileWrite |
| `sys_write_batch` | Write (per-item) | — | — | FileWrite (per-item) |
| `sys_unlink` | Write | DeleteHookCtx | DeleteHookCtx | FileDelete / DirDelete |
| `sys_rename` | Write (both) | RenameHookCtx | RenameHookCtx | FileRename |
| `sys_copy` | Read + Write | — | — | FileCopy |
| `mkdir` (Tier 2) | Write | — | — | DirCreate |
| `sys_setattr` | Write | — | — | MetadataChange |
| `sys_stat` | — | — | — | — |

**Zero-overhead invariant:** Empty callback list = no-op dispatch = zero overhead
when no services are registered.

**Kernel boundary:** Python reaches the Rust kernel via
gRPC to the `nexus-cluster` process. Each `sys_*` call is one gRPC
round-trip. Inside the Rust process, pillar calls, hook dispatch,
and service lifecycle are all pure Rust with zero FFI crossings.

### 2.5 Mediation Principle

Services access HAL only through syscalls. For mutating syscalls the pipeline is:
PRE-DISPATCH → route → permission gate → INTERCEPT pre → lock → HAL I/O
→ unlock → INTERCEPT post → OBSERVE. See `docs/syscall-design.md` for the full
per-syscall flow.

The MetaStore pillar (§3.A.1) and the ObjectStore pillar (§3.A.2) are HAL
contracts the kernel implements over. Reaching them directly — `MetaStore.list`,
`MetaStore.put`, `Arc<dyn ObjectStore>::read_content` etc. — is a kernel-internal
capability. Service-tier callers (Rust peer crates in `rust/services/`,
`rust/raft/`, `rust/transport/`, `rust/backends/`) reach the same
state through the §2.2 syscall surface (paths) or the §4 dispatch hook ABI
(observers, resolvers, hooks).

The §2.3 Tier 2 HDFS half (hash-addressed `read_content` / `write_content` /
streaming) is one such kernel-internal surface — used by federation cross-node
fetch (`KernelBlobFetcher` in `rust/raft/`) and by other Rust kernel-internal
modules that need content-hash addressing for replication, dedup, or storage
GC. Service-tier features that want hash-addressed semantics (workspace
versioning, transactional snapshots, etc.) express them as paths and read
through `sys_read(path)`, optionally verifying the served content_hash matches
an expected value.

---

## 3. HAL — Storage HAL & Control-Plane HAL

**Category:** HAL — Driver Contract (↓) | **Audience:** Driver implementors

The kernel exposes two HAL flavors:

- **§3.A Storage HAL** — persistent-data driver contracts. The 3 trait pillars
  (MetaStore, ObjectStore, CacheStore) plus the Transport x Addressing
  composition that decomposes ObjectStore.
- **§3.B Control-Plane HAL** — runtime DI surfaces. Capabilities the kernel
  needs but does not own: distributed namespace topology
  (`DistributedCoordinator`) and backend instantiation (`ObjectStoreProvider`).

Both flavors live under `rust/kernel/src/`: `abc/` for the §3.A pillars,
`hal/` for §3.B.

### 3.A Storage HAL — Trait Pillars

NexusFS abstracts storage by **Capability** (access pattern + consistency guarantee),
not by domain or implementation.

| Pillar | Trait (Rust) | Capability | Kernel Role | Crate path |
|--------|-------------|------------|-------------|------------|
| **MetaStore** | `MetaStore` | Ordered KV, CAS, prefix scan, optional Raft SC | **Required** — sole kernel init param | `kernel/src/abc/metastore.rs` |
| **ObjectStore** | `ObjectStore` | Streaming I/O, immutable blobs, petabyte scale | **Interface only** — instances mounted via `nx.mount()` | `kernel/src/abc/object_store.rs` |
| **CacheStore** | `CacheStore` | Ephemeral KV, Pub/Sub, TTL | **Optional** — defaults to `NullCacheStore` | `kernel/src/abc/cache_store.rs` |

**Rust-side strict layout:** `kernel/src/abc/` contains exactly the
3 §3.A pillar trait files. `kernel/src/hal/` contains the §3.B
Control-Plane HAL trait files (`DistributedCoordinator`,
`ObjectStoreProvider`). Kernel primitives (§4) live in `kernel/src/core/`
as concrete types. Connector-backend protocol extensions
(e.g. `LlmStreamingBackend`) live in `rust/backends/`; the matching
trait DECLARATION stays at the kernel boundary because
`ObjectStore::as_llm_streaming()` returns
`Option<&dyn LlmStreamingBackend>` in the kernel trait. Concrete impls
(`OpenAIBackend`, `AnthropicBackend`) live in
`rust/backends/transports/api/ai/`. Transport-layer abstractions
(`PeerBlobClient`, TOFU trust store) live in the tier-neutral
`rust/lib/` crate's `transport_primitives` module. Directory layout
enforces the three-way split: `abc/` is for §3.A pillars, `hal/` is
for §3.B DI surfaces, `core/` is for primitives.

**Orthogonality:** Between pillars = different query patterns. Within pillars =
interchangeable drivers (deployment-time config).

**Kernel self-inclusiveness:** Kernel boots with **1 pillar** (MetaStore);
ObjectStore mounts post-init. The kernel's own data needs are intentionally
minimal — O(1) KV with ordered prefix scan over zone-tagged `FileMetadata`
rows. Higher-level shapes (JOINs, FK, vector search, TTL, pub/sub) live in
the service layer, mirroring Linux's split: kernel defines VFS + block-device
interfaces while filesystems ship as separate modules.

#### 3.A.1 MetaStore — Inode Layer

**Linux analogue:** `struct inode_operations`

The typed contract between VFS and storage. Without it, the kernel cannot
describe files. Operations: O(1) KV (get/put/delete), ordered prefix scan
(list), batch ops, implicit directory detection. System config stored under
`/__sys__/` prefix.

Data type: `FileMetadata` — path, backend_name, etag, size, version, zone_id,
owner_id, timestamps, mime_type. Every row carries a `zone_id` — the
**kernel namespace partition identifier** (analogous to Linux `sb->s_dev`),
which federation extends with Raft consensus groups while the kernel owns
the concept. `owner_id` is the kernel's posix_uid — consumed by
`PermissionEnforcerProtocol.check_owner()` for O(1) DAC before service-layer
hooks run. Audit trail (who created a file) lives in the service layer
(`VersionRecorder`); the kernel inode keeps the steady-state fields only.

#### 3.A.2 ObjectStore (= Backend) — Blob I/O

**Linux analogue:** `struct file_operations`

CAS-addressed blob storage: read/write/delete by etag (content hash), plus
streaming variants. Directory ops (mkdir/rmdir/list_dir) for backends that
support them. Rename is optional (capability-dependent).

#### 3.A.3 CacheStore — Ephemeral KV + Pub/Sub (Optional)

**Linux analogue:** `/dev/shm` + message bus

The only **optional** HAL pillar. Kernel defines the trait (ephemeral KV + pub/sub);
services consume it for caching, event fan-out, and session storage.
Drivers: Dragonfly/Redis (production), `InMemoryCacheStore` (dev).

**Graceful degradation:** `NullCacheStore` (no-op) is the default. Without a real
CacheStore, EventBus disables, permission/tiger caches fall back to RecordStore,
and sessions stay in RecordStore. No kernel functionality is lost.

#### 3.A.4 Dual-Axis Architecture

Two independent axes, composed via DI:

- **Data traits** (this section): WHERE is data stored? → 3 kernel pillars by storage capability
- **Ops traits** (§5.3): WHAT can users/agents DO? → 40+ scenario domains by ops affinity

A concrete type sits at the intersection: e.g. `ReBACManager` implements
`PermissionProtocol` (Ops) and internally uses `RecordStore` (Data).

#### 3.A.5 Transport x Addressing Composition

**Linux analogue:** Block device driver (Transport) x filesystem (Addressing)

ObjectStore backends decompose into two orthogonal axes: **Transport** (WHERE —
raw key→bytes I/O) and **Addressing Engine** (HOW — CAS or Path). Every backend,
including external API connectors, is a Transport composed with an addressing
engine. REST APIs are filesystems: `GET` = `fetch`, `PUT` = `store`, `DELETE` = `remove`.

**DT_EXTERNAL_STORAGE** (`entry_type=5`): Mount-time detection via
`ConnectorRegistry.category` for OAuth APIs and CLI tools.

### 3.B Control-Plane HAL — Runtime DI Surfaces

Storage HAL (§3.A) is the persistent-data flavor of HAL; Control-Plane HAL is
the in-memory coordination flavor. The kernel calls a trait method, an
external crate's impl handles the actual work. Same DI shape on both sides:
trait declared in `kernel/src/hal/`, concrete impl in the owner crate, an
`Arc<dyn Trait>` slot the process boots before any syscall fires.

| Trait | Capability | Default Impl | Reference Impl |
|-------|------------|--------------|----------------|
| `DistributedCoordinator` | Per-node distributed namespace topology — zones, mounts, share registry, leader/voter introspection | `NoopDistributedCoordinator` (errors out) | `RaftDistributedCoordinator` in `rust/raft/` |
| `ObjectStoreProvider` | Construct `Arc<dyn ObjectStore>` for a given backend type + args | `OnceLock` slot installed at boot | `DefaultObjectStoreProvider` in `rust/backends/` |

#### 3.B.1 `DistributedCoordinator`

**Linux analogue:** `struct super_operations` — the abstraction the VFS layer
talks through to reach any concrete filesystem driver without naming the
driver type. `DistributedCoordinator` plays the same role for distributed
namespace topology: kernel-side syscalls dispatch through
`kernel.distributed_coordinator()` instead of naming `nexus_raft::*` types
directly.

11 methods, four families:

- **Introspection (2):** `list_zones`, `cluster_info`. `ClusterInfo` carries
  `leader_id`, `term`, `voter_count`, `witness_count`, `links_count`,
  `commit_index`, applied index — typed Rust struct.
- **Zone lifecycle (3):** `create_zone`, `remove_zone` (cascade-unmounts cross-zone
  references first; `force=true` honors the POSIX-style `unlink while i_links > 0`
  bypass), `join_zone` (`as_learner=true` for non-voter membership).
- **Mount wiring (2):** `wire_mount` / `unwire_mount` — leader-side fast-path.
  The apply-cb on the state machine is the correctness guarantee, this pair is
  the optimization.
- **Share registry (2):** `share_zone` (atomic create-zone + copy-subtree +
  register-share), `lookup_share` returns a `ShareInfo` (zone_id +
  remote-path metadata).
- **Per-zone dispatch (2):** `metastore_for_zone` returns
  `Arc<dyn MetaStore>` backed by Raft state machine; `locks_for_zone` returns
  `Arc<dyn Locks>` that replicates lock acquisition via
  `Command::AcquireLock`.

Boot-time setup is a module-level `install()` function — a once-per-process
hook that wires the slot and folds in DI plumbing (blob-fetcher slot stash)
that lives outside the runtime surface. Same shape as
`transport::python::install_transport_wiring`.

Naming convention follows the §3.A pillars (`MetaStore`, `ObjectStore`,
`CacheStore`): the trait name describes the capability — distributed-namespace
coordination — rather than the implementation (Raft) or a GoF role (Provider /
Manager).

#### 3.B.2 `ObjectStoreProvider`

Single method: `build(args: &ObjectStoreProviderArgs) -> Result<ObjectStoreBuildResult, String>`.
`ObjectStoreBuildResult` bundles `Option<Arc<dyn ObjectStore>>` (the backend)
and `Option<Arc<dyn MetaStore>>` (remote metastore, for `"remote"` backends).

`Kernel::sys_setattr("backend", ...)` and the mount path use this to instantiate
backends through trait dispatch. Cycle break is identical to the §3.A pattern:
kernel declares the trait, backends crate provides the impl, process boot wires
the slot.

The trait name describes the capability ("provides ObjectStore instances"), in
symmetry with `DistributedCoordinator` and the §3.A pillars.

---

## 4. Kernel Primitives

**Category:** Kernel Primitive (internal) | **Audience:** Kernel-internal

Primitives mediate between user-facing syscalls and HAL drivers. Users interact
with them indirectly through syscalls. See §2.2 for per-syscall usage.

| Primitive | Location | Linux Analogue | Role |
|-----------|----------|---------------|------|
| **VFSRouter** | `kernel/src/core/vfs_router.rs` | VFS `lookup_slow()` | `route(path, zone_id)` → `RouteResult`. Zone-canonical LPM (~30ns Rust). In-memory mount table keyed by `/{zone_id}/{mount_point}` |
| **LockManager** | `kernel/src/core/lock/` | `i_rwsem` + `flock(2)` + `sem_t` | I/O lock + advisory lock in one primitive (§4.1). I/O lock: per-path condvar-based RW lock. Advisory lock: `sys_lock`/`sys_unlock` with TTL via the `Locks` HAL trait (`LocalLocks` default, replicated backend via `install_locks(Arc<dyn Locks>)`) |
| **KernelDispatch** | `kernel/src/kernel/dispatch.rs` + `kernel/src/core/dispatch/` | `security_hook_heads` + `fsnotify` | Three-phase VFS dispatch (§2.4) + driver lifecycle hooks (MOUNT/UNMOUNT). Owns PathTrie + HookRegistry + ObserverRegistry. Empty = zero overhead |
| **PipeManager + StreamManager** | `kernel/src/core/pipe/` + `kernel/src/core/stream/` | `pipe(2)` + append-only log | VFS named IPC. DT_PIPE: destructive FIFO (MemoryPipeBackend / SharedMemoryPipeBackend). DT_STREAM: non-destructive offset reads. Details in §4.2 |
| **FileDescriptorTable** | `kernel/src/core/fdt.rs` | fd table (`task_struct.files`) | Pre-opened fd registry for PAS backends. `sys_write` registers via `ObjectStore::resolve_physical_path()`; `sys_read` fast-path via `libc::pread`; `sys_unlink` removes; `sys_rename` re-keys |
| **FileWatcher + FileEvent** | `kernel/src/core/file_watch.rs` | `inotify(7)` + `fsnotify_event` | File change notification + immutable mutation records. Local OBSERVE waiters + optional RemoteWatchProtocol. Details in §4.3 |
| **ServiceRegistry** | `kernel/src/core/service_registry.rs` | `init/main.c` + `module.c` | Kernel-owned symbol table + lifecycle orchestration (enlist/swap/shutdown). BackgroundService + duck-typed hook_spec() |
| **DriverLifecycleCoordinator** | `kernel/src/core/dlc.rs` | `register_filesystem` + `kern_mount` | Routing table + metastore + lock manager upgrade. Apply-side cache coherence is metastore-internal |
| **PermissionGate** | `kernel/src/kernel/dispatch.rs` + `kernel/src/core/permission_cache.rs` | LSM `security_inode_permission` | Kernel permission gate called before NativeInterceptHook dispatch on every `sys_*`. Decision cascade with lease cache (~100-200ns). Details in §2.4.1 |
| **AgentRegistry** | `kernel/src/core/agents/registry.rs` | Linux `task_struct` table + signal queue | Kernel SSOT for agent lifecycle: PID allocation, parent/child tree, signal semantics (SIGTERM/SIGSTOP/SIGCONT/SIGKILL/SIGUSR1), `AgentState::can_transition_to` validation, per-PID condvar wake-ups. Shared `Arc` exposed to procfs view (`AgentStatusResolver`) — no dual-write |
| **DT_LINK** | `proto/nexus/core/metadata.proto` (`DT_LINK = 6`) + `FileMetadata.link_target` | `symlink(2)` | Path-internal symlink resolved by `VFSRouter::route()` before reaching the backend. Single-hop redirect with `ELOOP` on chained or self-loop links. Details in §4.4 |
| **PermissionLeaseCache** | `kernel/src/core/permission_cache.rs` | LSM credential cache | Two-level DashMap of `(path, agent_id) → expiry` short-circuiting the permission gate's full ReBAC walk on a recent hit. Inheritance-aware: a parent-directory lease covers child files. Details in §2.4.1 |

### 4.1 Unified LockManager — I/O Lock + Advisory Lock

Rust `LockManager` (`rust/kernel/src/core/lock/`) unifies the kernel's
two locking concerns in one primitive — sharing the path-normalisation
helper, the hierarchy-aware conflict logic, and the `core/lock/` module
home. Constructed in `Kernel::new()` with a default `LocalLocks`
advisory backend; a replicated backend swaps in via
`install_locks(Arc<dyn Locks>)` at federation mount time (first-wins,
idempotent).

| Property | I/O Lock | Advisory Lock |
|----------|----------|---------------|
| Linux analogue | `i_rwsem` | `flock(2)` / `fcntl(F_SETLK)` / `sem_t` |
| Modes | `read` (shared) / `write` (exclusive) | counting via `max_holders` — `max_holders == 1` is the mutex form, `max_holders > 1` is the counting-semaphore form; same code path |
| Latency target | ~200ns (Rust condvar) | ~5us local / ~5-10ms Raft |
| Scope | Process-scoped, crash → released | TTL-based, expire → released |
| Visibility | Kernel-internal (`sys_read`/`sys_write`) | User-facing (`sys_lock`/`sys_unlock`) |
| Holder ID | Implicit handle (u64 from `next_handle`) | Caller-supplied `lock_id` string |
| Storage | In-memory only | Shared `Arc<Mutex<LockState>>` — `contracts::lock_state` is SSOT; the replicated backend's apply-path writes into the same Arc |
| Local impl | per-path condvar RW | `LocalLocks` (`core/lock/locks.rs`) — mutates the shared `LockState` Arc directly |
| Distributed impl | n/a (process-local) | replicated `Locks` HAL backend installed via `install_locks(Arc<dyn Locks>)`; apply-path mutates the same `LockState` Arc so reads observe committed state without a quorum round-trip |
| Syscalls | implicit (taken inside `sys_read` / `sys_write`) | `sys_lock` (try-acquire, Tier 1), `sys_unlock` (release, Tier 1), `lock()` (blocking wait, Tier 2) |

See `docs/lock-architecture.md` for full design. See `docs/federation-architecture.md` for
the replicated-backend install path.

### 4.2 IPC Primitives — Named Pipes & Streams

Two-layer architecture for both: VFS metadata (inode) in MetaStore, data
(bytes) in process heap buffer (like Linux `kmalloc`'d pipe buffer).

| Primitive  | Linux Analogue    | Buffer         | Read          |
|------------|-------------------|----------------|---------------|
| DT_PIPE    | `kfifo` ring      | MemoryPipeBackend     | Destructive   |
| DT_STREAM  | append-only log   | MemoryStreamBackend   | Non-destructive (offset-based) |

**DT_PIPE (PipeManager + MemoryPipeBackend):**

- **PipeManager (mkpipe)** — VFS named pipe lifecycle (created via `sys_setattr`
  upsert, read/write via `sys_read`/`sys_write`, destroyed via `sys_unlink`),
  per-pipe lock for MPMC safety. Reads are destructive (consumed on read).
- **MemoryPipeBackend (kpipe)** — Lock-free **SPSC** kernel primitive (`kfifo` analogue),
  no internal synchronization. Kernel manages pipe lifecycle directly.
  Direct MemoryPipeBackend access is kernel-internal only.

**DT_STREAM (StreamManager + pluggable StreamBackend):**

- **StreamManager (mkstream)** — VFS named stream lifecycle (same syscall
  surface as mkpipe). Per-stream lock for concurrent writers. Reads are
  non-destructive — multiple readers maintain independent byte offsets (fan-out).
- **StreamBackend protocol** — pluggable backing store for DT_STREAM data.
  `io_profile` determines which backend is used at creation time.
  Implementations: `MemoryStreamBackend` (in-memory, default),
  `SharedMemoryStreamBackend` (mmap shared memory, cross-process, ~1-5us),
  `WalStreamCore` (Raft-replicated WAL, durable + distributed).

**io_profile — Backend Selection via sys_setattr:**

`sys_setattr(path, entry_type=DT_PIPE|DT_STREAM, io_profile=...)` selects the
backend implementation at creation time. `io_profile` defaults to `"memory"`
(in-process ring buffer); `"shared_memory"` creates mmap-based cross-process
IPC; `"wal"` creates a Raft-replicated WAL stream (requires federation).
Rust kernel creates the backend, registers it in PipeManager/StreamManager,
and returns SHM metadata (`shm_path`, `data_rd_fd`, `space_rd_fd`) for
asyncio integration. sys_read/sys_write go through Rust PipeManager
regardless of io_profile — zero state outside the kernel.

See `docs/federation-architecture.md` for design rationale.

### 4.3 FileWatcher + FileEvent — File Change Notification

| Property | Value |
|----------|-------|
| Event types | `FILE_WRITE`, `FILE_DELETE`, `FILE_RENAME`, `METADATA_CHANGE`, `DIR_CREATE`, `DIR_DELETE`, `CONFLICT_DETECTED`, `FILE_COPY`, `MOUNT`, `UNMOUNT` |
| FileEvent | Frozen struct: path, etag, size, version, zone_id, agent_id, user_id, vector_clock |
| FileWatcher (kernel-owned) | Local OBSERVE waiters — `on_mutation()` resolves in-memory futures (~0us) |
| FileWatcher (kernel-knows) | Optional `RemoteWatchProtocol` for distributed watch, set via `set_remote_watcher()` |
| Emission point | Always AFTER lock release |

### 4.4 DT_LINK — Path-Internal Symlink

| Property | Value |
|----------|-------|
| Linux analogue | `symlink(2)` |
| Entry type | `DT_LINK = 6` (`proto/nexus/core/metadata.proto`) |
| Storage | `FileMetadata.link_target` — absolute or workspace-relative VFS path |
| Resolution | Kernel `route()` follows the link before reaching the backend; one hop only, with self-loop rejection |

A DT_LINK is a metadata-only entry whose `link_target` field carries the path it
points at. Path resolution treats it as a redirect: every `sys_*` call against a
DT_LINK path resolves to the equivalent operation on the link target, with hooks
firing on the resolved target path. `sys_unlink` removes the link without touching
the target; `sys_stat` reports the entry as a link with its `link_target` filled in.

Cycle handling is bounded by the one-hop rule — if `target` is itself a DT_LINK,
the resolver returns `ELOOP` rather than chaining. Self-loops (`link → itself`) are
rejected at `sys_setattr` time.

**Use cases:**

- `/proc/{pid}/agent` → `/agents/{name}/` (runtime back-reference to image; mirrors Linux `/proc/{pid}/exe`)
- `/proc/{pid}/workspace/chat-with-me` → `/proc/{pid}/chat-with-me` (workspace-anchored mailbox shortcut so agents addressing each other don't have to walk the registry)

---

## 5. Kernel-Authored Standards

**Category:** Kernel-Authored Standard (service-tier contract) | **Audience:** Services

### 5.1 The "Standard Plug" Principle

The kernel defines contracts it doesn't own — so kernel infrastructure works
automatically with any service that conforms.

**Linux analogies:**

| Linux pattern | What kernel defines | What modules provide | Kernel benefit |
|---------------|--------------------|--------------------|----------------|
| `file_operations` | Struct with read/write/ioctl pointers | Each filesystem fills the struct | VFS calls any filesystem uniformly |
| `security_operations` | Struct with 200+ LSM hook pointers | SELinux, AppArmor fill hooks | Security framework calls any LSM |

**Nexus equivalent:**

| Nexus pattern | What kernel defines | What services provide | Infrastructure benefit |
|---------------|--------------------|--------------------|----------------------|
| `RecordStore` | Session factory + read replica interface | PostgreSQL, SQLite drivers | Services get pooling, error translation, replica routing |
| `VFS*Hook` traits | Hook shapes (context structs) | Service-layer hook implementations | KernelDispatch calls any conforming hook uniformly |
| Service Protocols | Typed trait interfaces | Concrete service implementations | Typed contracts for service implementors |

### 5.2 RecordStore — Relational Storage Standard

| Property | Value |
|----------|-------|
| Kernel role | Kernel **defines** the trait — services consume |
| Consumers | Services (ReBAC, Auth, Agents, Scheduler, etc.) |
| Interface | `session_factory` + `read_session_factory` (SQLAlchemy ORM) |
| Drivers | PostgreSQL, SQLite (interchangeable without code changes) |
| Access path | Through the trait's session factories — pooling, error translation, replica routing flow from there |

The kernel is the standards body — it defines the interface shape that forces
driver implementors to provide pooling, error translation, read replica routing,
WAL mode, async lazy init. Both sides (drivers and services) conform to the
same interface; neither needs to know the other.

### 5.3 Service Protocols — 40+ Scenario Domains

40+ typed trait interfaces organized by domain
(Permission, Search, Mount, Agent, Events, Memory, Domain, Audit, Cross-Cutting).

---

## 6. Tier-Neutral Infrastructure (`contracts/`, `lib/`)

Two crates sit **outside** the Kernel → Services → Drivers stack.
Any layer may import from them; their own imports stay within
`contracts/` and `lib/` (plus the standard library), keeping them
tier-neutral leaves of the dependency graph.

| Crate | Contains | Linux Analogue | Rule |
|-------|----------|----------------|------|
| **`contracts/`** | Types, enums, exceptions, constants | `include/linux/` (header files) | Declarations only — zero implementation logic, zero I/O |
| **`lib/`** | Reusable helper functions, pure utilities | `lib/` (libc, libm) | Implementation allowed; depends on `contracts/` and stdlib only |

**Core distinction:** `contracts/` = **what** (shapes of data). `lib/` = **how** (behavior).

`rust/lib/` builds against `wasm32-unknown-unknown` with default features.

`rust/lib/` also carries the `transport_primitives` module — TLS
config, peer addressing, connection pooling, channel creation, the
TOFU trust store, and the `PeerBlobClient` trait. The module sits
behind the optional `transport` feature so WASM / pure-algo callers
skip the tonic + tokio dep stack. Every peer crate that speaks raft
or VFS gRPC (raft, transport, kernel through the peer-client slot)
enables `lib`'s `transport` feature.

### 6.1 Workspace Composition

The Rust workspace splits into two Cargo artifact roles:

| Cargo role      | Cargo type   | Purpose                                                                  |
|-----------------|--------------|--------------------------------------------------------------------------|
| Library crates  | `rlib`       | Compose into deployment binaries.                                        |
| Profile binary  | binary       | `rust/profiles/<name>/` — standalone deployment binaries.                |

The Linux analogue is `make bzImage`: rlibs compile into the final
deployment binary the same way `fs/built-in.a` and `kernel/built-in.a`
link into `vmlinuz`.

#### Crate Role Taxonomy

The library crates split into 5 architectural roles. Every peer crate
maps to exactly one role — that is the invariant that lets the dep
graph stay acyclic.

| Role | Crates | Linux analogue | Charter |
|------|--------|----------------|---------|
| **OS proper** | `kernel/`, `contracts/` | `kernel/` (vmlinux core) | VFS, syscalls, namespace primitives, HAL trait declarations. Depends on `contracts` and `lib`. |
| **Driver layer (kernel-internal)** | `backends/`, `raft/` | `drivers/` | Implement HAL traits; consume kernel's runtime API. `backends` = local storage drivers (ObjectStore impl). `raft` = distributed storage driver (MetaStore impl + DistributedCoordinator impl). |
| **Network surface (kernel-external)** | `transport/` | `net/` | VFS gRPC server + IPC envelope helpers (in-bound) plus VFS / peer-blob / federation clients (driver-outgoing). One crate covers both directions like Linux's `net/` covers both server sockets and outgoing connections. Depends on `kernel`, `lib`, and `raft` (proto stubs for the federation client). |
| **Post-syscall services (kernel-internal hooks)** | `services/` | LSM hooks (`security/`) | Audit, agents, permission, tasks. Fired on syscall paths through registered hooks; depends on `kernel`. |
| **Tier-neutral lib (§6)** | `lib/` | `lib/` (libc, libm) | Pure utilities depending on `contracts` only. Algorithms (bitmap, bloom, glob, hash, simd, ...) plus the `transport_primitives` module (TLS, pool, addressing, TOFU trust store, `PeerBlobClient` trait). |

The role split makes the orthogonality invariants
**`services ⊥ backends ⊥ raft`** (services and backends reach raft
state through `kernel.sys_*` syscalls, never via Cargo dep) and
**`kernel ⊥ raft`** (kernel reaches raft only through trait dispatch)
read directly off the table.

#### Kernel Crate Composition

`rust/kernel/src/kernel/` hosts the `Kernel` struct and its
syscall implementations across per-family submodules:

| File                | Owns                                                                           |
|---------------------|--------------------------------------------------------------------------------|
| `kernel/mod.rs`     | `Kernel` struct, constructor, wiring, MetaStore + Router proxies, syscall-shaped helpers (`lookup_content_id`, `with_metastore_route`, `commit_metadata`, `commit_delete`). |
| `kernel/io.rs`      | Tier 1 `sys_read` / `sys_write` / `sys_stat` / `sys_unlink` / `sys_rename` / `sys_copy`, plus the optimized inherent bodies for the Tier 2 `access` / `mkdir` / `rmdir` overrides. |
| `kernel/ipc.rs`     | Pipe + stream registries (`create_pipe`, `pipe_write_nowait`, `stream_read_at`, ...). |
| `kernel/locks.rs`   | Advisory-lock syscalls (`sys_lock`, `sys_unlock`, `metastore_list_locks`, `install_federation_locks`). |
| `kernel/dispatch.rs`| Native INTERCEPT hook dispatch (`dispatch_native_pre`, `dispatch_native_post`, `register_native_hook`). |
| `kernel/observability.rs` | Observer registry, file-watch registry, `sys_watch`, `dispatch_mutation` shared helper. |
| `kernel/mount.rs`   | Mount-table primitives (`add_mount`, `remove_mount`, `install_mount_metastore`, `route`, ...). |
| `kernel/federation.rs` | `DistributedCoordinator` slot accessors, `/__sys__/zones/` procfs synthesisers, blob-fetcher slot plumbing. |
| `kernel/convenience.rs` | Tier 2 `KernelConvenience` trait composing Tier 1 syscalls — `access`, `mkdir`, `rmdir`, `stat_batch`, `exists_batch`, `get_content_id`, `is_directory`, `get_top_level_mounts`, `set_xattr` / `get_xattr` / `get_xattr_bulk`, Tier 2 `write` (create-or-overwrite) plus Tier 2 single-file `read` / `unlink` defaults. |

The split between `kernel/` (syscalls) and `core/` (primitives) follows
the data type: §4 primitives — concrete data structures like
`VFSRouter`, `AgentRegistry`, `LockManager` — live in `core/`; the
syscall families that operate on them live in `kernel/`.

#### Control-Plane HAL DI Surface

The `Kernel.distributed_coordinator` slot holds an
`Arc<dyn DistributedCoordinator>` that drives every federation-aware
syscall (§3.B.1). Trait surface lives in `kernel::hal::distributed_coordinator`;
concrete impl (`RaftDistributedCoordinator`) lives in the raft crate at
`nexus_raft::distributed_coordinator`. The kernel → raft Cargo edge is
`raft → kernel` — kernel reaches distributed state through the trait dispatch,
with the coordinator owning that state.

Boot wiring:

| Step | Caller                                                           | Effect                                                                    |
|------|------------------------------------------------------------------|---------------------------------------------------------------------------|
| 1    | `Kernel::new`                                                    | Slot defaults to `NoopDistributedCoordinator`                             |
| 2    | `RaftDistributedCoordinator::install_with_kernel(...)` | Slot is replaced with `RaftDistributedCoordinator`. Publishes federation self-address, installs DT_MOUNT apply-cb on every loaded zone, replays DT_MOUNT entries after restart, wires the blob-fetcher slot, and flips `bootstrap_done`. Called from `nexusd-cluster::run_daemon`. |
| 3    | Federation syscalls (`create_zone`, `wire_mount`, ...) | Dispatch through `kernel.distributed_coordinator().<method>(kernel, ...)`   |

The §3.B.2 `ObjectStoreProvider` slot uses the same pattern: trait in
`kernel::hal::object_store_provider`, impl in `backends::provider`,
boot hook in `nexus-cluster` main.

#### Kernel Boundary — gRPC (not FFI)

Python communicates with the Rust kernel via gRPC over the
`nexus-cluster` process (profile binary at `rust/profiles/cluster/`).
The kernel boundary is a network protocol (gRPC): Python spawns or
connects to `nexus-cluster` and dispatches syscalls via typed RPCs
(`Read`, `Write`, `Delete`, `BatchRead`) and a generic `Call` RPC.

This split lets each peer crate depend on `kernel` (for trait
declarations: `abc::ObjectStore`, `hal::distributed_coordinator::DistributedCoordinator`,
...) while the binary-side dependency `nexus-cluster → {kernel, peers}`
flows in only one direction. `PeerBlobClient` lives in
`lib::transport_primitives` so both raft (server-side handler) and
transport (client-side fetch) can depend on it without depending on
each other.

#### Dependency Direction

```text
                       contracts              (zero deps)
                          ↑
                         lib                  (depends on contracts;
                          ↑                    algorithms + transport_primitives
                          │                    behind opt-in features)
                       kernel                 (depends on contracts + lib;
                          ↑                    declares HAL traits)
              ↑    ↑    ↑    ↑
              │    │    │    │
       backends raft transport services       (peer crates — depend on
              ↑    ↑    ↑    ↑                kernel + lib; transport
              │    │    │    │                additionally depends on raft
              │    │    │    │                for federation proto stubs)
              └────┴────┴────┴── rust/profiles/cluster  (deployment binary sink)
```

Edge invariants:

| Edge                                          | Direction                                      |
|-----------------------------------------------|------------------------------------------------|
| `services` / `backends` / `raft`              | role peers — orthogonal; reach each other via `kernel.sys_*` syscalls |
| `kernel ↔ lib`                                | one-way: `kernel → lib`                        |
| `raft ↔ transport`                            | one-way: `transport → raft` for federation client proto stubs (Postgres-client-references-libpq shape) |
| `kernel → raft`                               | trait-only: kernel reaches raft through `DistributedCoordinator` dispatch |
| `rust/profiles/<name>`                        | sink (deployment binary)                       |

#### RPC: Client Side vs Server Side

The remote-RPC stack lives on the network surface tier `transport/`,
plus raft for the federation server fabric.

| Side   | Crate                       | Module                         | Role                                                                                  |
|--------|-----------------------------|--------------------------------|---------------------------------------------------------------------------------------|
| Server | `transport`                 | `grpc` / `ipc`                 | VFS gRPC server (port 2028) + IPC envelope helpers                                    |
| Server | `raft`                      | `blob_fetcher_handler`       | Federation peer mesh + per-zone routers + blob-fetcher server handler         |
| Client | `transport`                 | `vfs` / `peer_blob` / `federation` | Driver-outgoing clients: VFS gRPC for `RemoteBackend`, peer-blob fetch, federation peer client |
| Shared | `lib::transport_primitives` | (whole module)                 | TLS, connection pool, addressing, TOFU trust store, `PeerBlobClient` trait — consumed by both sides |

`transport/` covers both directions of the network surface (Linux
`net/` analogue: same crate hosts server sockets and outgoing
connection helpers). The `RpcTransport` type sits in the kernel crate
(kernel-internal `RemoteMetaStore` / `RemotePipeBackend` /
`RemoteStreamBackend` wrappers also wrap it directly); `transport::vfs`
re-exports it so out-bound callers name a single canonical path.

### Placement Decision Tree

```
Is it used by a SINGLE layer?
  → Yes: stays in that layer
  → No (multi-layer):
       Is it a type / trait / exception / enum / constant?
         → Yes: contracts/
         → No (function / helper / I/O logic): lib/
```

### Import Rules

`contracts/` and `lib/` may import from: each other, stdlib, third-party crates.
They must **never** import from: `kernel`, `services`, `backends`, `raft`, `transport`.

---

## 8. Communication

Kernel-adjacent services built on kernel primitives (§4.2 IPC, §4.3
FileEvent). Not kernel-owned, but bottom-layer infrastructure.

| Tier | Nexus | Built on | Topology |
|------|-------|----------|----------|
| **Kernel** | DT_PIPE (§4.2) | MemoryPipeBackend — destructive FIFO | Local or distributed (transparent) |
| **Kernel** | DT_STREAM (§4.2) | MemoryStreamBackend — append-only log | Local or distributed (transparent) |
| **System** | gRPC + IPC | PipeManager/StreamManager, consensus proto | Point-to-point |
| **User Space** | EventBus | CacheStore pub/sub + FileEvent (§4.3) | Fan-out (1:N) |

See `docs/federation-architecture.md` for gRPC/consensus details.

### 8.1 NexusVFSService.Call — RPC Dispatch Order

The tonic `Call(method, payload)` handler resolves the method through
two dispatch paths in order:

1. **Rust services** — `Kernel::dispatch_rust_call(service, method, payload)`
   routes to a `RustService::dispatch` impl when the method maps to a
   Rust-flavoured entry in `ServiceRegistry`. Method names follow one
   of two shapes:
   - Dotted: `service.method` (canonical) — split on the first `.`,
     dispatch the bare method on that service.
   - Flat backward-compat: methods with the prefix `acp_` or
     `managed_agent_` route to that service with the full method name
     preserved.
2. **Python `@rpc_expose`** — fallback path when the Rust dispatch
   returns `None` (no Rust service for that name) or `NotFound`
   (service exists but doesn't expose the method). The handler hands
   the original method string to `bridge.dispatch_call`, which runs
   the existing async `dispatch_method` on the FastAPI loop.

Auth is resolved before either dispatch path so admin-only checks
apply uniformly. `RustCallError::InvalidArgument` and `Internal`
short-circuit straight to the wire encoder; no fallback in those
cases.

### 8.2 Registered Rust Services

| Service name | Source | Methods |
|--------------|--------|---------|
| `managed_agent` | `rust/services/src/managed_agent/` (feature `service-managed-agent`) | `start_session_v1`, `cancel_v1`, `get_session_v1` — owns the chat-with-me + workspace-boundary hooks plus the session lifecycle for `AgentKind::Managed`. State writes go to `kernel::core::agents::registry::AgentRegistry` directly. |
| `acp` | `rust/services/src/acp/` (feature `service-acp`) | `acp_call`, `acp_kill`, `acp_list_agents`, `acp_list_processes`, `acp_set_system_prompt`, `acp_get_system_prompt`, `acp_set_enabled_skills`, `acp_get_enabled_skills`, `acp_history` — stateless coding-agent CLI caller via ACP JSON-RPC. The AgentRegistry trait bridge is satisfied by `kernel.agent_registry` (the Rust SSOT itself), so spawn / kill / list calls go straight to `kernel::core::agents::registry::AgentRegistry`. |

Services compose into a profile binary the same way drivers do:
each `service-*` feature gates a `pub mod` line in
`rust/services/src/lib.rs`, and each profile's `Cargo.toml`
declares the features it enables. One dispatch path — no per-service
shortcuts — so audit / permission hooks added to the dispatch path
land in one place.

---

## 9. Cross-References

| Topic | Document |
|-------|----------|
| Syscall table and design rationale | [`docs/syscall-design.md`](docs/syscall-design.md) |
| VFS lock design + advisory locks | [`docs/lock-architecture.md`](docs/lock-architecture.md) §4 |
| Zone model, DT_MOUNT, federation | [`docs/federation-architecture.md`](docs/federation-architecture.md) §5-§6 |
| Raft, gRPC, write flows | [`docs/federation-architecture.md`](docs/federation-architecture.md) §2-§5 |
| Pipe + Stream design rationale | [`docs/federation-architecture.md`](docs/federation-architecture.md) §7j |
| Data type → pillar mapping | [`data-storage-matrix.md`](https://github.com/nexi-lab/nexus/blob/main/docs/architecture/data-storage-matrix.md) (nexus repo) |
| Ops ABC x scenario affinity | [`ops-scenario-matrix.md`](https://github.com/nexi-lab/nexus/blob/main/docs/architecture/ops-scenario-matrix.md) (nexus repo) |
| Backend storage composition (CAS x Backend) | [`backend-architecture.md`](https://github.com/nexi-lab/nexus/blob/main/docs/architecture/backend-architecture.md) (nexus repo) |
| CLI nexus/nexusd split | [`cli-design.md`](https://github.com/nexi-lab/nexus/blob/main/docs/architecture/cli-design.md) (nexus repo) |
