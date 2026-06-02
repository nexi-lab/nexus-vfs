# Syscall Design

**Status:** Implemented. Source of truth for syscall inventory and design rationale.
**See also:** [README](../README.md) §2 for the kernel-level view.

---

## 1. Architecture: Linux kernel + libc Pattern

Two layers, mirroring Linux kernel + glibc:

```
Linux:   Application → libc read()  → syscall(NR_read) → kernel sys_read()
Nexus:   Client      → nx.read()    →                  → NexusFS.sys_read()
                        ↑ Tier 2 (contracts/)               ↑ Tier 1 (core/)
                        No sys_ prefix                       sys_ prefix
                        Composes primitives                  Atomic primitives
```

- **Tier 1 (kernel)**: Abstract `sys_*` methods on `NexusFilesystem`. Implemented by `NexusFS`.
  All POSIX-aligned, path-addressed. No hash-addressing at kernel level.
- **Tier 2 (convenience)**: Concrete methods on `NexusFilesystem`. Compose Tier 1 syscalls.
  Half POSIX VFS-aligned, half HDFS/GFS-aligned (content access via driver).

---

## 2. Kernel Syscall Table

All path-addressed. No hash-addressing (CAS is driver detail, not kernel concern).

### Tier 1 — Abstract Syscalls (11)

| # | Plane | Syscall | Signature | POSIX Ref |
|---|-------|---------|-----------|-----------|
| 1 | Content | `sys_read` | `(path, count=None, offset=0) → bytes` | `pread(2)` |
| 2 | Content | `sys_write` | `(path, buf, count=None, offset=0) → dict` | `write(2)` — file must exist; raises `NexusFileNotFoundError` on non-existent path (creation via `sys_setattr`) |
| 3 | Metadata | `sys_stat` | `(path, include_lock=False) → dict \| None` | `stat(2)` — StatResult includes `owner_id` (posix_uid for DAC); include_lock=True appends advisory lock state (zero cost when False) |
| 4 | Metadata | `sys_setattr` | `(path, **attrs) → dict` | `chmod/chown/utimes` + `mknod`/`creat` — creates DT_REG, DT_DIR, DT_PIPE, DT_STREAM, DT_MOUNT; updates content_id, size, version, created_at_ms, owner_id |
| 5 | Namespace | `sys_unlink` | `(path, recursive=False) → dict` | `unlink(2)` |
| 6 | Namespace | `sys_rename` | `(old, new) → dict` | `rename(2)` |
| 7 | Namespace | `sys_copy` | `(src, dst) → dict` | — (server-side copy, Issue #3329) |
| 8 | Directory | `sys_readdir` | `(path, recursive=True, limit=None) → list` | `readdir(3)` — `/__sys__/locks/` returns active locks (like `/proc/locks`) |
| 9 | Locking | `sys_lock` | `(path, mode, ttl, max_holders, lock_id=None) → str \| None` | `fcntl(F_SETLK)` — acquire (lock_id=None) or extend TTL (lock_id=existing) |
| 10 | Locking | `sys_unlock` | `(path, lock_id=None, force=False) → bool` | `flock(LOCK_UN)` — release by lock_id, or force-release all holders |
| 11 | Watch | `sys_watch` | `(path, timeout, recursive) → dict \| None` | `inotify(7)` |

**Vectored syscall semantics (sys_read, sys_write, sys_unlink):**

- `reqs.len() == 1` → fast path: dispatches to single-item implementation (`sys_read_single`, `sys_write_single`, `sys_unlink_single`) with zero batch overhead.
- `reqs.len() > 1` → batch path: per-item auth + hooks in Phase A, then coalesced I/O in Phase B (sys_read uses rayon parallelism; sys_write uses sorted VFS lock acquisition to avoid deadlocks; sys_unlink loops sequentially).
- Each item in the result `Vec` corresponds positionally to its request. Per-item errors are isolated — one failing path does not abort the batch.
- Single-path callers use `KernelAbi::sys_read/sys_write/sys_unlink` (trait methods) or internal `sys_read_single`/`sys_write_with_link_depth`/`sys_unlink_single` (`pub(crate)`). Tier 2 `read()`/`unlink()` in `KernelConvenience` provide `#[inline]` defaults.
- Every item in the batch goes through the full permission gate individually.

### Tier 2 — Concrete Convenience (not abstract, composing Tier 1)

| Method | Tier | Composes | Notes |
|--------|------|----------|-------|
| `mkdir` | 2 | `sys_setattr(entry_type=DT_DIR)` | Directory create; optimized inherent override on `KernelConvenience` |
| `rmdir` | 2 | `sys_unlink(recursive=)` | Recursive directory delete; optimized inherent override on `KernelConvenience` |
| `access` | 2 | `sys_stat` | Returns `True` if stat succeeds |
| `is_directory` | 2 | `sys_stat` | Checks `is_directory` field |
| `glob` | 2 | `sys_readdir` + `fnmatch` | Pattern matching over directory listing. Python-side composition. |
| `grep` | 2 | `sys_readdir` + `sys_read` + `re` | Content search across files. Python-side composition. |

`sys_setattr` is the universal creation/management syscall:
- `create(path)` = `sys_setattr(path, entry_type=DT_REG)` — upsert: creates regular file if absent, updates metadata if present. Accepts `content_id`, `size`, `version`, `created_at_ms`, `owner_id`.
- `mkdir(path)` = `sys_setattr(path, entry_type=DT_DIR)` (Tier 2)
- `mount` = `sys_setattr(path, entry_type=DT_MOUNT, backend=...)`
- `mkpipe` = `sys_setattr(path, entry_type=DT_PIPE)`
- `mkstream` = `sys_setattr(path, entry_type=DT_STREAM)`
- `/__sys__/` paths = kernel management (service register/unregister)

### What's NOT a kernel syscall

Hash-addressed content operations (`read_content`, `write_content`, `stream`,
`write_stream`) stay on **ObjectStoreABC** (driver level):

- Hash-addressing implies CAS, but not all backends use CAS. Kernel is backend-agnostic.
- Linux doesn't expose `sys_read_block(lba)` — that's the block device driver's concern.
- HDFS separates: ClientProtocol (path-based, NameNode) vs DataTransferProtocol
  (block-based, DataNode). Our ObjectStoreABC = DataNode equivalent.

---

## 3. Convenience Layer (NexusFilesystem Tier 2)

Defined in `contracts/filesystem/filesystem_abc.py` as concrete methods.
NexusFS inherits them — callers use `nx.read(path)` directly.

### VFS Half — POSIX-aligned

| Method | Composes | Behavior |
|--------|----------|----------|
| `read(path, count, offset)` | `sys_stat` + `sys_read` | POSIX pread semantics |
| `write(path, buf, consistency=)` | `sys_setattr` (create) + `sys_write` | Create-if-absent via sys_setattr(DT_REG), then write content |
| `mkdir(path, parents, exist_ok)` | `sys_setattr(entry_type=DT_DIR)` | Directory creation with hooks + events |
| `rmdir(path, recursive)` | `rmdir` | Lenient defaults (recursive=True) |
| `append(path, content)` | `read` + `write` | Shell `>>` semantics |
| `edit(path, edits)` | `read` + transform + `write` | Apply diffs |
| `write_batch(files)` | N × `write()` | Batch file writes |
| `access(path)` | `sys_stat` | Existence check |
| `is_directory(path)` | `sys_stat` | Directory check |
| `lock_acquire(path, mode, ttl)` | `sys_lock` | Dict wrapper for gRPC Call RPC (sys_lock returns raw str) |
| `lock(path, mode, timeout)` | `sys_lock` (retry loop) | Blocking lock (like `fcntl(F_SETLKW)`) |
| `unlock(lock_id, path)` | `sys_unlock` | Release lock |
| `locked(path)` | `lock` + `unlock` | Async context manager |

### HDFS Half — Driver-level content access

| Method | Delegates to | Purpose |
|--------|-------------|---------|
| `read_content(hash)` | `ObjectStoreABC.read_content(hash)` | Direct blob access by hash |
| `write_content(content)` | `ObjectStoreABC.write_content(content)` | Direct blob store, return hash |
| `stream(hash)` | `ObjectStoreABC.stream(hash)` | Streaming blob read |
| `write_stream(path)` | `ObjectStoreABC.write_stream(path)` | Streaming blob write |

---

## 4. Key Design Decisions

### 4.1 sys_read / sys_write: Vectored, Content-only (POSIX preadv/pwritev)

`sys_read` and `sys_write` accept a slice of request structs and return a
`Vec<Result<..., KernelError>>` — one result per request, positionally matched.
Single-item calls (`reqs.len() == 1`) take a zero-overhead fast path that
dispatches directly to the single-item implementation.

`sys_write` is content-only (SRP). Metadata updates are handled by `sys_setattr`
or Tier 2 `write()`. File must exist — `sys_write` to a non-existent path raises
`NexusFileNotFoundError`. Creation goes through `sys_setattr(entry_type=DT_REG)`.
`sys_write` never implicitly creates files — this is a kernel invariant, not a
configurable behavior.

CAS read-modify-write for offset writes is handled internally by the driver.
Kernel does not know whether backend is CAS or path-addressed.

### 4.2 sys_unlink: Unified delete (files + directories)

`sys_unlink` handles both files and directories (with `recursive=` param).
`rmdir` is Tier 2 convenience that delegates to `sys_unlink(recursive=)`.
CAS content is freed when refcount reaches zero.

### 4.3 sys_setattr: Universal creation/management

`sys_setattr` is the Swiss Army knife — creation, attribute updates, and special
inode types all flow through it:

- **Create DT_REG**: `entry_type=DT_REG` creates a regular file (upsert — creates if absent, updates metadata if present). Accepts `content_id`, `size`, `version`, `created_at_ms`, `owner_id` for metadata population at creation time.
- **Create others**: `entry_type=DT_DIR/DT_PIPE/DT_STREAM/DT_MOUNT` creates the inode. DT_PIPE accepts `read_fd`/`write_fd`/`capacity` for stdio-backed pipes — there is no separate pipe-creation syscall
- **Update**: No `entry_type` updates mutable metadata fields (content_id, size, version, created_at_ms, owner_id)
- **Idempotent open**: Same `entry_type` on existing path recovers the buffer (pipes/streams)
- **`/__sys__/`**: Kernel management namespace (service register, config, etc.)

### 4.4 sys_lock / sys_unlock: Advisory locks (POSIX fcntl)

Exposed as kernel syscalls (not service-layer). Two syscalls cover all lock
operations (POSIX `fcntl(F_SETLK)` pattern — same syscall for acquire and extend):

- `sys_lock(path, lock_id=None)` — acquire (lock_id=None) or extend TTL (lock_id=existing)
- `sys_unlock(path, lock_id=None, force=False)` — release by lock_id or force-release all holders

Lock state query via existing syscalls (no dedicated lock-query syscall):
- `sys_stat(path, include_lock=True)` — appends lock info to stat result (zero cost when False)
- `sys_readdir("/__sys__/locks/")` — list all active locks (virtual namespace, like `/proc/locks`)

Tier 2: `lock_acquire()` wraps sys_lock with dict return for gRPC; `lock()`
provides blocking retry (`F_SETLKW`); `locked()` provides async context manager.
See `lock-architecture.md` §3.

### 4.5 sys_copy: Server-side copy (Issue #3329)

Uses backend-native server-side copy when available (GCS, S3), streaming for
cross-backend, read+write as fallback. Holds VFS locks internally — callers
must NOT hold locks when calling `sys_copy`.

### 4.6 sys_watch: File change notification (inotify)

Waits for file changes matching a glob pattern with timeout. Returns `FileEvent`
or `None` on timeout. Backed by `FileWatchRegistry` (`rust/kernel/src/core/file_watch.rs`).

Implementation: `parking_lot::Condvar` per watch + `Mutex<Vec<FileEvent>>` inbox.
Every mutation syscall calls `dispatch_observers` → `notify_match`, waking all
matching watchers. Cost when no watches registered: single `RwLock` read (~50ns).

Available on all kernel surfaces:
- **Rust in-process**: `KernelAbi::sys_watch(pattern, timeout_ms)` — managed-agent
  runtimes use this to replace polling with event-driven blocking on
  `/proc/{pid}/chat-with-me` mailboxes
- **Python**: `KernelClient.sys_watch(pattern, timeout_ms)` — gRPC Call RPC
  to kernel subprocess
- **gRPC/RPC**: `WatchMixin.sys_watch` → `sys_watch` Call RPC

### 4.7 Hash-addressed ops: Driver level, not kernel

```
Kernel:  sys_read(path)        → internal: path → metadata → hash → driver.read_content(hash)
                                  kernel knows path, does not know hash
Driver:  object_store.read_content(hash) → bytes
                                  driver knows hash, does not care about path
```

Federation content replication uses ObjectStoreABC directly (like HDFS DataTransferProtocol
between DataNodes — separate from NameNode API).

---

## 5. POSIX Alignment Summary

| Syscall | Aligned? | Notes |
|---------|----------|-------|
| `sys_stat` | ✅ | dict vs struct stat (Pythonic). StatResult includes `owner_id` for DAC |
| `sys_setattr` | ✅ | Bundles chmod/chown/utimes + mknod/creat (DT_REG, DT_DIR, DT_PIPE, DT_STREAM, DT_MOUNT). Accepts content_id, size, version, created_at_ms, owner_id |
| `sys_readdir` | ✅ | No opendir/closedir (acceptable simplification), supports pagination |
| `sys_rename` | ✅ | — |
| `sys_unlink` | ✅ | Vectored (`&[UnlinkRequest]`), unified delete (files + dirs), metadata-only (CAS GC pattern) |
| `sys_copy` | ✅ | No direct POSIX equivalent; server-side optimization |
| `sys_read` | ✅ | count/offset (pread semantics) |
| `sys_write` | ✅ | count/offset, content-only (SRP). No implicit file creation — path must exist |
| `sys_lock` | ✅ | fcntl(F_SETLK) — acquire + extend (lock_id param) |
| `sys_unlock` | ✅ | flock(LOCK_UN) — release + force (force param) |
| `sys_watch` | ✅ | inotify(7) equivalent |

Tier 2 convenience (not kernel syscalls):
- `access` → Tier 2 (derives from `sys_stat`)
- `is_directory` → Tier 2 (derives from `sys_stat`)
- `mkdir` → Tier 2 (`sys_setattr(entry_type=DT_DIR)`; optimized override on `KernelConvenience`)
- `rmdir` → Tier 2 (`sys_unlink(recursive=)`; optimized override on `KernelConvenience`)
- `get_xattr(path, key)` / `set_xattr(path, key, value)` / `get_xattr_bulk(paths, key)` → Tier 2 (Rust `KernelConvenience` trait, direct metastore — no hooks, no permission gate)
- `glob` → Tier 2 Python (composes `sys_readdir` + `fnmatch`)
- `grep` → Tier 2 Python (composes `sys_readdir` + `sys_read` + `re`)

---

## 6. Verification

```bash
uv run pytest tests/ -x -o "addopts="
uv run mypy src/nexus/contracts/filesystem/ src/nexus/core/nexus_fs.py
uv run ruff check src/
PYTHONPATH=src uv run lint-imports
```

### 6.1 Rust/Python Boundary Status (2026-05-19)

**Post gRPC migration (PR #4163):** The kernel runs as a separate Rust subprocess
(`nexus-cluster`). Python communicates exclusively via gRPC `KernelClient`. All
in-process PyO3 crossings documented in the previous version of this section
have been eliminated:

- **Hook dispatch**: Pure Rust — hooks are Rust middleware/interceptors, no Python callbacks.
- **Service lifecycle**: Python orchestrator manages services independently; no PyO3 crossings.
- **All syscalls**: Zero in-process crossings. Boundary is gRPC (~1ms), not FFI (~1μs).
- **Pillar access** (Metastore, ObjectStore, DCache): Pure Rust trait dispatch within kernel subprocess.

---

## 7. Long-term Architecture: Collapse to RPC Boundary (decided 2026-04-02)

### 7.1 Problem: NexusFilesystem is a redundant boundary

The current kernel boundary (`NexusFilesystem`) is a Python ABC whose
`sys_*` methods mirror the gRPC proto RPC definitions almost 1:1. This
means the ABC is not a real abstraction — it's just the wire protocol's
Python projection. All transport adapters converge on the same methods:

```
gRPC servicer        ──┐
HTTP/FastAPI routers  ──┤
FUSE operations       ──┼──→  NexusFilesystem.sys_read/write/...
Python SDK (nexus-fs)  ──┤
MCP                   ──┘
Future: driver API    ──┘
```

This creates several problems:

| Problem | Root cause |
|---------|-----------|
| Kernel FFI facade exists | Bypassing ABC's Python call overhead |
| `Arc<Inner>` on 5+ structs | Sharing state across FFI boundary |
| GIL safety clone-then-call pattern | Rust calling Python callbacks |
| Dual code paths (Rust fast + Python fallback) | Every feature maintained in two places |
| Hook count sync via `AtomicU64` | Kernel straddles two languages |
| 6 files to touch per new feature | ABC → impl → Kernel → stubs → proto → servicer |

No production storage system puts an internal ABC below its wire protocol:

| System | Kernel boundary |
|--------|----------------|
| Linux | syscall ABI |
| PostgreSQL | wire protocol |
| Redis | RESP protocol |
| CockroachDB | SQL / gRPC |
| etcd | gRPC |

### 7.2 Target: RPC as kernel boundary (transport-agnostic)

The boundary should be at the **RPC abstraction level** — not gRPC
specifically (which mandates HTTP/2 + protobuf + network), but the
procedure call contract itself: "given an operation name + arguments,
return a result." This is the common ancestor of all transports.

```
Transport adapters (thin, many):
┌─────────────────────────┐
│ gRPC    (tonic / grpcio) │──┐
│ HTTP    (axum / FastAPI)  │──┤       ┌───────────────────────────┐
│ FUSE    (fuse3)           │──┼──────→│  Rust kernel (pub fn)      │
│ Driver  (OS syscall hook) │──┤       │  sys_read(ctx, path, ...)  │
│ MCP                       │──┘       │  sys_write(ctx, path, ...) │
└─────────────────────────┘       │  sys_stat(ctx, path, ...)  │
                                      └───────────────────────────┘
                                           │
                                      ┌────┴────┐
                                      │Backends │
                                      │ CAS: pure Rust              │
                                      │ S3/GCS: gRPC adapter         │
                                      └─────────┘
```

Key design decisions:

1. **Kernel = Rust `pub fn`**, not ABC, not trait. One implementation, not
   an interface-with-one-impl pattern.
2. **Transport adapters are thin**: gRPC adapter deserializes → calls
   `kernel::sys_read` → serializes response. ~20 lines per RPC.
3. **Python calls use gRPC** (for `nexus-fs` Python package, unit tests).
   Kernel runs as subprocess; Python communicates via `KernelClient` gRPC.
4. **Hooks/observers** are Rust middleware/interceptors on the kernel
   functions — no cross-language callback dance.
5. **Python backends** are eliminated — all backends are pure Rust or
   route through the Rust gRPC adapter (connectors via gRPC, PR #3843).

### 7.3 What this eliminates

| Artifact | Status after collapse |
|----------|----------------------|
| `NexusFilesystem` (ABC → Protocol) | **Done** — now a Protocol, not ABC (PR 7a) |
| `Kernel` struct | **Done** — owns all core state: DCache, Router, Trie, Hooks, Observers, Metastore (PR 7b) |
| `Arc<Inner>` on 5+ structs | **Done** — all structs are fields of `Kernel` |
| Dispatch (KernelDispatch → DispatchMixin) | **Done** — Rust Kernel owns registries, DispatchMixin provides Python API (PR 7c) |
| Overlay feature | **Deleted** — CAS dedup makes it unnecessary (PR 7, -1354 lines) |
| CDC reassembly | **Done** — chunked_manifest detection + reassembly in Rust CAS engine |
| `stubs/nexus_runtime/__init__.pyi` | **Deleted** — PyO3 stubs removed after gRPC migration (PR #4163) |
| Module rename | **Done** — `nexus_fast` → `nexus_runtime` (PR 8) |
| `_backend_read` elimination | **Done** — all sys_read paths go through Rust kernel; Python `_backend_read` deleted (#1817 PR #3848) |
| `sys_write` metadata in Rust | **Done** — Rust kernel builds metadata after CAS write; Python `_write_internal`/`_build_write_metadata` deleted (#1817 PR #3848) |
| PIPE/STREAM in Rust | **Done** — sys_read/sys_write dispatch to PipeManager/StreamManager in Rust; `pipe_read_nowait`/`pipe_destroy` bypasses deleted (#1817 PR #3852) |
| Advisory lock in Rust | **Done** — `LockManager` in Rust (lock_manager.rs): LocalLocks + DistributedLocks; Python `sys_lock`/`sys_unlock` = thin wrappers |
| Connector via gRPC | **Done** — external/remote backends route through Rust gRPC adapter, not Python ObjectStoreABC (#1960 PR #3843) |

### 7.4 Concrete code shape

```rust
// kernel/io.rs — THE kernel. Not a trait, just functions.
// Vectored: accepts &[ReadRequest], returns Vec<Result<...>>.
// reqs.len() == 1 → fast path; reqs.len() > 1 → batch with rayon.
pub fn sys_read(
    &self,
    reqs: &[ReadRequest],
    ctx: &OperationContext,
) -> Vec<Result<SysReadResult, KernelError>> {
    if reqs.len() == 1 { return vec![self.sys_read_single(...)]; }
    self.sys_read_batch_impl(reqs, ctx)
}

// grpc/vfs_service.rs — thin tonic adapter
async fn read(&self, req: Request<ReadRequest>) -> Result<Response<ReadResponse>> {
    let results = kernel.sys_read(&[req.into()], &ctx);
    Ok(Response::new(results[0].clone()?.into()))
}

// Python: KernelClient (gRPC) — nexus-fs package, tests
// Python calls kernel subprocess via gRPC Call RPC.
// See src/nexus/remote/kernel_client.py
```

One implementation. One thin gRPC binding. Zero ABCs.

### 7.5 Migration path from current state

All work done in Phases A-G is directly reusable:

| Current (Phase G) | Target |
|-------------------|--------|
| `Kernel.sys_read` logic | `kernel::sys_read()` body (identical) |
| `RustPathRouterInner` | `kernel::Router` (struct field, no Arc) |
| `RustDCacheInner` | `kernel::DCache` (struct field, no Arc) |
| `VFSLockManagerInner` | `kernel::VfsLock` (struct field, no Arc) |
| `CASEngine` | `kernel::CasEngine` (unchanged) |
| `read_backend` dispatch | `kernel::backend_dispatch()` (pure Rust) |

Migration phases (incremental, each a PR):

1. **Rust kernel crate**: Extract `kernel/mod.rs` with `pub fn sys_read/write`
   from current `Kernel` logic. Kernel struct becomes the single
   kernel entry point.
2. **gRPC transport adapter**: Kernel subprocess exposes `sys_*` via
   tonic gRPC. Python `KernelClient` calls via gRPC (PR #4163).
3. **Delete NexusFilesystem**: Move Tier 2 methods to a standalone
   Python module that calls kernel via gRPC `KernelClient`.
4. **Delete PyO3 kernel bindings**: Remove cdylib crate, codegen,
   stubs — all kernel access goes through gRPC (PR #4163).

### 7.6 Relationship to current plan phases

| Phase | Status | Relationship to §7 |
|-------|--------|-------------------|
| A-G | Done | Logic **reused verbatim** in `Kernel.sys_read/write` |
| H (all Tier 1 syscalls) | Done | `sys_stat` + plan methods in Kernel |
| I (io_uring) | **Deferred indefinitely** | ~1-2μs per syscall (negligible). Rust-native async covers batch workloads. |
| §7 PR 7a (ABC → Protocol) | Done | `NexusFilesystemABC(ABC)` → `NexusFilesystem(Protocol)`, 28 files |
| §7 PR 7b (Metastore adapter) | Done | `PyMetastoreAdapter` in Rust, `set_metastore()`, dcache-miss fallback |
| §7 PR 7c (Dispatch collapse) | Done | `_resolve_and_read` deleted, `_read_via_dlc` → `_backend_read`, `KernelDispatch` → `DispatchMixin` |
| §7 PR 7d (Crate rename) | Done | `rust/nexus_pyo3` → `rust/nexus_runtime` |
| §7 PR 7e (Dispatch traits) | Done | `InterceptHook`/`PathResolver`/`MutationObserver` Rust traits (pure Rust) |
| §7 PR 7f (CDC Rust) | Done | CDC chunked_manifest detection + reassembly in Rust CAS engine |
| §7 PR 7g (Overlay deleted) | Done | Overlay feature deleted (-1354 lines), CAS dedup replaces it |
| §7 PR 8 (Codegen) | Done | Codegen deleted — kernel access via gRPC, no stubs needed (PR #4163) |
| §7 PR 8 (Module rename) | Done | `nexus_fast` → `nexus_runtime` (Python module name, 90+ files) |
| **§7 remaining** | **Done** | `_backend_read` deleted, sys_write metadata moved to Rust, PIPE/STREAM dispatched in Rust, advisory locks in Rust, connectors via gRPC — all completed in #1817/#1960 |

The key insight: **Phase H is the last phase that adds logic.** The §7
collapse is a **refactoring** that changes the boundary, not the logic.

---

## 8. Version History

| Version | Date | Changes |
|---------|------|---------|
| §1–§7 | 2026-03 | Initial syscall design, POSIX alignment, convenience layer, key decisions, collapse plan |
| §8 | 2026-04-10 | Added version history table |
| §11 | 2026-04-10 | [README](../README.md) §2.4.1: formal 4 dispatch contracts (RESOLVE, INTERCEPT PRE, INTERCEPT POST, OBSERVE) with ordering, error semantics, and zero-overhead invariant. Phase 18 docs. |
| §7.3, §7.6 | 2026-04-23 | §7 collapse roadmap fully completed: `_backend_read` deleted, sys_write metadata in Rust, PIPE/STREAM dispatched in Rust, advisory locks in Rust, connectors via gRPC. All "Remaining" items → Done (#1817, #1960). |
| §6.1 | 2026-04-26 | Rust/Python boundary status: hook dispatch (2+N crossings), service lifecycle (4 crossings, stdlib-only), zero-crossing syscalls, pure Rust pillar dispatch. Eliminated: sys_write IPC pre-check (redundant metadata.get), sys_stat py.import("datetime") → chrono. |
| §2, §4, §5 | 2026-05-07 | sys_setattr: DT_REG create (upsert) + content_id/size/version/created_at_ms/owner_id params. sys_stat: owner_id in StatResult. sys_write: file-must-exist contract. glob/grep: Tier 2 convenience (search-tier, PR #3921). Tier 1 surface: 8 syscalls (read, write, stat, setattr, unlink, rename, copy, readdir). |
| §5 | 2026-05-15 | Delete `/__xattr__/` path intercept from sys_read/sys_write — redundant with Tier 2 `get_xattr`/`set_xattr` (KernelConvenience). Document xattr as Tier 2 convenience. |
| §2, §5 | 2026-05-15 | glob/grep: Python Tier 2 (compose readdir + sys_read). Single-path convenience: Tier 2 `read()`/`unlink()` in KernelConvenience; internal callers use `sys_read_single`/`sys_write_with_link_depth`/`sys_unlink_single`. |
| §2, §4 | 2026-05-20 | mkdir/rmdir reclassified as Tier 2 `KernelConvenience` (removed from the Tier 1 `KernelAbi` surface — both express in terms of existing Tier 1s). `setattr_pipe` folded into `sys_setattr(DT_PIPE)`: DT_PIPE creation now has a single entry point. |
