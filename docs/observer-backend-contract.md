# Observer Backend Contract

**Status**: Design proposal — 2026-07-09
**Owner**: kernel team
**Reviews**: pending

## 1. Problem

Today the kernel treats `LocalConnector` as a passive **content passthrough**: files
live on the host filesystem, `sys_read` fetches bytes from the backend, and the
metastore learns about files only via lazy observation. This creates a
patch chain that grows every time a corner case surfaces:

```
[root cause] cc-tasks-share design: CC writes tasks to ~/.claude/tasks/
             directly via raw fs write, bypassing sys_write.
             LocalConnector has content, metastore has no metadata row.

[patch #1]   observe_backend_readdir_entry (2026-07-01)
             sys_readdir proposes a metadata row for every backend-only
             entry it enumerates. Bootstraps cross-peer visibility, but
             only fires when someone calls readdir.

[patch #2]   fan_out in sys_read
             When metastore misses AND no last_writer_address is known,
             sys_read dials every peer's BlobFetcher. First peer to hit
             its own backend materialises metadata via observe_backend_content.

[patch #3]   RemoteFetch event dispatch on fan_out (nexus-vfs #131)
             fan_out originally didn't fire the RemoteFetch observability
             event, leaving transport-observer blind on cold-first reads.
             (Reverted 2026-07-09 as the first step in this cleanup — see #132.)
```

Every patch is individually well-tested and defensible. The chain as a
whole is the technical debt of a single design choice: **"backend has
content, but its arrival is invisible to the kernel until a subsequent
kernel operation stumbles on it."**

## 2. Goal

Replace the lazy-observation chain with an explicit contract: **the
backend actively syncs its authoritative file listing into the
metastore**. When the contract holds, `sys_readdir` and `sys_read` can
trust the metastore as source of truth for existence — no
lazy-observation, no fan-out safety net.

The contract must be robust against:

1. **Cold start** — files that existed before the backend was mounted.
2. **Watcher event drops** — OS-level notification queues (inotify,
   FSEvents, ReadDirectoryChangesW) are best-effort, not guaranteed.
3. **Daemon restart** — writes that happened while nexus was down.
4. **Rapid write bursts** — coalescing / overflow in the OS event stream.

## 3. Contract

### 3.1 A kernel-side mechanism, NOT a backend trait

> **Design correction (learned from a live test).** An earlier draft
> modelled this as an `ObserverBackend` trait with an
> `ObjectStore::as_observer()` downcast. That is **wrong for the
> production deployment**: `local-connector` is loaded as a **dylib
> plugin**, so the kernel sees it as an opaque `DylibObjectStore`, and a
> concrete-type downcast (`as_observer`) cannot cross the dylib C-ABI
> boundary — it returns `None`, and the sync never arms. The mechanism
> is instead a **kernel-side generic reconcile** that only calls
> `ObjectStore::list_dir` + `stat` (which DO cross the C-ABI), so it works
> uniformly for dylib and built-in backends. It lives in
> `kernel/src/core/metadata_sync.rs` — a §4 kernel primitive, not an
> `abc/` or `extensions/` trait.

The pieces:

```rust
// kernel/src/core/metadata_sync.rs

/// Kernel-side channel a reconcile pass proposes metadata rows through
/// (idempotent get-check-then-propose via the SetMetadata command path).
pub struct MetadataSink { /* Weak<Kernel> + zone + mount_prefix */ }

/// RAII guard; Drop stops the reconcile thread (dropped by the DLC on unmount).
pub(crate) struct MetadataSyncHandle { /* opaque */ }

/// Generic walk over ANY backend — the same code drives a built-in
/// backend and a C-ABI-forwarded DylibObjectStore.
fn collect_backend_listing(backend: &dyn ObjectStore) -> Vec<(path, kind, size)>;

/// Run the initial walk synchronously, then spawn the periodic reconcile.
pub(crate) fn arm(backend: Arc<dyn ObjectStore>, sink: MetadataSink) -> MetadataSyncHandle;
```

Arming is an explicit per-mount opt-in — `Kernel::arm_metadata_sync(mount_point, zone)`
(takes `&Arc<Kernel>` so the reconcile thread gets a weak self-ref) — called by
the boot path after mounting a passthrough connector. Every non-armed mount runs
none of this code.

### 3.2 The reconcile's layers

The kernel-side reconcile provides **three layers**:

**Layer 1: Initial walk (correctness on mount)**

On `install_observer`, synchronously walk the backend's authoritative
storage and propose a metadata row for every entry. Runs to completion
before the mount is considered ready. Closes the "pre-existing files"
gap.

**Layer 2: Real-time watcher (latency)**

Spawn an OS-native filesystem watcher on the backend root. For each
watched event (Create / Modify / Remove / Rename), propose the
corresponding metadata update through the sink. Sub-second propagation
in steady state.

**Layer 3: Periodic reconciler (robustness — the safety net)**

Spawn a background task that, every `reconcile_interval` (default
5 min), re-runs the walker and proposes any entries the sink hasn't
already seen. This covers:

- Watcher event queue overflow (inotify `IN_Q_OVERFLOW`, FSEvents
  coalescing, RDCW buffer exhaustion under heavy write bursts).
- Watcher restart gaps (daemon restart, backend re-init).
- Any class of missed event we don't yet know about.

The reconciler makes the contract **self-verifying**: correctness does
not depend on OS event delivery. The watcher is a latency optimisation,
not a correctness mechanism.

### 3.3 MVP scope: additive-only reconciliation

For the initial implementation, both the walker and the reconciler
**only propose new metadata**. Deletion (files present in metastore but
absent from backend) is handled purely by the watcher.

Rationale: a transient backend miss (e.g. temporary NFS mount hiccup,
symlink target unavailable) must not trigger metadata delete. Deletion
reconciliation requires N-consecutive-miss confirmation semantics that
add design complexity without any known correctness gap for
cc-tasks-share. Deferred to a follow-up if a real need surfaces.

Consequence: a watcher-missed DELETE leaves a stale metastore row.
Subsequent `sys_read` on the stale path returns a natural `ENOENT` from
the backend — no data loss, only a visible "ghost" entry until the
watcher catches up.

### 3.4 Kernel changes

No branching in the kernel router — the lazy-observation chain is
deleted outright (commit 4). After the cut over:

- `sys_readdir` returns metastore entries directly. No
  `observe_backend_readdir_entry` side effect.
- `sys_read` on a metastore miss returns `ENOENT`. No `fan_out` safety
  net.
- Backends are responsible for keeping the metastore populated. `ObserverBackend`
  implementors do it via the three-layer sync described in § 3.2; content-owning
  backends (S3, CAS, PathLocal) do it via the existing `sys_write` path at
  content-arrival time. Both patterns publish metadata BEFORE the reader
  arrives, so no lazy fallback is needed.

## 4. LocalConnector implementation sketch

`local_connector.rs` grows an `ObserverBackend` impl:

```rust
impl ObserverBackend for LocalConnectorBackend {
    fn install_observer(
        &self,
        sink: ObservationSink,
    ) -> Result<ObservationHandle, ObservationError> {
        // Layer 1: initial walk (blocks until complete)
        for entry in walkdir::WalkDir::new(&self.root_path) {
            let entry = entry.map_err(ObservationError::Walk)?;
            let virt_path = self.physical_to_virtual(entry.path())?;
            let stat = entry.metadata().map_err(ObservationError::Stat)?;
            sink.propose(&virt_path, kind_of(&stat), stat.len(), None);
        }

        // Layer 2 + 3: watcher and reconciler on shared shutdown token
        let shutdown = ShutdownToken::new();
        let watcher = spawn_watcher(&self.root_path, sink.clone(), shutdown.clone())?;
        let reconciler = spawn_reconciler(
            self.clone(),
            sink,
            Duration::from_secs(300),
            shutdown.clone(),
        );

        Ok(ObservationHandle::new(shutdown, watcher, reconciler))
    }
}
```

Dependencies:
- `notify` crate (cross-platform inotify / FSEvents / ReadDirectoryChangesW).
  New dep on `nexus-vfs/rust/backends/`.
- `walkdir` crate (recursive walk with symlink policy). Already a
  transitive dep — confirm before writing the PR.

Threading:
- One dedicated OS thread per mount for the watcher event loop (owned
  by `notify`).
- One tokio task per mount for the reconciler loop (interval-driven).
- `ObservationHandle::drop` sends shutdown, joins both.

Symlink policy: honours the existing `follow_symlinks` field. Walker
and watcher both respect it uniformly (no divergence between initial
walk and steady-state watcher).

## 5. Migration plan

**No external users of LocalConnector today** — its only live consumer
is cc-tasks-share, developed and operated by the same team writing this
contract. That means we don't owe anyone a gradual migration, a
deprecation cycle, or dual-path compatibility. We cut over: the new
contract goes in and the old lazy-observation chain comes out in the
same PR. Nothing outside this repo depends on the old behaviour.

**One PR, four granular commits**, dependency-ordered. Per
`feedback_single_pr_many_commits`, big multi-phase efforts stay on one
PR so the whole contract change lands atomically. Per
`feedback_small_commits_per_concern`, each commit is a
self-explanatory rollback checkpoint.

**Commit 1**: `revert(#131): remove fan_out RemoteFetch event dispatch`
- Small clean checkpoint. The fan-out path itself is removed in
  commit 4.

**Commit 2**: `docs(architecture): observer-backend-contract design`
- This document. Merged early in the PR history so reviewers see the
  intent before the implementation.

**Commit 3**: `feat(kernel): ObserverBackend trait + ObservationSink/Handle`
- `kernel/src/extensions/observer_backend.rs` — trait + sink + handle + error
  type.
- `ObservationSink` implementation wraps the kernel's `SetMetadata`
  command dispatch. Idempotency via `metastore_get` before propose.
- Unit tests: sink dedupes duplicate proposes; handle Drop shuts down
  cleanly.
- No behavioural change yet — no backend implements the trait.

**Commit 4**: `feat: LocalConnector cut over to ObserverBackend, delete lazy-observation chain`
- Add `walkdir` (if not already transitive) + `notify` to
  `backends/Cargo.toml`.
- `LocalConnectorBackend` implements `ObserverBackend` with initial
  walk + watcher + reconciler.
- `DriverLifecycleCoordinator` calls `install_observer` on mount;
  stores handle for unmount cleanup.
- Kernel router `sys_readdir` and `sys_read` no longer branch on
  observation — metastore is trusted as SSOT for existence.
- Delete `observe_backend_readdir_entry` and its four unit tests.
- Delete `fan_out` from `sys_read` and any residual dead-code paths.
- `try_remote_fetch` stays — it's the deterministic
  last-writer-address routing path, unaffected.
- Docker-based E2E (§ 6) gates PR merge on this commit's final state.

Everything after this commit is the new contract; nothing straddles
old and new. Reviewers can walk commit-by-commit or read the final
diff; both tell the same story.

## 6. Validation strategy

Per `feedback_e2e_acceptance_criteria`: real E2E via Docker Desktop for
infra, tests-in-CI to protect against regression, following the
`integration-test-generator` scenario standard (3+ steps, real user
problem, strong causal chain, meaningful assertions, isolated test
data).

### 6.1 Environment

Two-node Docker Compose federation (existing scaffolding under
`nexus-vfs/tests/federation-e2e/`, extend or add compose file):

- Node A: nexusd with `LocalConnector` mounted at `/tasks` over
  `./local-tasks-a`.
- Node B: nexusd with `LocalConnector` mounted at `/tasks` over
  `./local-tasks-b`.
- Both nodes joined into one zone; peer-shared merged view live (same
  substrate as cc-tasks-share L3).

### 6.2 Scenarios

**Scenario S1: cold-start visibility**

Real user problem: node restart must not hide files the user wrote
during downtime.

1. **Step 1** — Node A daemon down. Write 5 JSON files directly to
   `./local-tasks-a/{a,b,c,d,e}.json`. Files carry distinct known
   content (`{"marker": "<id>"}`).
2. **Step 2** — Start Node A daemon. Backend mount triggers initial
   walk; all 5 rows propose to metastore and replicate to Node B.
   **Assert**: Node B's `list_directory("/tasks")` returns exactly
   `{a,b,c,d,e}.json` within `T <= 5s`.
3. **Step 3** — Node B `sys_read("/tasks/c.json")` succeeds. **Assert**:
   returned bytes match the known content written in Step 1
   (byte-exact, not just non-empty).

Data flow: Step 1 output (files on disk) is what Step 2's initial walk
consumes; Step 2 output (replicated metadata) is what Step 3's
metastore route consumes.

**Scenario S2: watcher-recovery via reconciler**

Real user problem: OS watcher misses events under load; nexus must
recover without operator intervention.

1. **Step 1** — Both nodes up. Node A pauses the watcher thread (test
   hook: `LocalConnectorBackend::pause_watcher_for_test`). Write 3
   files `./local-tasks-a/burst-{1,2,3}.json` while paused.
2. **Step 2** — Confirm Node B's `list_directory` does NOT see the
   files (watcher paused, reconciler not yet ticked). **Assert**:
   entries `{burst-1, burst-2, burst-3}` absent within a bounded poll
   window (e.g. 2s).
3. **Step 3** — Force reconciler tick (test hook:
   `LocalConnectorBackend::force_reconcile_for_test`). **Assert**:
   Node B's `list_directory` now includes all 3 burst files, and
   `sys_read("/tasks/burst-2.json")` returns byte-exact content
   written in Step 1.

Data flow: Step 1's paused-watcher state directly causes Step 2's
absence assertion (the paused state IS the setup for the negative);
Step 3's forced reconcile is what makes the assertion in Step 3 true.

**Scenario S3: peer read routes via metastore (no fan-out)**

Real user problem: cross-node reads should not depend on the deleted
fan-out safety net.

1. **Step 1** — Node A writes `./local-tasks-a/routed.json`. Wait for
   watcher to propose row. **Assert**: metastore replicated to Node B
   with `last_writer_address = <Node A>`.
2. **Step 2** — Node B `sys_read("/tasks/routed.json")` succeeds.
   **Assert**: returned bytes match Step 1.
3. **Step 3** — Verify the read went through `try_remote_fetch`
   (deterministic routing), NOT through fan-out. **Assert**: emitted
   `RemoteFetch` event has `remote_addr = <Node A>`, and the deleted
   `fan_out` code path was not exercised (statically absent — build
   fails if it exists post-PR-4).

Data flow: Step 1's `last_writer_address` metadata IS the input Step 2's
router keys off; Step 3's assertion pins the routing path.

### 6.3 CI wire-up

Scenarios encoded as `rust/tests/observer-backend-e2e.rs` (integration
test crate) with `docker-compose` scaffolding under
`tests/federation-e2e/observer-backend/`. Runs in the existing
`federation-e2e` CI job (nexus-vfs `.github/workflows/`); job gates
merge for PRs 3 and 4.

### 6.4 Local live-test runbook

Before each PR is pushed for review, run on Windows dev box:

```bash
cd ~/cursor-projects/nexus-vfs
docker compose -f tests/federation-e2e/observer-backend/compose.yml up -d
cargo test -p tests --test observer-backend-e2e -- --test-threads=1 --nocapture
docker compose -f tests/federation-e2e/observer-backend/compose.yml down
```

Passing locally is a hard precondition for pushing the branch. This
matches `feedback_no_flaky_local` — local Docker E2E failures are real
bugs, not timing flakes.

## 7. Non-goals

- **Not** changing the `ObjectStore` trait shape. `ObserverBackend`
  extends it via marker + method; existing backends are unaffected.
- **Not** applying observation to backends that already publish metadata
  through `sys_write` (S3, CAS, PathLocal, etc.). Those aren't the
  problem this contract solves.
- **Not** cross-backend generalisation of the fan-out pattern. The
  pattern goes away with this contract — no future backend should need
  it.
- **Not** delete-reconciliation (see § 3.3 — MVP scope).
- **Not** changing the raft `SetMetadata` command shape. Sink uses the
  existing command path.

## 8. Open questions

1. **Reconciler interval default** — 5 minutes proposed. Under what
   workload profile does this need to be tunable? Add mount option now,
   or defer until a real need surfaces?
2. **Large mount cost** — cc-tasks-share's `~/.claude/tasks/` is tens of
   files; initial walk is trivial. If LocalConnector is ever mounted on
   `$HOME` (millions of files), initial walk becomes prohibitive at
   mount time. Async background walk (mount ready before walk
   completes, with a "warming up" flag)? Or make it a mount option?
3. **notify crate on Windows** — RDCW is generally reliable but has a
   known 64 KB event buffer limit. Confirm behaviour under heavy write
   burst; may need to tune buffer size at watcher setup.
