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

### 3.2 The reconcile's triggers

The kernel-side mechanism keeps the metastore coherent with the backend
through **three triggers**, all funnelling into the one idempotent
propose atom (`Kernel::observe_backend_entry`, which never clobbers an
existing row — the existing row is SSOT for `last_writer_address`
routing). Each trigger enumerates the backend the cheapest way for it:

**Trigger 1: Initial walk (correctness on mount)**

On `arm`, synchronously walk the backend's authoritative storage and
propose a metadata row for every entry. Runs to completion before the
mount serves peers. Closes the "pre-existing files" gap.

**Trigger 2: On-access seed (latency)**

When a `sys_readdir` on an armed mount surfaces a backend child the
metastore does not yet carry, that child is seeded synchronously in the
same call — so the row (and its `last_writer`) exists at once, with no
reconcile-interval wait. This is the low-latency path, analogous to an
NFS client's `d_revalidate` on lookup. It reuses the backend listing
`sys_readdir` already fetched for the result union, so it adds a `stat`
only for genuinely-new entries; already-seeded children cost a single
map lookup.

**Trigger 3: Periodic reconcile (robustness — the safety net)**

A background thread re-runs the walk every `RECONCILE_INTERVAL` (default
5s) and proposes any entries not yet seen. This catches content nothing
has listed yet (which the on-access seed alone would miss until someone
reads it) and any class of missed out-of-band change. It makes the
contract **self-verifying**: correctness never depends on a readdir
happening.

> A sub-second OS-native filesystem watcher (inotify / FSEvents /
> ReadDirectoryChangesW via the `notify` crate) remains a deferred latency
> optimisation. The on-access seed already covers the common
> "read-what-just-appeared" path and the periodic reconcile is the
> correctness floor, so the watcher is not required for the contract to
> hold.

### 3.3 Scope: additive-only reconciliation

All three triggers **only propose new metadata**. Deletion (files present
in the metastore but absent from the backend) is out of scope.

Rationale: a transient backend miss (e.g. temporary NFS mount hiccup,
symlink target unavailable) must not trigger a metadata delete. Deletion
reconciliation requires N-consecutive-miss confirmation semantics that
add design complexity without any known correctness gap for
cc-tasks-share. Deferred to a follow-up if a real need surfaces.

Consequence: a file removed out-of-band leaves a stale metastore row.
A subsequent `sys_read` on the stale path routes to the backend and
returns a natural `ENOENT` — no data loss, only a visible "ghost" entry
until the row is cleared through the normal `sys_unlink` path.

### 3.4 Kernel changes

The lazy read-miss `fan_out` and peer-probe chains are deleted outright
(commit 4). After the cut over:

- `sys_readdir` serves entries from the metastore, unioned with the local
  backend listing for read-your-writes. On an armed mount that union also
  seeds freshly-discovered out-of-band entries (Trigger 2 above) via the
  shared `observe_backend_entry` atom — a principled, opt-in-gated seed,
  not the deleted lazy peer-probe.
- `sys_read` on a metastore miss returns `ENOENT`. No `fan_out` safety
  net.
- The metastore is kept populated ahead of readers. Out-of-band backends
  (LocalConnector) are covered by the three triggers in § 3.2; content-owning
  backends (S3, CAS, PathLocal) publish metadata via the existing `sys_write`
  path at content-arrival time. Both publish BEFORE the reader arrives, so no
  lazy fallback is needed.

## 4. Implementation

The mechanism is **kernel-side and generic** — not a backend trait. The
kernel walks any `&dyn ObjectStore` via `list_dir` + `stat` (which cross the
dylib C-ABI, unlike an `as_*()` downcast) and proposes rows through the one
idempotent atom `Kernel::observe_backend_entry`. LocalConnector implements no
observer trait; it is an ordinary `ObjectStore`.

- **Primitive (SSOT):** `rust/kernel/src/core/metadata_sync.rs` — the
  `MetadataSink`, the recursive `collect_backend_listing` walk, `arm` (initial
  walk + periodic reconcile thread), and the `MetadataSyncHandle` RAII guard.
- **Atom:** `Kernel::observe_backend_entry` (`rust/kernel/src/kernel/mod.rs`) —
  builds the row, stamps `last_writer_address`, proposes, idempotent.
- **On-access seed:** `Kernel::sys_readdir` (`rust/kernel/src/kernel/io.rs`),
  gated on `DriverLifecycleCoordinator::is_sync_armed`.
- **Opt-in + lifetime:** `Kernel::arm_metadata_sync` arms a mount; the DLC
  holds the handle and drops it on unmount.
- **Architecture context + coherence taxonomy:** `KERNEL-ARCHITECTURE.md` §4.5.

Symlink policy honours the backend's own `follow_symlinks` behaviour — the
walk consults `list_dir`/`stat`, so there is no separate walker to diverge.

## 5. Status

Landed. LocalConnector cut over to the kernel-side `metadata_sync` primitive;
the lazy read-miss `fan_out` and the `observe_backend_readdir_entry`
peer-probe chains were deleted. `try_remote_fetch` stays — it is the
deterministic last-writer-address routing path, unaffected. The on-access
seed (§3.2 Trigger 2) restored synchronous per-readdir materialisation after
the initial cutover moved it to the async reconcile, so a peer sees
out-of-band content with `last_writer` stamped in one hop. Docker-based E2E
(§6) guards the behaviour.

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
