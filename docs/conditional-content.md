# Conditional visible-content writes (N2 design review)

Status: implementation proposal, not a supported server capability yet.
Source reviewed: main `044a37393`.

## Contract

A new typed `WriteIfVersion` RPC is required. Adding an optional precondition to
`WriteRequest` would let an older server ignore it and perform an unconditional
write. An older server must instead return UNIMPLEMENTED, mapped by consumers to
Unsupported without a write fallback.

The operation replaces one regular file's complete contents. Its precondition is
either absence or the opaque version returned with a prior content snapshot.
The result is Committed(new version) or Conflict(current version, absent when
missing). Conflict changes no visible bytes or metadata. Transport failure or
any error after possible proposal submission is Unknown, resolved by reading the
consumer's persisted fence; it is not evidence that no commit happened.

Use a distinct `ReadVersioned` capability so an older server or an unsupported
storage backend cannot accidentally provide an incoherent bytes/generation pair.
Each successful read must select metadata once and return exactly the immutable
object named by that metadata. A lagging replica may return an older coherent
snapshot: the subsequent comparison is linearized by the zone leader.

Tokens bind the routed zone and the committed generation. Consumers treat them
as opaque. The generation allocator is persisted in the existing zone database
and advanced atomically with file metadata. Deleting a path must not delete the
allocator; recreating it cannot reuse a token. Ordinary writes and metadata
mutations must invalidate the old token too. Zone replacement/restore is an
administrative lifecycle boundary and must not silently retain an old instance's
token namespace; the exact existing zone-incarnation source still needs checking.

Streams, pipes, links, native-reference/connector storage, partial writes and
backends without the necessary guarantees return Unsupported. Authorization and
native write hooks use the same kernel seam as Write. There is no lock-based,
read-then-put, or metadata-only approximation.

## Storage boundary found in current source

`kernel/syscall_impl.rs` writes ObjectStore bytes before committing metadata.
`MetaStore::put_if_version` has a non-atomic default, and its u32 metadata version
is not a content token. The existing Raft CasSetMetadata compares metadata only.
None of those is the requested primitive.

CasLocalBackend already provides immutable content staging. For that backend,
stage and fsync the immutable object, then conditionally publish its pointer and
generation in one existing zone-Raft/redb transaction. An unsuccessful comparison
may leave an unreachable staged object, never changed visible content. Keep the
existing CAS retention/GC ownership; do not delete an object that a concurrent
reader or another file can still reference.

PathLocalBackend instead truncates a live path. The cluster currently uses it
for both the root mount and federation cache. It cannot truthfully implement the
same conditional operation by wrapping its metadata commit. Returning Unsupported
on this backend is a necessary capability boundary, not completion of S6 for the
current deployed mailbox paths.

The preferred next review is to reuse existing CAS storage for Nexus-managed
federated data, keeping native workspace/reference mounts on their existing
backend. This avoids inventing another issuer, store, daemon, or a special mailbox
storage engine. It requires an explicit migration and operational acceptance for
the current PAS-backed state; no running node is retargeted by this proposal.
An alternative backend primitive is acceptable only if it demonstrates the same
visible-content and crash guarantees without a second source of truth.

### First admission is a separate consistency boundary

The original isolated real-redb prototype added two internal commands at the bincode enum
tail and keeps an incarnation/counter and per-path revisions in the existing
zone control-state tree. Ordinary SC replacements and deletes update the revision
in their existing transaction. Six checks pass (conflict immutability,
unconditional replacement, delete/recreate, restart/snapshot, post-admission EC
rejection and deterministic replay).

The seventh check deliberately fails: two replicas receive the same SC file,
one then receives a different EC image, and both apply the same first versioned
read. Allocating a version against each replica's current image gives the SAME
token to DIFFERENT metadata. Rejecting EC only after per-path admission does not
fix this pre-existing divergence. A compare against replica-local bytes would
also make apply decisions differ between replicas, so it is not a valid repair.

That prototype is not an exposed RPC or a supported capability. Do not ship it
or claim its six passing checks close N2. Admission must establish an
authoritative SC image through the existing consensus/store boundary, protect
concurrent ordinary writes, and handle legacy/PAS state explicitly. A local
creation-epoch file is not a replicated incarnation; a comment saying "SC only"
does not enforce it. Candidate designs still need a concrete source-level review
against this counterexample before selecting the public token contract.

Evidence: `n2-metadata.test.stdout`, `n2-metadata.test.stderr` and
`n2-metadata.receipt.json` in the Windows task artifact directory. Current result:
6 passed, 1 failed, no ignored tests. Both initial compilation errors and the
package-selector failure are retained separately. No production node, actor,
identity, certificate, cursor or storage backend was changed.

### Revised foundation: create the first image through SC

The current source experiment removes read-side admission entirely. It reserves
the internal metadata subtree `/__managed_content_v1__` as a candidate key-only
policy. The predicate includes exactly that root and its slash-delimited children;
it never reads a revision, local cache, wall clock or applied index. This is not a
published mount contract and no public RPC or running node uses this subtree.

The EC origin rejects a matching command before appending it to the EC WAL. Both
peer ingress and the state-machine defensive boundary skip a matching old EC
entry and return success so its sequence can advance; anti-entropy does not send
the subtree. The same boundary protects the conditional allocator's control
namespace. Rejected-entry logs exclude command payloads. Unrelated EC paths keep
their current behavior.

Only an absent, eligible key can get its first revision, through
`WriteVersionedMetadata` carrying the explicit first image. The image and revision
are committed in the existing redb/Raft transaction. A read is a single existing
database snapshot and never proposes a command, allocates a revision or imports
an existing image. An occupied unversioned key returns Unsupported to the future
file seam, even if replicas happen to agree on its bytes. Generic control writes
cannot overwrite/delete this allocator. Metadata counters cannot replace a
managed file image. Ordinary SC Set/CAS/Delete update a tracked revision in their
existing transaction; a rejected CAS does not advance it.

The original red source and failure logs are preserved, including the then
untracked module, in `n2-first-admission-red-prototype/manifest.json`. The revised
tests retain the divergent legacy-image counterexample and require refusal on
both replicas, with no revision allocation. A second test exercises a follower
receiving a future EC image before its first SC create: it ACKs without applying
that image and later applies the explicit SC create unchanged.

This foundation still does not complete N2. Before exposing any file capability:

- Every voter and learner must implement the policy and the command encoding.
  Activation and membership admission must enforce that fact; a comment or an
  operator's version-string assertion is insufficient. Mixed old/new operation
  cannot provide this guarantee.
- A new managed mount must use the existing immutable CAS backend and translate
  to the reserved metadata subtree consistently across aliases and nodes. PAS
  and native-reference mounts remain Unsupported. No running mount is retargeted.
- The existing zone lifecycle must supply a replicated incarnation boundary and
  prevent token reuse after an administrative restore/replacement. The proposed
  16-byte incarnation in the first SC create is only an isolated allocator seed.
- Legacy migration must inventory regular files, links, streams and their route
  ownership, verify original bytes and durable values, quiesce their writers,
  then create the new authoritative images through native SC operations. It must
  preserve stream positions and identities, rather than silently resetting or
  editing reader cursors. Existing-key in-place read-enrolment is excluded.
- Kernel authorization/hooks, cache invalidation, exact immutable blob fetching,
  typed public RPCs, client Unknown handling and real learner acceptance remain
  separate required steps. Metadata tests alone certify none of them.

The remote read boundary also matters: current `try_remote_fetch` asks a peer for
the current path and then attaches the caller's earlier metadata generation.
That is not a versioned snapshot. The conditional capability must fetch the exact
immutable object through the existing hash/chunk transport, or fail. It must not
fall through to a current-path fetch with an old generation.

## Delivery slices and required evidence

1. Freeze the public RPC/token contract with the S6 consumer, including the zone
   incarnation and definite-error/Unknown rules. Default trait capability is
   Unsupported; no mock advertises stronger behavior than its real backend.
2. Implement the existing-store transaction and generation lifetime. Ensure all
   ordinary metadata/content writers invalidate tokens, apply observers invalidate
   derived caches, and snapshots/restart preserve the allocator.
3. Wire kernel, transport and client. Reads use exact immutable content. Keep PAS
   and other unsupported backends fail-closed and verify that nothing visible is
   modified on those paths.
4. Exercise two real nodes with a learner: competing writers, create races,
   concurrent unconditional writes, delete/recreate ABA, aliases and distinct
   subtrees, delayed/stale readers, restart/snapshot and an ambiguous response.
5. Adopt the capability in actual managed mailbox storage. Inventory and preserve
   existing data, identities, certificates and durable reader values before any
   coordinated backend change. Migration uses native APIs and verified bytes;
   operator cursor edits or resets are not an acceptance method.
6. Land S6 binding against a real released NexusVFS tag, then verify a stopped or
   frozen old owner cannot regress the newer claimant's committed cursor. Source
   availability, distinct-identity F6, successful send and lease renewal do not
   substitute for this acceptance.

The existing F6 archive remains frozen. This work introduces its own isolated
fixtures and receipts and does not reuse the 30 old directed cases as proof.
