# Record owner guards

Per-file conditional writes do not fence a Session's other files or its WAL.
A client can prepare a completion before deletion and publish it afterwards
unless the owner decision and the final mutation share a serialization point.

The qualified `ZoneMetaStore` record controls bind a record to one protected
owner revision. They use the owning zone's existing Raft actor and redb database.
They are metadata controls; they do not qualify a mutable content backend.

## Admission and commit

1. The storage owner explicitly protects its owner record and reads its revision.
   The owner path and record path must belong to the same qualified zone.
2. `bind_record_guard` compares the exact qualified record image, then commits
   the permanent owner binding and conditional-only policy together. An absent
   record can be enrolled before publication. A conflicting image changes no
   policy. Repeating the same binding is safe; rebinding to another owner refuses.
   The existing protection policy records the permanent owner role: an owner
   cannot become a child record, and a child record cannot admit other records.
3. `replace_guarded_record` compares both the record revision and the admitted
   owner revision in the final apply transaction. `append_guarded_record` checks
   the owner in that same transaction before assigning its sequence. The finite
   Raft mutation payload also supports the existing seal and trim transaction
   arms, without copying a record or accepting nested arbitrary commands.
4. Ordinary metadata replacement, deletion and rename cannot bypass the record
   policy. Unconditional WAL append, seal and trim cannot bypass its owner.

The revision allocator remains the existing conditional-metadata allocator.
Process IDs, wall clocks and advisory lease expiry do not authorize commits.
Mutations, owner comparisons and `last_applied` commit in one transaction.
The apply functions perform no blob I/O or background work.

The existing stream wakeup observer also handles guarded appends. It uses the
durably applied outcome: an assigned offset wakes local stream readers and file
watches, while a refused ordinary or guarded append publishes no write event.
The observer retains only a weak Kernel reference and performs no storage I/O.

An owner key and its permanently bound record paths identify one storage
incarnation. Persistent Agent/SID indexes and Agent mailbox cursors retain
their independent lifetimes. They must not become children of a particular
Session's storage lifetime. Restoring a retired incarnation requires fresh
owned storage paths and the existing persistent index's publication protocol.

## Retirement

`retire_record_guard` atomically publishes a terminal owner image and retains a
permanent retirement marker. Neither a current revision nor a new connection can
admit a writer after retirement. The old owner path cannot be overwritten or
deleted to restore that authority. The marker and bindings survive restart and
snapshot restore and provide durable intent for later reclamation.

A submitted operation can have an unknown outcome. Callers must read the durable
owner decision before deciding how to proceed; a timeout proves no retirement.
Repeating admission to the same live owner is idempotent. Append retry continues
to require an application event identity and replay deduplication.

## Storage admission

These controls use the existing `FixedLocal` storage admission. Generic,
forwarded and EC proposal doors refuse the new commands. Managed membership
and snapshots into a managed group remain unsupported.

The first binding or retirement upgrades the existing protected-record format
requirement to `guarded-records-v1`. Later ordinary record protection preserves
that requirement. The prior conditional-policy reader, official v0.8.29-rc.5,
rejects the unknown requirement before serving this store. Readers predating
that policy framework are outside the qualified reader set; this change does
not qualify an arbitrary historical binary for rollback.

## Storage I/O lifetime

The owning service can explicitly enroll a fresh or quiescent owner with
`admit_record_io_owner`. Existing consumers retire before enrollment. This
preserves the owner revision and upgrades the required reader format to
`guarded-record-io-v1`; later record admission and retirement preserve that
requirement and the owner's I/O role.

`begin_record_io` checks a consistent owner snapshot, acquires a native shared
file lock, then checks the same owner again. The returned handle stays with the
actual blocking operation until its storage side effects finish. Cancelling
the request's reply does not release that operation's handle.

Retirement commits immediately through Raft. `try_exclude_retired_record_io`
provides an exclusive native handle only after every admitted operation has
finished. An operation can finish while its runtime or cohost process remains
alive. Reopening the same metadata store uses the same native lifetime domain,
so another Kernel instance cannot forget an outstanding operation.

The small native lock inode stays with the permanent retirement identity.
Recreating its path while an old handle exists would split the exclusion.
File operations and lock waits run outside the Raft actor's apply transaction;
only deterministic enrollment and owner decisions enter consensus.

The Kernel's `read_guarded_content` and `replace_guarded_content` retain the
lifetime handle through their synchronous content work and completion hooks.
They share permission checks, link resolution and immutable publication with
the existing conditional-content operations. A stale owner refuses before
staging content; retirement during an admitted write is checked again in its
final metadata transaction. A cancelled RPC must leave its blocking worker
running with this handle until the actual operation finishes.

These lifetime controls do not yet start a reclamation worker or wire every
consumer's content publisher. The product deletion gate stays closed until
those integrations are accepted. The ordinary, unguarded content and syscall
surfaces retain their existing contracts and do not qualify physical cleanup.

The typed `ReadGuarded`/`WriteGuarded` RPC pair carries a required owner token
and preserves the existing authenticated identity, runtime gateway delegation
and request envelope. An older server returns `UNIMPLEMENTED`; a client must
not retry through an unguarded operation. The blocking and asynchronous Rust
clients share conditional response decoding, including uncertain write results.
Server workers retain their Kernel I/O handle after the RPC reply is cancelled.
These data operations do not grant clients owner admission or retirement rights.

## Trusted service controls

The Kernel's regular-file control methods share the existing service-only
protection boundary: `admit_record_content_io`, `bind_record_content_owner`,
`retire_record_content_owner` and `try_exclude_retired_content_io`. They keep
the caller's original identity, require metadata write permission, apply read
hooks and recheck directory-link targets. They do not elevate an RPC caller.

I/O enrollment qualifies the protected owner's exact immutable image and keeps
its revision. Binding qualifies an existing regular file, or reserves an absent
one, before the existing apply transaction compares that image. Both paths must
use the same captured mount, backend and metastore; spell both through the same
alias. These methods do not admit a legacy WAL or a cross-mount owner.

Retirement preserves the owner's immutable application bytes and publishes the
existing irreversible storage marker with its new revision. That marker is the
authority. After an unknown reply, the service reads the current owner revision
and validates it with the exclusion operation: `Ok(None)` confirms retirement
while actual I/O remains, and `Ok(Some(handle))` additionally excludes that I/O.
The service retains the handle through any future reclamation work. Neither
result qualifies shared CAS reference ownership or starts reclamation.

These controls currently serve native trusted services. RPC control admission,
Session factory integration and automatic cleanup remain separate requirements.

## Acceptance and remaining integration

`test_protected_zone_metadata` exercises the actual actor and durable database:
prepared history/completion/ACK writes after retirement, legacy write refusal,
concurrent writers, reconnect after restart, snapshots, format retention and
unrelated writable records. The native runtime CI also supplies the
digest-verified official rc.5 daemon and checks its actual startup refusal.

These primitives do **not** enable Sudocode's remote Session deletion yet.
The following remain required before advertising that product capability:

- Authenticate and compose the controls at the kernel/RPC and consumer boundary.
- Wire every content publisher to hold storage I/O guards through actual
  completion, including work continuing after request cancellation.
- Reclaim owned hot records and cold references automatically after retirement,
  resuming after crashes and preserving independently retained CAS content.
- Qualify real daemon/PTY consumer journeys, current deployed products and
  multi-node storage before changing feature defaults.

The primitives do not advertise fenced OS locks, guard reads, delete blobs or
change kernel syscall field meanings. Native OS FS retains its existing lock and
automatic cleanup implementation while the remote lifecycle is integrated.
