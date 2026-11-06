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

## Acceptance and remaining integration

`test_protected_zone_metadata` exercises the actual actor and durable database:
prepared history/completion/ACK writes after retirement, legacy write refusal,
concurrent writers, reconnect after restart, snapshots, format retention and
unrelated writable records. The native runtime CI also supplies the
digest-verified official rc.5 daemon and checks its actual startup refusal.

These primitives do **not** enable Sudocode's remote Session deletion yet.
The following remain required before advertising that product capability:

- Authenticate and compose the controls at the kernel/RPC and consumer boundary.
- Hold storage I/O guards through actual completion, including work continuing
  after request cancellation; drain them before reclamation.
- Reclaim owned hot records and cold references automatically after retirement,
  resuming after crashes and preserving independently retained CAS content.
- Qualify real daemon/PTY consumer journeys, current deployed products and
  multi-node storage before changing feature defaults.

The primitives do not advertise fenced OS locks, guard reads, delete blobs or
change kernel syscall field meanings. Native OS FS retains its existing lock and
automatic cleanup implementation while the remote lifecycle is integrated.
