# Atomic first-agent claim and public receipt foundation

This source slice adds storage helpers, not an issuance RPC or a production
rollout. It builds on the caller-owned CSR signing foundation. A minter must
authenticate and authorize the caller, verify its CSR, select the trusted
issuer/profile and check revocation before constructing a candidate. Those
transport/policy gates are not implemented by this storage module.

## One name, one record, one apply

`auth::agent_issuance` stores the existing `AuthKeyRecord` fields at the JSON
top level and adds one reserved `credential_lifecycle` field containing a
versioned public receipt. The existing `agent:<name>` claim and its receipt
are the same value, inserted once using the existing control-zone Raft CAS.
There is no second claim registry, database, journal, daemon or Raft command.
Legacy `AuthKeyRecord::decode`, provider and listing readers ignore the extra
field and keep reading the same identity record.

The receipt binds issuer fingerprint, authenticated caller and owner, agent
name, operation ID, full canonical request digest, and the exact public
certificate DER/serial. A competing operation or changed request returns a
typed Conflict. An identical request returns the committed bytes, even when
a newly signed candidate has a different serial/signature. No private key
or token belongs in this record.

The HAL's explicit `put_if_absent_atomic` and `get_linearizable` default to
errors. The Raft driver delegates them to its existing apply-time CAS and
ReadIndex barrier. `KernelSlotStore` forwards both and also forwards the
existing legacy `put_if_absent`: previously that wrapper accidentally used
the trait's get-then-put default, losing the installed backend's CAS.

## Legacy rotation invariant

Legacy rotation may update an existing, readable legacy agent row. It cannot
overwrite any `credential_lifecycle` marker, including malformed or future
versions. If its initial read finds no row, it must insert with CAS rather
than upsert: a managed insert might win after that read.

The existing-row guard depends on a permanent name binding: managed claims
only insert absent names, and supported token revoke-by-hash now rejects
all `agent:` keys. Certificate revocation continues through the existing CA
CRL path. Therefore a readable legacy row cannot be deleted and replaced by
a managed row between its class check and legacy update. Legacy rotations
of that row remain legacy. This is a state-transition invariant, not a claim
that read-then-upsert is a general CAS.

Every writer must use these guarded routes. An old issuer binary or direct
operator mutation of the raw store is outside the invariant. Enabling the
future CSR RPC requires the authoritative writer upgrade first; compatibility
with legacy readers does not authorize unguarded legacy writers. No running
writer is upgraded by this slice.

## Unknown and replay authorization

Store failures are Unknown, including a reply lost after the real apply or a
failed read barrier. The client retains the same private key, CSR, operation
ID and request binding. A query uses a read barrier and checks issuer,
authenticated caller, owner and name before comparing operation/digest.
Knowing an operation ID confers no query/replay authority. A missing result
means only "not observed at this read barrier": an in-flight proposal may
still commit. It never permits a fresh operation, key or name.

Caller authorization is re-evaluated by the future RPC handler for every
attempt/query. A receipt is not a bearer credential. Expired, lost or revoked
authentication requires explicit operator recovery; receipt storage does not
provide a re-mint or a recovery bypass. Pending key/CSR/op persistence and
leaf activation remain a separate client-side slice.

## Sign-before-CAS consensus log boundary

Signing before the atomic insert preserves exact committed certificate bytes
despite randomized signatures and serials. The coordinator exposes only the
winner and does not application-log a losing certificate. However the Raft
proposal carries the candidate value BEFORE apply. A failed-CAS candidate
can therefore remain in consensus logs/WAL even though it is absent from the
final claim row. This design cannot promise that losers were never persisted.

A CSR holder already owns the corresponding private key. If it can also read
those logs, it may recover a cryptographically valid losing leaf. The current
CA-chain/CRL verifier does not consult this receipt to reject such a serial.
Before RPC/renewal integration, the issuer policy must explicitly accept
consensus-log access as trusted issuer/operator authority, or add an agreed
admission check for the committed serial. This slice enables neither option
and must not be described as enforcing one valid leaf cryptographically.

## Isolated CI coverage

Unit fixtures exercise the one-row layout, legacy decoding and rotation,
changed operations/requests, unauthorized queries, a lost commit reply,
unknown/future markers, unsupported stores, and the absent-read/managed-insert
race. A cluster-profile fixture uses a real one-voter control zone through the
kernel slot: eight competing operations, one winner, a lost reply after real
Raft apply, shutdown, persisted-zone reopen and exact certificate recovery.
Existing provider/list/legacy rotation tests remain in the workspace CI.

```sh
cargo test -p auth agent_issuance --lib
cargo test -p auth slot_store --lib
cargo test -p nexus-cluster --test agent_issuance_receipts
```

Ordinary NodeRenew/AgentRenew RPCs, revoked-caller authorization, owner-only
pending state, activation and cohost capability wiring remain later slices.
