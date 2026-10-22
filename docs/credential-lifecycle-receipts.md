# Immutable agent intent and selected final certificate

This slice proves isolated crypto/storage composition. It enables no RPC,
production signing, renewal, deployment or client activation. It supersedes
the unshipped signed-candidate prototype: a losing signed identity must not
be recoverable from the Raft WAL by a holder of the corresponding CSR key.

## Two records in the existing control store

- **I**, at the existing cluster-global `agent:<name>` key: the legacy
  AuthKeyRecord JSON prefix plus version-2 `credential_lifecycle`. This
  binds verified caller, owner, issuer fingerprint, actor name, operation ID
  and canonical request digest to the complete unsigned X.509 TBS, verified
  SPKI, positive serial and second-precision validity window. Name claim and
  unsigned identity are one apply-time put_if_absent. No signature exists
  before this selection.
- **F**, at `credential-final:<SHA256(canonical I)>`: version, intent hash,
  TBS hash, serial and selected final DER. Another immutable put_if_absent
  in the SAME existing auth control store, using the SAME Raft command.
  No second registry, issuer, journal, database or daemon.

The digest is domain separated (nexus-agent-intent-v2 followed by NUL) over
the serialized typed intent, whose fields are ordered and contain no maps.
Versions, names, SPKI, serial, validity and TBS/DER sizes are bounded.
Unknown versions fail closed rather than reinterpret policy after upgrade.

| Observed records | Derived state | Recovery |
|---|---|---|
| No I at this barrier | NotObserved | Retain original key/CSR/op; an in-flight proposal may still commit |
| I and no F | IntentCommitted | Recheck current authority, sign only exact I, select F |
| I and F | Finalized | Recheck current authority and return only stored F |

There is no mutable takeover journal.

## Serialize without a signing key, then guard the existing signer

prepare_agent_csr_intent verifies bounded P-256 CSR proof using the existing
verifier, discards all requested policy and builds the ordinary-agent v1
profile through the existing policy builder. A public-only SigningKey
adapter captures rcgen's exact TBS and refuses signing. Preparation does not
accept the CA private key. Issuer DN encoding, algorithm identifiers,
extensions, SPKI, serial and validity are committed as bytes, rather than
a profile label that might later change.

Only after I is committed does finalize_agent_issuance call its trusted
crypto adapter with the stored winning intent. sign_committed_agent_intent
uses the SAME existing CA loader and rcgen signer. It verifies exact issuer
fingerprint, current CA/signing capability, matching CA key, leaf validity,
subject algorithm and policy. A guarded key compares the encoder's entire
TBS with I BEFORE delegating to the real CA key. Changed bytes, fields,
algorithms or issuer encodings are refused. Output is parsed and its
signature, TBS and serial checked again.

Concurrent finalizers may produce randomized ECDSA encodings of the SAME
committed TBS/serial. F's CAS selects one encoding. Both winners and losers
read F back; ONLY that stored DER is returned or replayed. This promises
exact returned-certificate replay, not one mathematically possible ECDSA
signature. Losing F proposals can contain a valid encoding of the already
committed identity. Losing I proposals contain no signature. No expanded
log-reader trust or TLS receipt lookup is added to admission.

## Crash, Unknown and current authorization

Crashes before I apply, after I, after signing, after F apply and before
response retain the same client key, CSR, operation and request binding.
Signing failure after I never elects another serial/key. Lost commit replies
and failed read barriers return Unknown. Replaying F never signs again.
An absent linearizable query is absence at that barrier, not proof that a
prior submission cannot still apply.

The coordinator requires a per-request IssuanceAuthorizer from the future
composition root. It derives identity from authenticated caller context and
checks current caller validity, CRL, owner and applicable policy. Checks
apply to commit/query/replay, before signing/F CAS and before returning a
certificate. Receipt strings, operation IDs and the expired legacy prefix
grant no authority. Changed request/op is a typed Conflict; changed
issuer/caller/owner is refused. Lost, expired or revoked authentication
requires explicit operator recovery, never silent remint or allow_existing.

Owner-only pending key/CSR/op persistence, transport policy/CRL wiring and
activation are NOT implemented here. Fleet/session/runtime paths are unchanged.

## Legacy reader/cache and writer compatibility

I retains a decodable legacy prefix with expires_at_ms=0 and revoked=false.
Legacy authentication refuses expiry; name dedup still sees a permanent
binding. This sentinel is NOT operator revocation and cannot override
current authorization/CRL. F completion never activates the legacy row.
Existing certificate identity remains CA-chain/CRL based, with no receipt
store lookup.

Every managed marker, including malformed/future versions, refuses legacy
allow_existing rotation. A legacy absent-read must insert with CAS, never
upsert over a concurrent I. Existing readable legacy rows can rotate as
legacy: managed insertion requires absence, and supported token revocation
cannot delete the name binding.

Token revoke-by-hash refuses agent: AND the entire credential- namespace,
including F and future renewal intents. Token mint/revoke derive HMAC hex
keys and cannot address these reserved keys. Supported legacy upsert/delete
paths cannot erase I or F. The HTTP DELETE endpoint uses the same guarded
revoke function instead of its former direct store.delete; reserved targets
return HTTP 400, including absent/future records. Old issuer binaries/raw operator store mutation
are outside this invariant: authoritative writers must be upgraded before
future RPC enablement. No running writer is upgraded by this slice.

Strict atomic CAS and linearizable read APIs default to errors, never weak
fallbacks. Legacy new-name mint also requires strict CAS: inheriting the
trait's weaker get-then-put cannot erase a managed insert even on a backend
that implements only the strict method. Unsupported stores refuse creation;
existing readable legacy rotations remain compatible.
Raft uses existing apply-time CAS/ReadIndex. KernelSlotStore
forwards those plus the legacy CAS; its old trait-default get-then-put
wrapper would otherwise discard the backend CAS.

## Isolated CI fixtures

- Crypto: public-only unsigned TBS; hostile CSR policy discarded;
  key/serial/time/issuer/TBS mutations refused; repeated signatures verify
  against the same committed TBS/serial.
- Storage: competing operations, immutable I/F, current-authority revocation,
  crash at I/sign/F/response, exact stored DER, concurrent finalizers,
  reserved deletes, malformed schemas and unsupported stores failing closed.
- Readers: real legacy decoding and token provider/cache rejection of
  incomplete prefixes; ordinary legacy authentication, invalidation and
  rotation stay compatible. Actual HTTP admin DELETE preserves reserved
  records; HTTP listing retains the expired prefix and skips F's schema.
  This does not pretend the token fixture tests
  the independent certificate identity plane.
- Composition: real one-voter Raft through KernelSlotStore; eight distinct
  CSR operations/one unsigned winner; concurrent real ECDSA finalizers;
  lost replies after actual I/F apply; crash after signing; persisted-zone
  reopen without changing original intent. Restart waits for leader entry
  apply before ReadIndex, without warm-up writes or production Raft changes.

Commands run in CI, with no local Cargo build:

```sh
cargo test -p raft@0.1.0 --all-features transport::certgen::csr_intent --lib
cargo test -p auth agent_issuance --lib
cargo test -p auth slot_store --lib
cargo test -p nexus-cluster --test agent_issuance_receipts
```
