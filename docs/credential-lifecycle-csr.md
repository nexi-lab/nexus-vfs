# Caller-owned CSR signing foundation

`nexus_raft::transport::{sign_node_csr, sign_agent_csr}` sign a caller-owned
EC P-256 public key. They accept one bounded PKCS#10 PEM request, verify its
signature and key algorithm, and return only the public leaf certificate.
They share certificate policy and the CA loader with the existing local-key
generators. The caller's private key never enters these APIs.

The authenticated issuer supplies the node/zone/name and approved reachability
SANs. No requested DN, SAN, key usage or extended usage is trusted. Nodes retain
their node URI, approved server names and client/server usage; ordinary agents
receive only their agent URI and client usage. Unknown request extensions fail
closed. Owner-bound session and user-runtime credentials retain their existing
short-lived issuance and renewal paths.

The supplied issuer must be current, carry CA basic constraints, permit signing
if it carries key usage, and match the signing key. Leaves cannot outlive it.
Each signed leaf gets an independent issuer-generated positive random serial:
reusing a subject key must not alias certificate revocation or renewal lineage.
The application remains responsible for selecting the authorized issuer and
checking caller authorization and revocation before calling the signer.

## Lifecycle boundary

These are stateless signing primitives. They do not expose an RPC, enroll an
identity, claim an agent name, persist an operation, perform a renewal, or
change a running node. Repeated calls sign distinct certificates; they do not
implement idempotent replay. A later issuance coordinator must return the
exact committed public certificate from its receipt instead of signing again.

The lifecycle contract for that coordinator is:

- Persist the caller's private key, CSR and operation ID owner-only before
  making a network request. Never silently fall back to server-generated keys.
- Bind replay to the authenticated caller, issuer, credential kind and complete
  request fingerprint. An identical operation replays the exact committed
  certificate; changed input conflicts. Proposal-ambiguous failures are Unknown.
- Commit first-agent issuance's existing name claim and public receipt as one
  apply-time `put_if_absent` in the existing shared control store. Legacy readers
  and rotation must remain compatible; legacy routes cannot overwrite a managed
  receipt. An occupied unmanaged name is not permission to adopt it.
- Commit at most one immutable successor for each `(issuer, kind, prior serial)`.
  An exact replay returns that winner; a competing operation or CSR conflicts.
  Preserve overlap and revocation policy. `allow_existing` is not renewal.
- Authorize receipt queries/replay independently of possession of an operation
  ID. Loss or expiry of the credential requires explicit operator recovery,
  never an implicit new mint. This foundation does not implement that recovery.

The isolated unit fixtures cover possession of the requested key through the
existing authorship verifier, requested identity/usage elevation, malformed
encoding and signature, key curve, unsupported extensions, CA capability,
issuer/key mismatch, issuer validity, leaf expiry and independent serials.
Race, restart, legacy receipt compatibility and revoked-caller tests belong
to the stateful coordinator slice.

CI's existing `cargo test --workspace --all-features` job runs the fixtures.
The focused command is:

```sh
cargo test -p raft --all-features transport::certgen::csr_tests --lib
```
