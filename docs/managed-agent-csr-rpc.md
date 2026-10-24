# Managed Agent caller-owned CSR interface (experimental)

This adds the network frontend to the existing unsigned I / selected F
coordinator. It reuses `AgentMinter`, the configured local CA holder and the
existing auth control store. The cluster profile opts in with
`experimental-managed-agent-csr`; default builds report version 0 and refuse
issuance. No running node, managed Agent, trust registration or session is
changed by this source slice.

## Authority and binding

The strict-mTLS Node control service exposes three methods:

- `GetAgentCsrCapabilities`: version 1 and the exact local CA certificate DER
  SHA256 (32 bytes). This is distinct from the collaboration address's SPKI
  authority digest. A capability is not permission to issue.
- `IssueAgentCsrV1`: prepare public unsigned intent, select I, sign only I,
  select F, return the stored public certificate.
- `QueryAgentCsrV1`: authenticated read-only reconciliation of the exact
  original request. It never prepares, signs or inserts anything.

Each request binds the actual current local Node (`node:<native node ID>`),
expected issuer DER digest, resolved managed Agent name, owner, display name,
operation ID and **original CSR PEM bytes**. The local Node is the native
cluster control principal and vouches for the managed descriptor/owner;
frontend Agent credentials do not confer this authority. The deploy/runtime
adapter must obtain that descriptor through its native owner-checked path,
rather than let a frontend request choose a different identity.

The profile checks current local CA, Node certificate role/signature/time and
the strict native revoked-serial file on every coordinator authorization
callback, including query, signing, F selection and replay. Unreadable or
malformed revocation data refuses the operation. Receipt strings and operation
IDs grant no authority. This does not add distributed Node revocation or
foreign Agent CRL policy. Revocation ordered before the next authorization
check refuses it; there is no claim of atomic revocation through network
response delivery.

The request digest is SHA256 over UTF-8 domain
`nexus-managed-agent-csr-v1` followed by NUL, then these six fields in order:
Agent name UTF-8, owner UTF-8, display name UTF-8, operation ID UTF-8, original
CSR PEM bytes, expected issuer's 32 raw digest bytes. Each field is preceded
by its byte length encoded as an unsigned 64-bit big-endian integer.
No JSON encoding or client-supplied digest is trusted. Agent/owner identities
are bounded to 256 UTF-8 bytes with no whitespace, control or path separator;
display name is at most 256 bytes with no controls; CSR is 1..16384 bytes;
operation IDs use the existing contracts validator.

## Outcomes and recovery

`Finalized` returns only stored F, with the original serial/intent digest.
`IntentCommitted` reports I without a selected certificate. `NotObserved`
means absent at that read barrier; a prior in-flight proposal may still apply.
`NotSubmitted` proves a pre-issue refusal of **this command**; it says nothing
about an earlier ambiguous command. After a mutation attempt, all errors are
conservatively `Unknown`. Unrecognized enum values, unsupported methods,
transport loss and response loss must not become success or trigger a retry.

The caller must persist its private key, CSR, complete request and operation
owner-only **before** issuing the RPC. It retains them through Unknown and
queries that same operation. An explicit recovery may finish the same I/F;
it cannot replace the key, operation, owner or name. An occupied legacy name
is refused: there is no `allow_existing`, adoption or server-generated-key
fallback. Returned DER must be checked against the original key, expected CA,
Agent name and current validity before publication in the existing credential
bundle format.

`raft::agent_csr_client::PendingAgentCsr` supplies that caller persistence. The
native owner-checked deploy adapter passes its resolved `AgentCsrBinding` and
public local CA. `create` persists a new P-256 key and the exact protobuf
request in one owner-only document, syncing the file before returning the
request. Existing files (including interrupted writes) are never replaced.
`load` is explicit recovery: it rejects changed Agent/owner/display/operation,
issuer, malformed material and a CSR/key mismatch. Neither method makes an
RPC. The caller submits once or queries the original persisted request; an
explicit finish of the same operation is separate from an automatic retry.

`publish` accepts only the bound `Finalized` response from the authenticated
issuer. It checks request/identity/serial, the pinned CA, signature, current
validity, ordinary Agent SAN/client-only usage and the original public key.
It uses the existing `AgentCredential` filenames and writes `credential.json`
last. Identical files can complete an explicitly resumed publication;
conflicts or partial bytes refuse without overwrite. The pending document is
retained. This is local caller state, not an issuer, grant store or runtime
activation receipt. A lost write/sync can leave a partial file requiring native
operator recovery; no request is returned for submission after that error.
These primitives do not resolve a managed owner, install trust, activate an
outbound runtime identity, or implement a domain join by themselves.

The CA private key is read only in the coordinator's guarded signer callback
after I wins. Query and F replay do not need it. Tests use a real isolated
mTLS listener, real one-voter Raft, the native issuer and caller-generated key;
fault injection loses replies after actual I/F apply. No model, fleet endpoint
or deployment is involved. Windows executed that native fixture successfully,
then all 73 cluster-profile library tests passed with the feature enabled.
Prior local passes used a shared target directory that was later found to
reuse dependency artifacts across worktrees. They are retained as diagnostic
history, not final source qualification. Requalification uses a stable profile
per source workline under the same target root. The composed caller-persistence
head still needs its own native validation and exact-head three-platform CI.
