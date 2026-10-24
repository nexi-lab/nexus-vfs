# Cross-domain Agent join: native source proposal

Status: experimental address/value foundation plus an unconditional reservation
of `/collaboration` in the existing cluster permission provider. This is not an
enabled federation protocol. The `a2a/experimental-domain-join` feature has no
credential issuance, native collaboration authorization or mount activation.
Existing local conversations and their identifiers are unchanged.

The deployment target is an existing SudoWork/Moss/cohost product runtime on
Edge, then existing Cloud Agent allocations. A separate standalone Agent is
not qualification of that runtime. Shared sequencing and release composition
belong in sudostack; appliance service selection belongs in sudoedge. Native
authentication, authorization, addressing and forwarding belong here and in
the consuming scode runtime, not in deployment scripts.

## Facts that rule out a configuration-only join

At v0.8.23, live public-CA registration, signature-based foreign classification
and mailbox sender stamping exist. A foreign issuer cannot become a local
Node/voter. These are useful authentication primitives, not a completed
collaboration contract:

- `ForeignAgentMailboxOnly` admits transcripts by path shape rather than
  participation. Stamping a sender does not authorize reading the transcript.
- Its path predicate is intentionally broad for stamping. Reusing that
  predicate as an allow-list broadens authorization in the wrong direction.
- It denies all foreign reader writes, including a receiver's own register.
- `resolved_agent_id` qualifies foreign names with slashes; the existing
  presence/index convention assumes single segments and both ends otherwise
  derive conversation IDs from different name strings.
- A managed cohost uses its local Kernel backend. Replacing that mailbox with
  a direct remote client would bypass the required local content-policy path.

Do not enable cross-domain operation by widening those legacy checks, copying
one domain's private CA, granting foreign Node authority, or joining the Edge
to a remote Raft quorum merely to make its mailbox visible.

## Public identity and addressing values

The proposed global Agent address binds the **full SHA256 of the registered
anchor's DER SubjectPublicKeyInfo (SPKI)** and the exact UTF-8 Agent subject.
The same rule applies to the domestic cluster CA. The registered anchor is the
authority, not the leaf's direct issuer if intermediates are later supported.
Operator labels, endpoints and display names are not authority identifiers.

The experimental `a2a::domain_address::AgentAddress` codec is:

```text
a1.<base64url-no-padding(32-byte issuer fingerprint)>.<base64url-no-padding(subject UTF-8)>
```

Values are reversible, canonical, single path segments of at most 218 ASCII
bytes. The subject bound is 128 UTF-8 bytes with no control characters. This
is an address-format bound; it does not replace the issuer's subject policy or
establish that the subject appears in any valid certificate. No normalization,
slash replacement, CN fallback or handwritten downstream codec is permitted.

An address is public data, not a `VerifiedPrincipal`. The later authorizer must
derive its caller from the current actual mTLS leaf or the trusted managed
descriptor/owner composition. An address decoded from a request cannot be
promoted into that proof. Node, controller, session and durable managed-Agent
identities must remain distinct.

The existing classifier verifies signatures and picks the first matching
anchor. Two renewed CA certificates using one key must therefore produce the
same address; complete-certificate DER is unsuitable as that input. Before
activation, native enrollment must reject an ambiguous key registered under
conflicting domains or grants, and current classification must detect an
already-conflicting anchor set rather than pick its iteration order. A new
authority key produces different addresses. Any continuity across that key
rotation needs an explicit native authority decision; deployment scripts cannot
alias the two generations themselves.

Raw subjects are exact values, not trusted display labels. `escaped_subject`
produces an ASCII rendering that exposes format characters, including U+200B,
U+202E and U+FEFF. Permission/grant review must show this rendering and the full
canonical segment, rather than accepting a visually ambiguous display name.

For initial one-to-one collaboration, derive membership from an ordered pair
in the address itself, rather than introducing another mutable CID-membership
registry. Each participant stays one bounded component:

```text
/collaboration/v1/<space>/pairs/<first>/<second>/transcript
/collaboration/v1/<space>/pairs/<first>/<second>/readers/<owner>
```

`space` is an opaque 128-bit lowercase hexadecimal value, not a Raft Zone ID or
a caller's self-asserted tenant. `first` and `second` are distinct canonical
Agent segments sorted by ASCII bytes. Only those two participants can have a
reader in this pair. Both domains derive the same path. Exact parsing rejects
prefix lookalikes, extra segments, noncanonical order and unrelated readers.

This separate path family does not match the legacy transcript allow-list.
The v0.8.23 provider refuses it for a foreign caller, but allows domestic and
unidentified callers. The old stamping hook leaves these paths unstamped.
This change reserves the complete `/collaboration` path component in the
existing permission provider, before its domestic fast path and independently
of the experimental feature. It denies non-system callers, including admins,
on transcript, reader and malformed paths. A real Kernel I/O regression covers
those caller classes, with ordinary local paths retaining their existing rules.

The reservation is a denial, not the future native participant authorizer.
Every serving node must also be **identity armed** (`CertIdentity` or `ApiKey`).
An `Open`/`NoAuth` profile resolves network requests as `is_system=true`, and
the Kernel deliberately bypasses permission providers for that context. Such
a profile does not protect this namespace and must not host a collaboration
space, even on loopback. Future activation must refuse this posture rather
than reinterpret its synthetic system context as an authenticated Agent.
Every node that can serve the hosting zone must enforce the boundary; an
individual peer's capability cannot qualify a mixed-version zone. Existing
older binaries cannot gain that enforcement through negotiation. The family
is not yet mounted, replicated, stamped or authorized by this prototype.

## Enrollment and authority

The minimal join needs three explicit decisions:

1. **Trust**: an existing domain operator approves the peer's full public-CA
   fingerprint and verified service endpoint. Use the existing live
   `RegisterForeignCa` authority and reverse server trust, never a second
   issuer or an insecure transport fallback. Reconcile an identical enrollment;
   conflicting or unknown registration outcomes are not permission to remint.
2. **Authentication**: the current peer classifier validates the real leaf,
   time, issuer continuity and applicable current revocation policy. The
   outbound credential must attest the actual resolved cohost Agent; a shared
   Node/controller credential cannot speak for arbitrary hosted identities.
   When an existing product has only session credentials, record that fact;
   do not rename a session or static profile into a durable Agent.
3. **Authorization**: anchor trust does not imply access to every collaboration
   space. Extend the existing native trust/control authority with explicit
   space-scoped grants and revocation. Each space must immutably select one
   hosting authority and its authoritative replicated zone/endpoint. Non-hosts
   must route to that authority and must not first create a local transcript.
   Default for an old anchor with no such
   grant is no access to this new family. Do not add another identity database.
   A space grant is distinct from model, filesystem, administrative, owner
   adoption and cluster membership rights.

The precise grant schema and authority-update operation remain a native review
gate. A deployment manifest can name required capabilities and public pins;
it cannot declare that a remote peer has granted permission.

Current authorization must apply to new requests and queries on a previously
established TLS channel. Map live and offline revocation writers before
claiming atomic ordering through append/receipt completion. A process-local
mutex or a callback returning `()` is not a cross-process ordering proof.

## Data plane and compatibility

The existing local Kernel remains the execution boundary. A collaboration
mount/adapter must authorize the verified Agent, apply its configured content
policy, and forward under that Agent's own current credential. The same global
path is used at both ends, preserving identity through routing. The adapter
must cover metadata/indexing, framed stream append/read, lock/renew and the
caller's own reader commits; an ObjectStore write alone is insufficient.

The hosting profile must include `/collaboration` in its replicated prefix and
mount configuration before admitting a space. Otherwise an apparently global
path can silently land in a node's SOLO root zone. The space authority/grant
record, not the path's appearance or local first write, chooses the one copy.

Keep one authoritative transcript. Local delivery/reconciliation evidence is
not a second authoritative log. A proven native pre-submission refusal is
distinct from Unknown after a possible append. Preserve the original operation
through Unknown and reconcile; never automatically resend a possibly committed
append. Reader leases and acknowledgments retain their actual guarantees.

Native authorization for the new family must require all of:

- the required negotiated protocol capability;
- current authenticated principal and current space grant;
- exact canonical path and pair membership;
- for reader mutation, exact caller ownership of the reader leaf;
- local and remote policy success for the requested operation.

Legacy local names/conversations continue through the existing local path.
Cross-domain operation uses an explicit versioned capability; it cannot be
silently translated to a bare name or a legacy remote filesystem write.
Directory visibility is addressability, not proof of a running receiver.

Before using the new family, the daemon's stamping hook must derive the same
canonical sender from trusted context. This prototype does not change the old
`resolved_agent_id`, envelope, or wide stamping predicate. Stamping and narrow
authorization are separate consumers and must not share opposite safety
assumptions about over-including paths.

## Concrete implementation sequence

1. Review/test this value codec and path derivation in Nexus. Generate consumer
   artifacts only from the accepted exact owner source; do not hand-copy it
   into Stack, Edge, Cloud, scode or the MCP bridge.
2. Establish the actual managed-Agent/owner to outbound-leaf seam and native
   current-authority lifetime. Preserve existing strict identity claims;
   missing issuance/recovery primitives are explicit blockers, not a reason
   to enable fallback credentials or `allow_existing`.
3. Add the existing-store scoped join authority, narrow participant and reader
   enforcement, canonical stamping and explicit capability negotiation.
4. Implement/qualify the local Kernel collaboration adapter, then consume it
   in the existing scode managed host. Preserve the ordinary model path and
   native approval/pause/worker/receipt boundaries.
5. The shared deploy performs actual inspection, source-bound staging,
   owner-controlled replacement, native join and authenticated verification
   on the real DGX. Preserve existing product state and model policy. Seven
   peers are a resulting end-to-end check, not a replacement for deploying it.
6. Consume those same capabilities in Cloud's existing runtime/allocation
   adapter, preserving real Agent and Session bindings and retained volumes.

Required native negatives include unrelated-pair reads/writes, another reader,
same names in distinct domains, a forged Node or sender, unsupported old peers,
expired/revoked leaves on live channels, removed anchors/grants, content
deny/redaction/analyzer outage, response loss, restart/reentry and no resend.
Positive tests must include the actual existing Edge product path and preserved
local model/history behavior. Address-unit tests establish none of those live
properties on their own.
