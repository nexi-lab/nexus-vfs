# Cross-domain Agent join: native source proposal

Status: experimental address, request-identity and immutable space-policy
foundation, plus an unconditional reservation of `/collaboration` in the existing
cluster permission provider. No daemon installs the experimental identity/policy
path. Credential issuance, current foreign-CRL policy, management installation,
Kernel forwarding and mount activation are still required. Existing local
conversations and their identifiers are unchanged.

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
The existing foreign-CA registry/bootstrap fingerprint remains SHA256 of the
complete certificate DER. That registry key and the SPKI address authority are
different pins and must not be substituted for each other in native APIs.

The experimental `a2a::domain_address::AgentAddress` codec is:

```text
a1.<base64url-no-padding(32-byte issuer fingerprint)>.<base64url-no-padding(subject UTF-8)>
```

Values are reversible, canonical, single path segments of at most 218 ASCII
bytes. The subject bound is 128 UTF-8 bytes with no control characters. This
is an address-format bound; it does not replace the issuer's subject policy or
establish that the subject appears in any valid certificate. No normalization,
slash replacement, CN fallback or handwritten downstream codec is permitted.

An address is public data, not an authenticated principal. The authorizer must
derive its caller from the current actual mTLS leaf or the trusted managed
descriptor/owner composition. An address decoded from a request cannot be
promoted into that proof. Node, controller, session and durable managed-Agent
identities must remain distinct.

The legacy classifier verifies signatures and picks the first matching
anchor. Two renewed CA certificates using one key must therefore produce the
same address; complete-certificate DER is unsuitable as that input. Before
activation, native enrollment must reject an ambiguous key registered under
conflicting domains or grants, and current classification must detect an
already-conflicting anchor set rather than pick its iteration order. A new
authority key produces different addresses. Any continuity across that key
rotation needs an explicit native authority decision; deployment scripts cannot
alias the two generations themselves. The experimental transport entry now
derives the address from the actual TLS leaf and current anchors, rejects
conflicting matches instead of choosing their order, and requires exactly one
Nexus Agent SAN. It refuses Node, owner/session and user-runtime credentials,
nonempty bearer tokens and runtime-delegation carriers. Its authenticated result
has no public constructor or deserializer. A required native current-authority
check runs on each admission; there is no default allow policy. In particular,
the old cluster-only CRL projection cannot satisfy foreign revocation policy.

Certificate-only fixtures prove signature/SPKI/address and refusal rules. A
separate real tonic/rustls connection checks the composed admission against a
real Raft space store, then rejects later requests on that same channel after
space revocation, current-policy denial and foreign-anchor removal. Its current
certificate-policy callback is a test stand-in, not a foreign-CRL implementation;
its Ping carrier performs no collaboration data operation or mount activation.
Parsing a public certificate alone is deliberately a private helper, not an
authentication entry point.

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

The initial experimental `SpacePolicy` fixes its version, opaque space ID,
hosting SPKI authority, non-reserved replicated zone, sorted unique set of 2..64
canonical Agent members and a half-open validity interval. Members explicitly
grant pairwise collaboration inside that space. Both participants must be in
that grant, and the actual caller must be one of those two: a third authorized
space member still cannot read their pair. Reader read/write/lock/unlock is
restricted to that caller's own leaf. Transcript verbs are read and append;
generic replacement, rename, copy, deletion or an operation wildcard is not
implied. Host and routed-zone mismatches refuse local creation.

`RaftSpacePolicyStore` is a typed view over the existing replicated control
store's `collaboration` namespace. Host/membership records are immutable CAS
inserts. Identical requests reconcile to the same policy; conflicting bindings
refuse. A space revocation is an irreversible tombstone, including when it wins
before an in-flight create. Changes need a new space ID. Policy and revocation
are read together at one consensus read point, never as unrelated cached gets.
Ambiguous mutation responses remain Unknown and do not trigger a second proposal.
These storage primitives are trusted composition-root methods, not Agent RPCs.
`SpaceManagementService` exposes the native management boundary through the
existing context-aware Kernel Call service, without another HTTP/IPC protocol.
It refuses Open/NoAuth construction and separately requires the resolved local
Node subject, canonical Node identity and native system/admin flags on every
call. A plain system/admin context, foreign Agent or owner/session is insufficient;
request bodies cannot supply the caller. DTOs reject unknown fields. Once a
mutation is attempted, errors remain typed Unknown and read-only reconciliation
does not resubmit it. Its capability is `managementVersion:1, dataPlaneVersion:0`:
confirmed control state is not a usable collaboration route or delivery.

Native profile installation of that management service, a verified authority-to-endpoint routing
record, whole-zone capability/readiness checks and the native permission-provider
wiring remain activation gates. A deployment manifest cannot declare that the
remote host granted permission or choose an arbitrary forwarding endpoint.

Current authorization applies to new admissions and queries on a previously
established TLS channel. A revocation ordered before an admission refuses it.
An already admitted operation may finish: the control-zone read does not order
revocation atomically through a later data-zone append. Claiming drained/quiescent
revocation would additionally require the actual worker fence. Receipt recovery
is another current admission, not permission to replay the write. Foreign-CRL
distribution and offline/live issuer writers must be integrated before enabling
this path; a callback returning `()` is not that implementation.

## Data plane and compatibility

New joining authorities use a collaboration-only trust purpose, not the old
global foreign-mailbox recognition route. The existing foreign-CA store owns
this purpose too: its versioned scoped envelope omits the old decoder's
required root fields, so an older binary cannot silently ignore a new scope
field and newly install the CA with legacy permission. The legacy encoding
and existing local/foreign mailbox semantics remain available for their
existing explicit trust configuration. Scoped roots are refused by ordinary
foreign identity resolution even if a same-key legacy alias appears first.
The versioned collaboration authenticator still needs its independent space
grant and current-authority policy; recognition is not access.

This is not an in-place downgrade guarantee for a CA previously installed as
legacy: an older daemon may retain an earlier cached trust set after a decode
error. All serving nodes must advertise the current scope/admission capability,
and any previous legacy registration must be explicitly reconciled before
activation. No profile/old RegisterForeignCa method installs a scoped grant in
this slice. Open/NoAuth remains unprotected and cannot host the new family.
The native VFS resolver reclassifies a long-lived TLS leaf against current
roots even when the foreign set becomes empty; removing the last anchor must
not turn an old foreign leaf into a local identity.

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
canonical sender from trusted context. This foundation does not change the old
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
