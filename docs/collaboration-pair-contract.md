# Native pair attachment contract (source preparation)

This is the native contract consumed by SudoCode issue #1479. It does not
activate the data plane: current `collaboration.capabilities_v1` continues to
report `dataPlaneVersion: 0`. A description is public data, not a live attachment,
grant, completed provision, peer presence or delivery receipt.

The source API is `a2a::collaboration_pair` and the actual TLS composition is
`transport::collaboration_access::SpaceAuthorizer`. Both remain under the existing
`experimental-domain-join` feature. No separate issuer, CRL store or scheduler is
introduced. Existing local conversations and the reserved namespace are unchanged.

## Inputs and exact public description

`PairRequest::decode` accepts only `version: 1`, one existing `space`, and one
canonical native `AgentAddress::segment()` in `peer`, within 1024 bytes. The
request does not name its caller, a host/zone, an arbitrary path or reader owner.
`SpaceAuthorizer::authorize_pair` authenticates the original TLS Agent, reads
the current policy once, and uses the actual serving authority and routed zone.
Missing/currently revoked authority or policy fails through those existing paths.

`PairIntent::Describe` requires transcript-read and own-reader-read admission.
`PairIntent::Provision` additionally requires transcript-append and own-reader-write
admission. It never grants a write to an existing peer reader. The resulting
`AdmittedPair` has private construction and retains the authenticated actor and
intent; a decoded description cannot construct it.

`PairDescription::encode` carries `version`, `space`, `hostAuthority`,
`replicatedZone`, two canonically ordered `participants`, `actor` and
`policyDigest` (BLAKE3 of the complete canonical encoded immutable policy).
The public codec transmits no writable path. `conversation()` and `own_reader()`
derive paths through the existing native codec. CA-DER registration/selected TLS
anchor pins remain distinct from address SPKI pins and must be checked by the
native attachment; this description does not replace them. A consumer compares
the description against its independently admitted native binding, never against
another copy of the same network response. Matching values are not current grant
or current-channel proof.

`SpaceAuthorizer::discover_pairs` accepts one explicitly selected known space.
It checks the actual Agent and one current policy, then returns only pairs that
contain that Agent. It cannot list other pairs or global Agents. The result lists
possible granted pairs, not existing transcripts, current receivers or online
presence. The operator-provided space selection is not discovered by scanning
another party's `/agents` directory.

## Required adapter behavior

The following are the native adapter operations to implement; they are not
registered Call methods or available client APIs yet:

| Operation | Existing admission and required behavior |
| --- | --- |
| Describe pair | `authorize_pair(Describe)`; return the exact binding and actual provision/attachment state separately. |
| Provision pair | `authorize_pair(Provision)`; a native operation prepares one authoritative transcript and discovery entries for that pair only. Preserve every existing reader/cursor and transcript. Re-entry must not reset or overwrite them. Retain the original operation ID and reconcile ambiguous outcome without resubmission. |
| Discover known-space pairs | `discover_pairs`; filter provision/attachment facts under current admission. No caller writes both parties' legacy chat-list links. |
| Transcript metadata/read | Same exact pair and current `ReadTranscript` admission; route to the one authoritative replicated zone. Metadata is not an arbitrary Stat/Readdir escape hatch. |
| Transcript append | Current `AppendTranscript`, canonical authenticated sender stamping, original envelope/delivery ID and actual framed append. Preserve Unknown and original append reconciliation. |
| Own reader read/commit/lease | Existing `ReadOwnReader`, `WriteOwnReader`, `LockOwnReader`, `UnlockOwnReader`; retain original cursor and lock lifetime/renewal behavior. No other reader mutation. |

Data operations remain typed Kernel/VFS operations. Generic Call is the existing
control/service surface, not an alternate filesystem implementation. A future
management/attachment service must compose the native admission and backend; it
must not treat arbitrary JSON `ctx`, a Node credential or a generic `Write` as the
Agent's authorization. Admission alone does not establish atomic revocation
through operation completion: original storage ownership, current authority,
content-policy and response/withdrawal fences remain required.

The consumer must replace the collaboration branch of `ensure_conversation`
with native provision/readback. It must not run the legacy two-party mkdir/link
sequence under the new path prefix. `ensure_presence`, enumeration and receive
must use the same attachment and explicitly scoped discovery; discovery is not
presence. Keep original `node.json`, local Kernel, Agent/SID, files, model routes,
history, local conversations, operation IDs and reader custody.

## Capability, artifacts and acceptance

`require_pair_capability` refuses absent/version-0, partial and future-unknown
capabilities. The proposed complete version is `dataPlaneVersion: 1` plus
`pairContractVersion: 1`. Parsing this declaration does not authenticate it or
prove a deployment. No current service advertises that pair. Only the completed
native profile may do so after every serving node enforces the full contract.

Required matched artifacts are the broker, local-Box adapter and existing
SudoCode consumer at exact reviewed source/payload hashes, plus actual profile
capability/current-authority receipts and retained v0.8.26 store/service
compatibility. SW1 owns current issuer/CRL composition; Root owns this native
adapter/profile; Private coordinates #1479; SW3 owns rollout. No new actor,
customer Node, CA wildcard, remote managed backend or Stack proxy is permitted.

Final acceptance is the actual existing requester session and Ji Ye session
through the same broker, with fresh both-endpoint attachment evidence and one
independently initiated nonce per direction. Record authenticated delivery IDs,
cursors, responses and actual bounded model calls/usage. Model-free transport
tests or an echo controller cannot replace the existing runtime journey.
