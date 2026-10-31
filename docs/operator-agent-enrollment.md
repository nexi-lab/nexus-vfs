# Operator-granted Agent enrollment

`nexus-agent-enroll` is a single-destination client of the
existing Node-mTLS-gated `nexus.raft.ZoneApiService/MintAgent` RPC. It can use an
older daemon that already exposes that RPC. It neither starts a daemon nor
opens its data store, loads a CA private key, signs offline, searches peers or
uses `allow_existing`. The existing server verifier, minter and replicated name
claim stay authoritative. This is not the experimental managed-CSR lifecycle.
The operator-only entry cannot start a daemon. Build it with
`cargo build --release -p nexus-cluster --bin nexus-agent-enroll --features operator-agent-enrollment`.
Default daemon builds exclude the operator module; both entries still reuse the
same existing TLS loader, RPC client and bundle writer. CI publishes the client
separately with its feature in the artifact name and applies the same unchanged
per-platform size cap. It does not replace the running Node executable.
Future normal release archives carry both distinctly named executables under
the existing archive checksum; a client-only installation copies only the
operator entry and leaves the selected running Node intact.

The real-process journey in `scripts/e2e/operator_agent_enrollment.py` is shared
by Cargo's all-features integration test and the optimized Windows binary CI
job. It exercises actual Node-mTLS MintAgent issuance, persisted credentials,
exact local receipt replay, concurrent requests, preflight refusals and Unknown
across a private Node restart. Windows runs the built release executables and
retains a source/binary-hashed receipt and raw logs. Build/`--help` checks alone
do not qualify that journey. The runner requires Python 3.9 or newer and removes
its own private Node keys/database on either outcome.

An operator prepares policy explicitly, without minting:

```sh
nexus-agent-enroll --data-dir /absolute/existing-box \
  --initialize --grant /absolute/private/node-grant.json \
  --endpoint https://selected-issuer:2126 --workspace-root /absolute/workspaces
```

Repeat `--workspace-root` for additional authorized subtrees. Paths use native
platform syntax, including absolute Windows drive paths. The selected data
directory supplies the existing Node mTLS identity. Policy pins that leaf's
SHA-256 DER fingerprint and cluster CA fingerprint, the exact HTTPS destination,
the allowed workspace subtrees and a private client-state directory. There is
no default wildcard grant. Existing files are never overwritten. Store the
grant/state beneath an operator-controlled private directory, not a repository
or a peer-writable mount. The common owner-only persistence helper protects new
records on Unix and Windows. Possession of the Node credential is verified by
the server; a caller-supplied owner name is never authentication.

The command accepts one JSON claim on stdin, bounded to 8 KiB:

```json
{"version":1,"actor":"codex-0123456789abcdef0123456789abcdef","operationId":"00000000-0000-4000-8000-000000000001","threadId":"00000000-0000-4000-8000-000000000002","workspace":"/absolute/workspaces/project"}
```

Invoke `nexus-agent-enroll --grant /absolute/private/node-grant.json`.
Only `codex-` followed by 32 lowercase hex digits is permitted. The canonical
workspace must lie beneath an explicitly granted canonical subtree. The local
Node leaf and CA must still match their pins. Endpoint, key paths and authority
are never accepted from the claim. Changing an owner/CA or grant is an explicit
operator action; this command does not discover or adopt a replacement.

Before opening the channel, an exclusive owner-only synced attempt record
reserves the original actor/operation/request/target. At most one invocation
can submit MintAgent for that actor. A completed local result replays the
original bundle reference; another operation or an incomplete attempt requires
operator recovery. Concurrency never enables another RPC. RPC failure, refusal,
response loss, persistence failure or a crash after reservation is **Unknown**,
even when a particular connection error appears likely to precede submission.
No retry, fallback, new actor or new operation is elected. Absence of a result
does not prove that the replicated name claim was not committed.

On success stdout contains only a bounded public receipt:

```json
{"version":1,"actor":"codex-0123456789abcdef0123456789abcdef","operationId":"00000000-0000-4000-8000-000000000001","credentialDirectory":"/absolute/existing-box/agents/codex-0123456789abcdef0123456789abcdef"}
```

The standard credential writer persists the existing bundle layout; leaf keys
remain in its existing owner-only credential store. No Node/CA private key or
PEM is returned. Before reservation, validation may return
`{"outcome":"not_submitted","detail":"..."}`. After reservation it returns
`{"outcome":"unknown","detail":"..."}` on failure. These outcomes concern
the current invocation and never erase an earlier Unknown operation.

The SDK operator adapter owns the subsequent private ACP workspace/profile and
one saved SID. It receives a leaf-bundle reference, not issuance authority. Its
multi-stage recovery remains conservative even if this inner command refuses
before an RPC. Current server authorization/revocation still governs use of
the leaf; a replayed local receipt is not proof of current authorization.
