# Node deployment operations

`NexusNodeOperatorClient` uses the same generated protocol, TLS dialing and
typed transport errors as the existing clients. It exposes Node-gated
session-minter and replica controller RPCs. A JS class
does not prove Node authority; the real daemon authenticates and authorizes
the current credential on each operation. No admin methods were added to the
agent-facing client and no server permission was widened.

Keep the operator configuration and Node key on the device, outside the Moss
process. Moss continues using its own low-privilege controller credential and
the native owner-bound session-mint/renew path. This command configures an
existing minter; it issues no certificate, creates no Agent and changes no model.

```sh
nexus-node-operator list-session-minters /private/operator.json
nexus-node-operator ensure-session-minter /private/operator.json edge-moss
```

The private JSON has `endpoint` and the ordinary `tls` config (`ca`, `cert`,
`key`, optional `serverName`), as existing paths or in-memory PEM values. The
CLI requires an owner-only configuration on Unix. Never put credentials in
arguments, logs or deployment receipts. Obtain native binary/client artifacts
from a pinned source and bind the deployment receipt to their hashes.

Ensure first reads the current list. If present, no mutation is sent. Otherwise
it makes one allow attempt and reads again. A lost response followed by observed
presence records the original mutation response as `unknown`, including its
diagnostic; the read proves the current state, not which writer established it.
Missing state or failed reconciliation throws `NexusOperatorOutcomeUnknown`
with both available errors. No mutation is automatically retried. Revocation
is an explicit separate operator decision; never remove a preexisting grant as
an automatic deployment rollback.

Scripted mTLS tests exercise the client transport and reconciliation behavior.
The existing `test:zone-api-live` CI route builds the current daemon and checks
Node-versus-Agent authorization through its actual control store. Product
acceptance also exercises controller installation and session recovery.

## Replica controller calls

The trusted controller uses `controlReplica`, `issueReplicaCsr` and
`queryReplicaCsr` on `NexusNodeOperatorClient`. Each invocation makes one RPC.
Requests and responses retain the native field names. JSON contract fields are
opaque `Uint8Array` bytes, and renewal proof timestamps are canonical decimal
strings spanning the full native `uint64` range. The client copies request bytes
before waiting for a connection and returns the complete native outcome state.

Before submitting a mutation, the controller durably retains the original
request, operation IDs, CSR proof and authenticated storage association. An
uncertain CSR attempt is queried with the same request. Control mutations are
reconciled by selecting `reconcile_binding_json` or `reconcile_issuer_json`
with the original JSON bytes. `Unknown`, `NotObserved` and `Refused` preserve
that original operation for recovery. Current native authorization and durable
binding checks govern readiness; the controller verifies returned credentials
before installation.

`npm run package:operator -- /absolute/new-runtime.tgz` builds a portable
runtime archive from clean producer source. It includes the normal compiled
SDK, canonical CLI and exact lockfile-installed production dependencies, with
per-file/source hashes and an adjacent archive receipt. The target runs
`node runtime/bin/nexus-node-operator.mjs ...` without npm or a compiler. Its
private operator config stays outside the archive. This packaging selects no
service, changes no grants and publishes nothing to an npm registry.
