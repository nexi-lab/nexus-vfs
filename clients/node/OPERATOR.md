# Node deployment operations

`NexusNodeOperatorClient` uses the same generated protocol, TLS dialing and
typed transport errors as the existing clients. It exposes the three existing
Node-gated session-minter RPCs separately from `NexusZoneApiClient`. A JS class
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

Scripted mTLS tests qualify the client transport and reconciliation behavior.
Actual Node-versus-Agent authorization, real existing-controller minting and
product session recovery still require a native daemon acceptance case.
