# Native caller-owned Agent credential operations

The experimental `auth csr` commands are a thin operator interface to the
shared `raft::agent_csr_client` implementation. Build the cluster profile with
`experimental-managed-agent-csr`. The command uses the existing local Node
certificate/key and public CA under `--data-dir/tls`; it never reads a CA
private key, opens an offline auth store, starts a daemon, or searches other
issuers when the explicit endpoint fails.

The native deploy adapter must resolve the real managed Agent and owner through
its owner-checked host before calling this Node-privileged interface. CLI
arguments are the operator's request, not a substitute for that resolution.
Use owner-controlled storage for the pending document and versioned bundle.

```sh
nexusd-cluster --data-dir /native/node-data auth csr prepare \
  --endpoint https://127.0.0.1:22141 --agent ACTUAL_AGENT --owner ACTUAL_OWNER \
  --operation ORIGINAL_OPERATION --pending-file /private/operations/agent.json
```

`prepare` checks the actual Node role, remote version-1 capability and pinned
issuer, then persists and syncs a new P-256 key and original request. It sends
no issue RPC. An existing/partial document refuses; it is never replaced.
Capability support alone does not establish store readiness or permission.

Use the same binding, display name, operation and pending path for subsequent
commands:

- `query` performs one read-only observation. It validates the response binding;
  a finalized observation also verifies CA/signature/time, identity and the
  original key. `not_observed` is not proof that an older proposal cannot apply.
- `issue` submits that exact existing request once. It may explicitly finish
  the same committed I/F; it never prepares another key or operation, retries
  an ambiguous request, queries as a fallback, or adopts a legacy name.
- `publish --bundle-dir /private/bundles/VERSION` queries without issuing, then
  publishes only a verified final certificate in the existing `AgentCredential`
  format, manifest last. It does not activate a managed runtime.

Transport loss after an issue attempt is `unknown`, with the original document
retained. Query/validation/publication errors also retain it. Machine receipts
state `outcomeScope: this_command`; a `not_submitted` command cannot erase an
earlier ambiguous operation. An exit code, missing/truncated output or a queued
command is never delivery or absence proof. Consumers must inspect the typed
receipt and preserve uncertainty, especially after a submitted issue.

Receipts contain public identity/hash/path/state information. They never carry
the private key, raw pending document, credentials or synthetic model history.
The feature remains separate from collaboration grants, trust installation,
native runtime identity binding and the final domain join.
