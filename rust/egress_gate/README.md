# Live egress policy

The existing `egress_gate` service supports a deployment-owned JSON policy file.
Set only `NEXUS_EGRESS_GATE_CONFIG` to its absolute path. The shared document,
administration storage, validation and delivery helpers live in
[`sudostack`](https://github.com/sudoprivacy/sudostack/tree/main/packages/egress-policy).
Moss owns the authenticated management API and UI. Cloud defaults to disabled.

The gate loads the initial policy during service installation. A malformed or
missing initial file aborts boot. It reads replacements before eligible writes
and the read-only `egress_gate.get_policy_status_v1` Call. The hook remains
registered while policies change; the classifier and policy change together.
An admitted replacement must increase its revision. Each already admitted write
retains its policy snapshot until it finishes.

The deployment must atomically replace the file and keep it outside agent-writable
workspaces. Kubernetes installations project the controller-owned configuration
Secret read-only. Agents have no policy mutation RPC. Status reports applied
revision, mode, switch, mounts and configuration errors, without business values.
The existing authenticated transport determines which runtime a caller can reach.

If a replacement is invalid, missing or rolls back its revision, writes on the
last policy's configured planes are refused and status reports the failure.
Unrelated paths retain their existing behavior. The last admitted policy is not
silently replaced by an empty or disabled policy. Local GPU mounts must be omitted
from the outbound planes.

An optional analyzer uses loopback. Runtime business policy travels with that
classification request, independently of the model request's contents. The
shared analyzer applies it per request and keeps deployment protections in force.
Business policy requires the analyzer; unsupported provider settings fail policy
admission instead of dropping recognition.
