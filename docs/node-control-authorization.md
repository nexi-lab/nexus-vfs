# Node control authorization

The cluster listener can admit domestic and registered foreign Agent
certificates for cohosted VFS services. Passing that TLS handshake does not
authorize a Raft proposal or a local credential/trust administration operation.

On a TLS-enabled listener, `RaftGrpcServer` wraps both `ZoneTransportService`
and `ZoneApiService`. Before decoding the RPC payload, it verifies the actual
connection's leaf against the configured **local cluster CA**, checks current
certificate validity, and requires exactly one canonical Nexus Node URI SAN.
`RaftWitnessServer` uses the same boundary. New control methods default to this
Node-only policy. Registering a foreign CA cannot confer local Node authority,
even if its issuer name and Node SAN match local values.

The four delegated credential methods (`MintSessionAgent`, `MintUserRuntime`,
`RenewSessionAgent`, `RevokeAgentCert`) retain their native issuer allow-list
and ownership checks. Excluding these routes from the Node wrapper does not
authorize issuance. The local issuer/admin implementations independently use
the same local-CA/Node verifier, including the Node branch of revocation.
The separate token-gated enrollment listener and cohosted VFS routes keep
their existing authorization boundaries.

An explicitly plaintext development listener retains its previous behavior;
it is not a protected cross-domain host. This change does not introduce Node
CRL distribution, consensus membership authorization, or foreign Agent
revocation policy. Those are separate contracts; a valid local Node remains
a cluster control principal.

`raft/tests/node_rpc_boundaries.rs` uses isolated real mTLS and a one-voter
Raft store. It checks an authorized Node proposal, refusal without mutation
for domestic Agents, foreign Agents and foreign Nodes, refusal before Raft
message parsing, and preservation of the delegated issuer door. The cluster
profile regression invokes the real local Agent issuer with a registered
foreign Node certificate. No live fleet node, trust registry or model is used.
