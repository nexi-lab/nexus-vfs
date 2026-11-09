# nexus-vfs

Rust VFS kernel workspace extracted from the [nexus](https://github.com/nexi-lab/nexus) monorepo.

## Crates

| Crate | Path | Description |
|-------|------|-------------|
| `contracts` | `rust/contracts` | Types, enums, constants (zero deps) |
| `lib` | `rust/lib` | Algorithms + transport primitives |
| `transport` | `rust/transport` | gRPC transport layer |
| `kernel` | `rust/kernel` | VFS kernel (syscalls, metastore, drivers) |
| `backends` | `rust/backends` | Storage backend implementations |
| `raft` | `rust/raft` | Raft consensus for federation |
| `nexus-cluster` | `rust/profiles/cluster` | Standalone cluster binary (`nexusd-cluster`) |

## Build

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace
```

## Option B: In-process Cargo git dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
kernel = { git = "https://github.com/nexi-lab/nexus-vfs", default-features = false }
```

This compiles the kernel as an rlib linked directly into your binary --
no gRPC, no subprocess. The consumer changes only the git URL.

## Option C: gRPC subprocess (production default)

Build and run `nexusd-cluster`:

```bash
cargo build --release -p nexus-cluster
./target/release/nexusd-cluster --help
```

The Python app layer connects via gRPC (`RPCTransport`).

For explicitly authorized Codex A2A enrollment, the
[operator Agent enrollment contract](docs/operator-agent-enrollment.md) describes
the single-endpoint Node client, private grants and Unknown recovery. It reuses
the installed daemon's MintAgent RPC without starting or replacing that daemon.

### HTTP search and relationship authorization

Build `cargo build --release -p nexus-cluster --features http-api` and run the
daemon with `--enable-rebac --http-addr 127.0.0.1:2026` alongside its usual
cluster and signed Search plugin configuration. The `rebac` feature can also be
built on its own for gRPC deployments. `NEXUS_REBAC_ENABLED=true` and
`NEXUS_HTTP_ADDR=127.0.0.1:2026` are the corresponding environment settings.

ReBAC enforces file grants for ordinary callers; administrators and system
operations retain their authority. `/v2/rebac/tuples` manages the same replicated
tuples that the kernel and Search result filter read. Successful grant/revoke
responses wait for the local replica to apply the committed change. Other
replicas enforce their locally applied state as replication progresses.

HTTP clients send `Authorization: Bearer <key>`. Credentials in JSON bodies or
query strings are rejected. Paths are canonical VFS paths, including configured
mounts such as `/docs`. The loopback HTTP listener is intended to sit behind a
TLS reverse proxy; its outbound gRPC connections use the daemon's cluster CA and
node certificate while preserving the bearer caller's identity.

For a separately hosted browser console, set
`NEXUS_HTTP_ALLOWED_ORIGINS=https://console.example.com,http://localhost:5173`.
The listener validates this list at boot and matches complete origins. Empty
configuration leaves cross-origin access disabled; wildcards, credentials and
URLs containing paths, queries or fragments are rejected. Allowed origins can
preflight bearer/JSON requests and read authentication errors and revision
headers. CORS does not authenticate requests or replace OAuth browser binding
and CSRF checks. The ordinary credential, readiness and authorization gates
still apply to every actual API call.

Cross-zone queries support query type, result limit, and one path prefix. Pin
`zone_id` to use additional ranking, chunk, or path-filter options; unsupported
cross-zone options return HTTP 400.

Plugin unload removes registration and closes service instances after active
calls finish. Library code remains mapped until process exit so dependency
threads and thread-local destructors can finish safely. Restart the daemon to
replace plugin binaries.

## Acknowledgments

We welcome **Zhuotao Liu** (Tsinghua University) as a contributor. The
cross-trust-domain signed-authorship design — agent identity certificates and
an unforgeable mailbox `from` that any consumer can verify without trusting the
ingress node — draws on **BlockA2A** (Zhenhua Zou, Zhuotao Liu et al.,
*BlockA2A: Towards Secure and Verifiable Agent-to-Agent Interoperability*,
[arXiv:2508.01332](https://arxiv.org/abs/2508.01332)).

- **Adopted:** the sign-and-verify identity model — a sender signs each message
  with its private key and any receiver verifies it against a resolvable public
  key (BlockA2A Protocol 2).
- **Realized on nexus primitives:** the raft log is the ordered, replicated,
  tamper-evident, strongly-consistent ledger; CA-signed X.509 certificates are
  the resolvable identity; and the kernel permission gate is the access control.
  This keeps intra-cluster operation strongly consistent with no external
  consensus, while leaving the path open to cross-organization (cross-CA) trust.


## Managed-agent durable session recovery

Agent registry mutations retain the exact registry incarnation authorized by
the request's ownership check. State updates, heartbeats, signals and removal
do not follow a PID that was reused while the request was in progress, and
responses do not read a replacement process's descriptor. This fence uses the
existing native `AgentInstance`; it does not change generic Call payloads.
External clients can opt into `Call("agent_register_external_v2")` with the
existing external registration fields. Its result includes an opaque
`incarnation`, allocated by the same native registry insertion as the PID.
Keep it with that registration and send it alongside `pid` to `agent_get`,
`agent_update_state`, `agent_heartbeat`, `agent_signal`, `agent_unregister` and
`agent_unregister_external`. Delayed tokens refuse a reused PID even when the
owner, Agent name and connection ID are unchanged. Missing or malformed tokens
cannot downgrade a v2 registration to a PID-only operation. Owner authorization
still applies; an incarnation is not a credential. Owner-filtered `agent_list`
returns each current v2 registration's incarnation from the same snapshot.
Managed-session reads and controls refuse external registry entries.
Legacy registrations retain their PID-only protocol. An older daemon refuses
the new registration method rather than silently registering an unfenced
process. These are node-local registry operations; independent CLI lifetime
ownership, typed observations and authorized cross-node routing remain separate
discovery work. No protobuf message changes are required for this Call contract.

Transient engine observations use the shared Rust contract in
`contracts::runtime_status`. The `agent_runtime_{register,publish,heartbeat,
unregister,get,list}_v1` Call methods preserve separate running instances of
one Agent or durable session. Their identity contains the registry's boot
scope, logical PID and the same native `AgentInstance` incarnation used above.
Runtime registrations require that incarnation on legacy operations too;
their immutable wire policy cannot be downgraded by omitting a token.
Registration retries additionally retain their admission intent, so a lost
response cannot make a caller adopt a replacement registration.

Foreground activity and background worker counts come from the engine's
read-only `RuntimeFacts` source through `RuntimeObservationHost`. The registry
owns observation revisions and expiry. Attendance (`online` or `unknown`) is
independent of fact availability (`fresh`, `stale`, `unsupported` or
`unavailable`). A heartbeat confirms attendance without refreshing old work
facts. An expired observation never implies idle work or a confirmed exit.
Neither transcript contents nor silence are an activity source.

`runtime_directory.list_v1` uses the existing authenticated Rust-service and
federation client to query coordinator-known peers. It retains the caller's
owner/zone scope, uses node mTLS rather than forwarding caller credentials,
and reports unavailable scopes separately from complete empty inventories.
Each registry remains authoritative for its own instances; this directory
does not replicate activity or grant process control. Its peer queries share
one bounded deadline. Unsupported or disconnected nodes remain explicit.

`managed_agent.start_session_v1` retains its existing `session_id` response:
this is the registry pid used by `get_session_v1`, `cancel_v1`, and `/proc`.
An in-process runtime can additionally return `durable_session_id`, the key of
its persistent transcript. `get_session_v1` exposes the same optional field.
Raw subprocesses and providers without durable sessions omit it.

Hosted controllers cancel a live attachment with `managed_agent.cancel_v2`,
passing `session_id` and the returned `session_endpoint.channel_id`. A retired
channel returns `cancelled: false` and leaves the current execution running,
even if a restart reused its PID. The existing channel generation is the
attachment identity; it is never persisted as a transcript ID. This method
retains the same delegated-owner authorization as the existing controls.

To restore a stopped co-hosted session, start the same agent with
`resume_session_id` set to the previous `durable_session_id`. The runtime owns
loading, identity checks and protection against concurrent writers. A successful
restore returns a new pid in `session_id` and the original durable ID.

The ID is a single path component (ASCII letters, digits, `_` and `-`, at most
128 bytes). Recovery is rejected for `spawn_spec`, a daemon without an
in-process provider, or a provider that has not implemented recovery. It never
silently falls back to a fresh session. Existing `SpawnTask` implementations
remain source-compatible: `spawn_with_options` defaults to ordinary `spawn`
when no recovery was requested, and rejects recovery otherwise.
