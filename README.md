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

`managed_agent.start_session_v1` retains its existing `session_id` response:
this is the registry pid used by `get_session_v1`, `cancel_v1`, and `/proc`.
An in-process runtime can additionally return `durable_session_id`, the key of
its persistent transcript. `get_session_v1` exposes the same optional field.
Raw subprocesses and providers without durable sessions omit it.

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
