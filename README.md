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
