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
