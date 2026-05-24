# Nexus — VFS + Rust Core (trimmed)

Trimmed fork of [`nexi-lab/nexus`](https://github.com/nexi-lab/nexus). The
Python codebase, Docker/k8s stack, docs, benchmarks, agent connectors, and
the Python wheel cdylib are stripped out. Upstream's 9-crate workspace is
consolidated into 3 crates.

## Layout

```
rust/                       # cargo workspace (3 crates)
├── nexus-core/             # contracts + util + kernel + backends + services
│                           # (was 5 separate rlib tier-crates upstream)
├── nexus-cluster/          # Raft consensus + VFS gRPC server/client + federation
│                           # (was raft + transport upstream)
└── nexusd/                 # daemon binary — `cargo install`-able entry point

nexus-fuse/                 # standalone FUSE client (separate workspace)
proto/                      # .proto files used by nexus-core + nexus-cluster build.rs
scripts/protoc-compat.py    # PROTOC shim for raft-rs's protobuf-build 0.14
```

## Build & run

```bash
cargo build --release --workspace
./target/release/nexusd --no-tls --bootstrap-mode static --data-dir /tmp/nexus
# VFS gRPC :2028,  Raft federation :2126

# Optional FUSE client (Linux/macFUSE only)
cd nexus-fuse && cargo build --release
```

Toolchain: `stable` (see `rust-toolchain.toml`).

## What's served on the wire

| Endpoint | Service | RPCs verified |
|---|---|---|
| `:2028` | `nexus.grpc.vfs.NexusVFSService` | `Ping`, `Write`, `Read`, `Delete`, `Call` |
| `:2126` | `nexus.raft.ZoneApiService` | `GetClusterInfo`, `GetSearchCapabilities`, `JoinZone`, `Propose`, `Query` |
| `:2126` | `nexus.raft.ZoneTransportService` | `StepMessage`, `ReplicateEntries` (inter-node Raft) |

`Initialize` and `BatchRead` RPCs are declared in `vfs.proto` but the Rust
server returns `Unimplemented` — upstream wired these handlers only on the
Python side and the trim doesn't backfill them.

## What was removed

Python source (`src/`), Alembic migrations, `pyproject.toml`/`uv.lock`,
Dockerfiles/compose, k8s charts, observability, MkDocs, Python tests and
benchmarks, the `buf` Python proto pipeline, `.github/` workflows, the
`nexus-bench` crate, the `nexus-cdylib` Python wheel cdylib (along with its
`sudocode` git-dep), the 8 agent connectors in `backends/` (OpenAI,
Anthropic, GDrive, Gmail, Slack, X, HN, CLI), and raft's auxiliary
`nexus-witness` / `nexus-federation-server` binaries.

## License

Apache-2.0 — inherited from upstream. See `LICENSE`.
