# Nexus — VFS + Rust Core (trimmed)

Trimmed fork of [`nexi-lab/nexus`](https://github.com/nexi-lab/nexus) with the
Python codebase, Docker/k8s stack, docs, and benchmarks stripped out. What
remains is the Rust core workspace and the standalone FUSE daemon.

## Layout

```
rust/                       # cargo workspace (9 crates)
├── contracts/              # tier-neutral types/traits (zero deps)
├── lib/                    # pure-Rust algorithms + transport primitives
├── kernel/                 # in-tree Rust API surface, VFS gRPC stubs
├── backends/               # ObjectStore drivers (local, S3, GCS, …)
├── services/               # post-syscall services (audit, agents, tasks)
├── transport/              # VFS gRPC server (:2028) + federation client
├── raft/                   # Raft consensus + embedded redb storage
├── profiles/cluster/       # nexusd-cluster binary
└── nexus-cdylib/           # Python wheel cdylib (nexus_runtime.so)

nexus-fuse/                 # standalone FUSE daemon (separate workspace)
proto/                      # only the .proto files Rust build.rs reads
scripts/protoc-compat.py    # PROTOC shim for raft-rs protobuf-build 0.14
```

## Build

```bash
# Full Rust workspace
cargo build --release --workspace

# FUSE daemon (separate workspace)
cd nexus-fuse && cargo build --release
```

Toolchain: `stable` (see `rust-toolchain.toml`).

## What was removed

Python source (`src/`), Alembic migrations, `pyproject.toml`/`uv.lock`,
Dockerfiles/compose, k8s charts, observability, MkDocs, Python tests and
benchmarks, the `buf` Python proto pipeline, `.github/` workflows, and
the `nexus-bench` crate. See git history for the trim commits.

The workspace `[patch."https://github.com/nexi-lab/nexus"]` entry is
retained because the `sudocode` git-dep transitively references
`nexi-lab/nexus`; the patch redirects it to the local `rust/kernel` path.

## License

Apache-2.0 — inherited from upstream. See `LICENSE`.
