# `rust/profiles/` — deployment binary crates

Each subdirectory here builds one production binary. The profiles are structured
as a **library plus thin binaries** so binary variants can add per-deployment
features without duplicating dependency declarations.

## Layout

```
profiles/
├── cluster/                # nexusd-cluster — the base runtime
│   ├── Cargo.toml          # [lib] name = "nexus_cluster"
│   │                       # [[bin]] name = "nexusd-cluster"
│   └── src/
│       ├── lib.rs          # pub fn run() — clap parsing, tokio runtime,
│       │                   #   subcommand dispatch, all wiring code
│       ├── main.rs         # 3 lines: nexus_cluster::run()
│       └── auth_posture.rs # sk- credential policy (with unit tests)
└── full/                   # nexusd-full — cluster + S3/R2 object-store driver
    ├── Cargo.toml          # depends on nexus-cluster; opts backends into driver-s3
    └── src/
        └── main.rs         # 3 lines: nexus_cluster::run()
```

## Confined user runtime

`nexusd-cluster --data-dir <user-volume> --bind-addr <address> serve-user
--owner <owner-id> --credential <bundle-directory>` runs the same Kernel and
service declarations under one fixed owner's delegated mTLS identity. The
external issuer supplies the standard `AgentCredential` bundle. The certificate
must have the owner's runtime server name and a lifetime of at most 300 seconds.

The runtime opens a local root Raft zone without a peer/control-plane listener.
Namespace metadata, WAL transcripts, files and the owner/volume binding are
durable. Raft keeps its normal persisted node ID and ConfState. Credentials,
channels and execution state are not saved in the VFS metastore. The process has
no cluster CA private key, signing service, enrollment listener or operator token.

The issuer coordinator replaces the mounted bundle using an atomic directory
projection. The runtime validates the unchanged trust root and owner before
installing a new TLS identity. Requests on established connections and new TLS
connections stop when the current credential expires; a later valid replacement
restores service. This mode is also available to binaries composing
`run_with_services`, including the in-process SudoCode adapter. Pod placement,
credential delivery and renewal remain the control plane's responsibility.

## Adding a new dependency

Add it to **`profiles/cluster/Cargo.toml`** only. It flows to every binary
that consumes `nexus-cluster` transitively (currently just `full`, but any
future profile like `nexusd-edge` would inherit automatically).

Do **not** add the dep to `profiles/full/Cargo.toml`. If you find yourself
mirroring a dep between the two, stop and treat it as a signal that the
`nexus_cluster::run` seam is wrong — extend the seam or move the dep to
cluster.

## Adding a new deployment variant (e.g. `nexusd-edge`)

1. `mkdir rust/profiles/edge/src`
2. `rust/profiles/edge/Cargo.toml`:
   ```toml
   [package]
   name = "nexus-edge"
   ...

   [[bin]]
   name = "nexusd-edge"
   path = "src/main.rs"

   [dependencies]
   nexus-cluster = { path = "../cluster" }
   # Delta from cluster — e.g. an alternative backends set:
   backends = { workspace = true, default-features = false,
                features = ["driver-in-memory"] }
   anyhow = "1"
   ```
3. `rust/profiles/edge/src/main.rs`:
   ```rust
   fn main() -> anyhow::Result<()> {
       nexus_cluster::run()
   }
   ```
4. Add `"rust/profiles/edge"` to the workspace `members` in the root
   `Cargo.toml`.

## Adding a new `backends` driver used only by `full` (not `cluster`)

Because Cargo unifies features across the workspace per-crate-invocation, the
delta lives in `profiles/full/Cargo.toml` alone:

```toml
[dependencies]
nexus-cluster = { path = "../cluster" }
backends = { workspace = true, default-features = false,
             features = ["driver-s3", "driver-<new-driver>"] }
```

`cargo tree -p nexus-cluster | grep backends` should still show only the
drivers cluster's own Cargo.toml lists. `cargo tree -p nexus-full | grep
backends` should show the union.

Do **not** add a `driver-<name>` feature to `profiles/cluster/Cargo.toml`
just because full needs it — that would leak "cluster knows about this
driver" into every reader of cluster's manifest.

## Non-goals

- **This is not a plugin loader boundary.** dylib plugins ship via
  `--plugin-dir` at runtime; per-binary Cargo features are compile-time.
- **Do not add per-tenant configuration here.** Runtime posture (auth
  policy, mount config, federation topology) is env-var / CLI-driven —
  see `profiles/cluster/src/lib.rs`.
