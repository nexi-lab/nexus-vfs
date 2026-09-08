# @nexus-ai-fs/vfs-client

Node client for the Nexus VFS gRPC service.

It is published from this repository so that the client and the server are
built from one service definition. `scripts/sync-proto.mjs` copies
`proto/nexus/grpc/vfs/vfs.proto` into the package at build time and the copy
is never committed, so there is exactly one editable `vfs.proto` in the tree
and no consumer can drift from it.

Pure JavaScript over [`@grpc/grpc-js`](https://www.npmjs.com/package/@grpc/grpc-js).
No native addon: installing needs no Rust toolchain, and an Electron consumer
needs no ABI rebuild per release.

## Installing

Published two ways by `.github/workflows/release.yml`:

- **npm** — `@nexus-ai-fs/vfs-client`, the same scope and registry as
  `@nexus-ai-fs/api-client`. Requires `NPM_TOKEN` on this repository; the job
  skips with a warning when it is absent.
- **Tencent COS** — a tarball at
  `https://sudowork-runtime-1309794936.cos.accelerate.myqcloud.com/nexus-vfs/clients/node/<version>/nexus-ai-fs-vfs-client-<version>.tgz`,
  the same bucket that already carries `nexusd-cluster` and the vault plugin.
  Needs no registry credentials, so a consumer can pin the URL directly:

  ```json
  "@nexus-ai-fs/vfs-client": "https://sudowork-runtime-1309794936.cos.accelerate.myqcloud.com/nexus-vfs/clients/node/0.2.4/nexus-ai-fs-vfs-client-0.2.4.tgz"
  ```

  Pin a version for a dependency. `.../clients/node/latest/nexus-ai-fs-vfs-client.tgz`
  is a stable name for whatever is current — for a drift check or a smoke test,
  not for a lockfile.

Both run on a tag and on `workflow_dispatch`.

## Usage

```ts
import { NexusVfsClient } from '@nexus-ai-fs/vfs-client'

// Plaintext, for a trusted-loopback `nexusd serve-local --no-tls`.
const client = new NexusVfsClient('127.0.0.1:2126')

await client.write('/notes/hello.txt', Buffer.from('hi'), authToken)
const bytes = await client.read('/notes/hello.txt', authToken)
const mounts = JSON.parse(await client.call('get_mount_points', '{}', authToken))

client.close()
```

Against an auth-on `nexusd-cluster`, which serves mutual TLS and rejects
plaintext clients:

```ts
const client = NexusVfsClient.withMtls('100.64.0.1:8443', {
  caPath: '/etc/nexus/ca.pem',
  certPath: '/etc/nexus/client.pem',
  keyPath: '/etc/nexus/client-key.pem',
})
```

The certificate authenticates the *process*. Caller identity still rides the
per-request auth token, so every method takes one.

## API

| Method | Purpose |
| --- | --- |
| `new NexusVfsClient(endpoint, options?)` | Connect (plaintext unless `options.tls` is set). Lazy — dials on first RPC. |
| `NexusVfsClient.withMtls(endpoint, tls, options?)` | Connect with mutual TLS. `tls.serverName` defaults to `nexus-node`. |
| `call(method, payload, authToken)` | Generic dispatch with a JSON payload; returns the JSON response. |
| `callBinary(method, payload, authToken)` | Generic dispatch with raw bytes, for protobuf plugin methods (`password-vault.*`). |
| `read(path, authToken)` | Read a VFS path; returns raw bytes. |
| `write(path, content, authToken)` | Write raw bytes to a VFS path. |
| `delete(path, authToken)` | Delete a VFS path. |
| `ping(authToken)` | Liveness through the generic dispatch path. |
| `serverInfo(authToken)` | Version, zone and uptime, from the typed `Ping` RPC. |
| `close()` | Close the channel. |

`endpoint` accepts `host:port` or a `http(s)://` URL.

An RPC that fails in transport rejects with `gRPC <op> failed: <details>`. An
RPC that reaches the server but fails there rejects with the server's error
payload verbatim.

## Development

```bash
npm install
npm run build        # syncs the proto, then compiles
npm test             # offline unit tests
npm run check-proto  # CI guard: fails if the packaged proto is stale

NEXUS_VFS_ENDPOINT=127.0.0.1:2126 npm run test:live
```
