// Round-trips against a live nexusd from inside a BUNDLE — the shape a
// consumer actually ships, talking to the server it actually talks to. Offline
// tests cannot tell a definition that is merely well formed from one that moves
// bytes correctly, and a bundler can break what a plain `node` run resolves
// fine, so this covers both at once for the price of one binary download.
//
// It does NOT reproduce the protobufjs 7.5.4 failure behind this package's
// version floor: that one passes here and only appears inside moss's
// dependency tree. Downstream end-to-end remains the guard for that class.
//
// Not a node:test file: it is the entry a bundler is pointed at. Exits non-zero
// on failure so a CI step fails on it.
import { NexusVfsClient } from '../dist/index.js'

const endpoint = process.env.NEXUS_VFS_ENDPOINT
if (!endpoint) {
  console.error('NEXUS_VFS_ENDPOINT is required')
  process.exit(2)
}

function check(condition, what) {
  if (condition) {
    console.log(`ok   ${what}`)
    return
  }
  console.error(`FAIL ${what}`)
  process.exitCode = 1
}

const client = new NexusVfsClient(endpoint, { connectTimeoutMs: 30_000 })
try {
  const info = await client.serverInfo('')
  check(Boolean(info.version), `typed RPC: server reported version ${info.version}`)

  // `ping` shipped for months routed through the generic `Call` surface,
  // which carries no `ping` method — every call answered `unknown Call
  // method: ping`. Offline tests could not see it (they mock the channel),
  // so assert it against the real daemon.
  const pong = await client.ping('')
  check(pong === info.version, `ping answers from the live daemon (${pong})`)

  // The generic dispatch path, which is what the empty-status failure hit.
  const mounts = JSON.parse(await client.call('get_mount_points', '{}', ''))
  check(Array.isArray(mounts.result), 'generic Call returned a result array')

  const path = `/live-bundled-${process.pid}.bin`
  const content = Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x80])
  await client.write(path, content, '')
  const read = await client.read(path, '')
  check(read.equals(content), 'non-UTF-8 bytes survived a write/read round-trip')

  await client.delete(path, '')
  let deleted = false
  try {
    await client.read(path, '')
  } catch {
    deleted = true
  }
  check(deleted, 'the path is gone after delete')
} catch (error) {
  console.error('FAIL unexpected error:', error?.message ?? error)
  process.exitCode = 1
} finally {
  client.close()
}
