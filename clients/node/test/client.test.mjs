import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { DEFAULT_CLUSTER_SERVER_NAME, NexusVfsClient } from '../dist/index.js'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))

test('ships the service definition it was built against', () => {
  assert.ok(existsSync(join(packageRoot, 'proto', 'nexus', 'grpc', 'vfs', 'vfs.proto')))
})

test('loads the service and exposes the drop-in surface', () => {
  const client = new NexusVfsClient('http://127.0.0.1:1')
  for (const method of ['call', 'callBinary', 'read', 'write', 'delete', 'ping', 'serverInfo']) {
    assert.equal(typeof client[method], 'function', `${method} missing`)
  }
  client.close()
})

test('accepts a URL or a bare host:port target', () => {
  for (const endpoint of ['http://127.0.0.1:1', 'https://127.0.0.1:1', '127.0.0.1:1']) {
    const client = new NexusVfsClient(endpoint)
    assert.equal(client.target, '127.0.0.1:1')
    client.close()
  }
})

test('withMtls reports which PEM file is missing', () => {
  assert.throws(
    () =>
      NexusVfsClient.withMtls('https://127.0.0.1:1', {
        caPath: join(packageRoot, 'does-not-exist-ca.pem'),
        certPath: join(packageRoot, 'does-not-exist-cert.pem'),
        keyPath: join(packageRoot, 'does-not-exist-key.pem'),
      }),
    /read nexus CA certificate .*does-not-exist-ca\.pem/,
  )
})

test('exports the cluster server name the certs carry', () => {
  assert.equal(DEFAULT_CLUSTER_SERVER_NAME, 'nexus-node')
})

test('names the gRPC status in a transport failure', async () => {
  // Calls queue while the channel comes up, so an unreachable server surfaces
  // when the bounded wait expires rather than immediately. Callers match on the
  // status name to tell a missing plugin method from a real failure, so it has
  // to survive into the message.
  const client = new NexusVfsClient('127.0.0.1:1', { connectTimeoutMs: 250 })
  await assert.rejects(client.read('/nope', ''), /gRPC read failed: DEADLINE_EXCEEDED: /)
  client.close()
})

test('queues a call while the channel is still connecting', async () => {
  // The Rust client this replaces dialed lazily and queued; grpc-js fails fast
  // by default, which broke callers that dial a daemon they just spawned.
  const client = new NexusVfsClient('127.0.0.1:1', { connectTimeoutMs: 400 })
  const startedAt = Date.now()
  await assert.rejects(client.read('/nope', ''))
  assert.ok(
    Date.now() - startedAt >= 300,
    'the call returned before the connect wait elapsed, so it failed fast',
  )
  client.close()
})
