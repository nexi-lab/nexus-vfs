import assert from 'node:assert/strict'
import test from 'node:test'

import { NexusRpcError, NexusZoneApiClient, userRuntimeServerName } from '../dist/index.js'

/**
 * The zone-api plane is a second service, loaded from a three-file proto
 * closure (`transport` → `commands` → `core/metadata`). Both failure modes it
 * introduces are silent:
 *
 *   - drop a file from the sync list and the closure no longer resolves, so
 *     the service never loads;
 *   - dial it and get a bare `Error`, so a caller deciding whether a failure
 *     is retryable has only the message text to go on. That is what made a
 *     consumer misread a stream-closed error as a transport hiccup.
 *
 * Both are covered here without a daemon: constructing the client forces the
 * closure to parse, and an unreachable target produces a real gRPC status.
 */

const UNREACHABLE = '127.0.0.1:1'

const client = () => new NexusZoneApiClient(UNREACHABLE, { connectTimeoutMs: 150 })

test('a runtime TLS name binds the exact owner and never the root node name', () => {
  assert.equal(userRuntimeServerName('alice'), 'nexus-user-2bd806c97f0e00af1a1fc3328fa763a9269723c8')
  assert.notEqual(userRuntimeServerName('alice'), userRuntimeServerName('Alice'))
  assert.notEqual(userRuntimeServerName('alice'), userRuntimeServerName('bob'))
  for (const owner of ['', 'alice\n', 'a'.repeat(257)]) {
    assert.throws(() => userRuntimeServerName(owner), /invalid/)
  }
})

test('mintUserRuntime exposes a real typed RPC and refuses invalid lifetime before dispatch', async () => {
  const c = client()
  try {
    for (const validitySecs of [0, -1, 301, 1.5, Number.MAX_SAFE_INTEGER]) {
      await assert.rejects(c.mintUserRuntime('alice', { validitySecs }), /between 1 and 300/)
    }
    const error = await c.mintUserRuntime('alice', { validitySecs: 300 }).catch(error => error)
    assert.ok(error instanceof NexusRpcError)
    assert.equal(error.operation, 'mint user runtime')
  } finally { c.close() }
})

test('the zone-api proto closure resolves and the service loads', () => {
  const c = client()
  try {
    assert.equal(c.target, UNREACHABLE, 'the endpoint resolves to a gRPC target')
  } finally {
    c.close()
  }
})

test('mintSessionAgent reaches the wire and reports a typed status', async () => {
  const c = client()
  try {
    const error = await c
      .mintSessionAgent('alice', { validitySecs: 3600 })
      .then(() => null, err => err)
    assert.ok(error instanceof NexusRpcError, `expected NexusRpcError, got ${error?.name}`)
    assert.equal(typeof error.code, 'number', 'the numeric status code is carried')
    assert.match(error.status, /^[A-Z_]+$/, 'the status name is carried as data')
    assert.equal(error.operation, 'mint session agent')
  } finally {
    c.close()
  }
})

test('revokeAgentCert is bound too, and fails the same structured way', async () => {
  const c = client()
  try {
    const error = await c
      .revokeAgentCert(Buffer.from('-----BEGIN CERTIFICATE-----\n'))
      .then(() => null, err => err)
    assert.ok(error instanceof NexusRpcError, `expected NexusRpcError, got ${error?.name}`)
    assert.equal(error.operation, 'revoke agent cert')
  } finally {
    c.close()
  }
})

test('a caller can classify without matching the message text', async () => {
  // The regression this guards: a server-supplied detail containing a status
  // name used to be indistinguishable from the status itself.
  const c = client()
  try {
    const error = await c
      .mintSessionAgent('alice', { validitySecs: 1 })
      .then(() => null, err => err)
    assert.ok(error instanceof NexusRpcError)
    assert.notEqual(error.status, '', 'status is populated independently of the message')
    assert.ok(error.message.includes(error.status), 'the message still names it for a human')
  } finally {
    c.close()
  }
})
