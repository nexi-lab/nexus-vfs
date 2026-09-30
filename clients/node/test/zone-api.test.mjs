import assert from 'node:assert/strict'
import test from 'node:test'

import { NexusRpcError, NexusZoneApiClient } from '../dist/index.js'

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
