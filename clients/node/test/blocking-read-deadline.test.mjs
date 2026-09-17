import assert from 'node:assert/strict'
import test from 'node:test'

import { BLOCKING_READ_DEADLINE_MARGIN_MS, NexusVfsClient } from '../dist/index.js'

/**
 * `connectTimeoutMs` bounds the wait for the channel. A blocking read asks the
 * daemon to hold the response for `timeoutMs`, so bounding that call by the
 * connect timeout made every long poll at or above it expire on the client
 * first. The caller then saw DEADLINE_EXCEEDED instead of the daemon's own
 * `timed_out` answer — and since a throw from streamReadAt is the
 * stream-closed signal, a live writer was reported as exited.
 */

const UNREACHABLE = '127.0.0.1:1'

test('a blocking read outlives connectTimeoutMs by its own timeout', async () => {
  const client = new NexusVfsClient(UNREACHABLE, {
    connectTimeoutMs: 100,
    blockingReadMarginMs: 50,
  })
  const started = Date.now()
  await assert.rejects(
    client.streamReadAt('/stream', '0', '', { blocking: true, timeoutMs: 400 }),
    /gRPC stream read failed: DEADLINE_EXCEEDED: /,
  )
  const elapsed = Date.now() - started
  // Old behaviour expired at connectTimeoutMs (100ms). The deadline now comes
  // from 400 + 50, so anything past 300ms proves the poll was not truncated.
  assert.ok(elapsed > 300, `expired after ${elapsed}ms, expected the poll's own deadline`)
  client.close()
})

test('a non-blocking read still uses connectTimeoutMs', async () => {
  const client = new NexusVfsClient(UNREACHABLE, {
    connectTimeoutMs: 150,
    blockingReadMarginMs: 50,
  })
  const started = Date.now()
  await assert.rejects(client.streamReadAt('/stream', '0', ''), /DEADLINE_EXCEEDED/)
  const elapsed = Date.now() - started
  assert.ok(elapsed < 1000, `took ${elapsed}ms; a non-blocking read must not wait on a poll`)
  client.close()
})

test('the default margin is exported so callers need not guess it', () => {
  assert.equal(typeof BLOCKING_READ_DEADLINE_MARGIN_MS, 'number')
  assert.ok(BLOCKING_READ_DEADLINE_MARGIN_MS > 0)
})
