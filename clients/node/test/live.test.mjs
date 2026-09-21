// Round-trips against a real nexus daemon. Opt-in: set NEXUS_VFS_ENDPOINT
// (e.g. `127.0.0.1:2126` for a `nexusd serve-local --no-tls`). For an
// auth-on cluster also set NEXUS_VFS_CA / NEXUS_VFS_CERT / NEXUS_VFS_KEY,
// and NEXUS_VFS_TOKEN when the zone requires one.
import assert from 'node:assert/strict'
import test from 'node:test'

import { NexusVfsClient } from '../dist/index.js'

const endpoint = process.env.NEXUS_VFS_ENDPOINT
const token = process.env.NEXUS_VFS_TOKEN ?? ''

const connect = () => {
  const { NEXUS_VFS_CA: caPath, NEXUS_VFS_CERT: certPath, NEXUS_VFS_KEY: keyPath } = process.env
  if (caPath && certPath && keyPath) {
    return NexusVfsClient.withMtls(endpoint, {
      caPath,
      certPath,
      keyPath,
      serverName: process.env.NEXUS_VFS_SERVER_NAME,
    })
  }
  return new NexusVfsClient(endpoint)
}

test(
  'round-trips against a live daemon',
  { skip: endpoint ? false : 'set NEXUS_VFS_ENDPOINT to run' },
  async (t) => {
    const client = connect()
    t.after(() => client.close())

    await t.test('serverInfo', async () => {
      const info = await client.serverInfo(token)
      assert.ok(info.version, 'server reported no version')
    })

    await t.test('call dispatches and decodes JSON', async () => {
      const raw = await client.call('get_mount_points', '{}', token)
      assert.ok(Array.isArray(JSON.parse(raw).result))
    })

    await t.test('lock is exclusive and contention is not an error', async () => {
      const path = `/vfs-client-lock-${process.pid}`
      const first = await client.lock(path, token, { timeoutMs: 30_000 })
      assert.equal(first.acquired, true, 'the first holder should take the lock')
      assert.ok(first.lockId, 'an acquired lock reports its id')
      try {
        const second = await client.lock(path, token, { timeoutMs: 1_000 })
        assert.equal(second.acquired, false, 'a second holder must see contention, not an error')
      } finally {
        assert.equal(await client.unlock(path, token, { lockId: first.lockId }), true)
      }
      const again = await client.lock(path, token, { timeoutMs: 30_000 })
      assert.equal(again.acquired, true, 'the lock is takeable once released')
      await client.unlock(path, token, { lockId: again.lockId })
    })

    await t.test('watch reports a write, and an idle wait is not an error', async () => {
      const path = `/vfs-client-watch-${process.pid}.bin`
      // Park the watch before the write lands: that is the ordering a follower has.
      const pending = client.watch(path, token, { timeoutMs: 15_000 })
      await new Promise(resolve => setTimeout(resolve, 200))
      await client.write(path, Buffer.from('x'), token)
      const event = await pending
      assert.equal(event.matched, true, 'the write should wake the watch')
      assert.ok(event.eventType, 'a matched event names its type')
      await client.delete(path, token)

      const quiet = await client.watch(`/vfs-client-quiet-${process.pid}`, token, { timeoutMs: 1_000 })
      assert.equal(quiet.matched, false, 'an expired wait is reported, not thrown')
    })

    await t.test('write then read returns the same bytes', async () => {
      const path = `/vfs-client-live-${process.pid}.bin`
      const content = Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x80])
      await client.write(path, content, token)
      try {
        assert.deepEqual(await client.read(path, token), content)
      } finally {
        await client.delete(path, token)
      }
      await assert.rejects(client.read(path, token))
    })
  },
)
