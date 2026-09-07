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
