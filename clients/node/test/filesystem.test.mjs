import assert from 'node:assert/strict'
import test from 'node:test'
import * as grpc from '@grpc/grpc-js'
import { fixture } from './helpers/vfs-fixture.mjs'

test('chmod sends native permissions and owner credentials through its typed RPC', async () => {
  const requests = []
  const { client, close } = await fixture({ chmod(call, reply) {
    requests.push(call.request)
    reply(null, { is_error: false })
  } })
  try {
    for (const mode of [0o700, 0]) await client.chmod('/project/run.sh', mode, 'owner-token')
    assert.deepEqual(requests, [0o700, 0].map(mode => ({ path: '/project/run.sh', mode, auth_token: 'owner-token' })))
    for (const mode of [-1, 0o4700, 1.5, NaN]) {
      await assert.rejects(client.chmod('/project/run.sh', mode, 'owner-token'), /permission bits/)
    }
    assert.equal(requests.length, 2)
  } finally { await close() }
})

test('an older daemon cannot silently acknowledge a chmod it never performed', async () => {
  const { client, close } = await fixture({})
  try {
    await assert.rejects(client.chmod('/project/run.sh', 0o700, ''), /UNIMPLEMENTED/)
  } finally { await close() }
})

test('directory deletion opts into the existing recursive RPC and preserves authorization failures', async () => {
  const requests = []
  const { client, close } = await fixture({ delete(call, reply) {
    requests.push(call.request)
    if (call.request.path === '/denied') reply({ code: grpc.status.PERMISSION_DENIED, details: 'Owner cannot delete this directory' })
    else reply(null, { success: true, is_error: false })
  } })
  try {
    await client.delete('/project/file', 'owner-token')
    await client.delete('/project/skills', 'owner-token', { recursive: true })
    assert.deepEqual(requests, [
      { path: '/project/file', auth_token: 'owner-token', recursive: false },
      { path: '/project/skills', auth_token: 'owner-token', recursive: true },
    ])
    await assert.rejects(client.delete('/denied', 'owner-token', { recursive: true }), /PERMISSION_DENIED/)
    assert.equal(requests[2].auth_token, 'owner-token')
  } finally { await close() }
})
