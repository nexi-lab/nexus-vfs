import assert from 'node:assert/strict'
import test from 'node:test'
import * as grpc from '@grpc/grpc-js'
import * as loader from '@grpc/proto-loader'
import protobuf from 'protobufjs'
import { NexusVfsClient } from '../dist/index.js'
import { VFS_PROTO } from '../dist/generated/proto.js'

async function fixture(handlers) {
  const root = protobuf.parse(VFS_PROTO, { keepCase: true }).root
  const definition = loader.fromJSON(root.toJSON(), { keepCase: true, defaults: true })
  const server = new grpc.Server()
  server.addService(definition['nexus.grpc.vfs.NexusVFSService'], handlers)
  const port = await new Promise((resolve, reject) => server.bindAsync(
    '127.0.0.1:0', grpc.ServerCredentials.createInsecure(),
    (error, value) => error ? reject(error) : resolve(value),
  ))
  const client = new NexusVfsClient(`127.0.0.1:${port}`)
  return { client, async close() {
    client.close()
    await new Promise((resolve, reject) => server.tryShutdown(error => error ? reject(error) : resolve()))
  } }
}

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
