import assert from 'node:assert/strict'
import test from 'node:test'
import * as grpc from '@grpc/grpc-js'
import * as loader from '@grpc/proto-loader'
import protobuf from 'protobufjs'
import { NexusVfsClient, NexusSessionTransport, SessionCodec } from '../dist/index.js'
import { VFS_PROTO } from '../dist/generated/proto.js'

const endpoint = { protocol: 'acp-mailbox/1', channel_id: 'read-retry', agent: 'worker', controller: 'owner',
  transcript: '/conversations/0123456789abcdef0123456789abcdef/transcript' }

async function fixture(handlers) {
  const root = protobuf.parse(VFS_PROTO, { keepCase: true }).root
  const definition = loader.fromJSON(root.toJSON(), { keepCase: true, longs: String, defaults: true })
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

for (const status of [grpc.status.CANCELLED, grpc.status.UNAVAILABLE]) {
  test(`real gRPC ${grpc.status[status]} read resumes the same cursor without replaying input`, { timeout: 5000 }, async () => {
    const agent = new SessionCodec(endpoint, 'agent')
    const frames = ['one', 'two'].map(text => agent.encode({ type: 'rpc', message: {
      jsonrpc: '2.0', method: 'session/update', params: { text },
    } }))
    const offsets = []
    const writes = []
    const received = []
    let failed = false
    let resolveDone, rejectDone
    const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject })
    void done.catch(() => {})
    const { client, close } = await fixture({
      streamReadAt(call, reply) {
        const offset = call.request.offset
        offsets.push(offset)
        if (offset === '1' && !failed) {
          failed = true
          reply({ code: status, details: 'Timeout expired' })
          return
        }
        const data = frames[Number(offset)]
        reply(null, { data: data ?? Buffer.alloc(0), next_offset: data ? String(Number(offset) + 1) : offset,
          timed_out: !data, eof: !data, is_error: false })
      },
      streamWriteNowait(call, reply) {
        writes.push(call.request.data)
        reply(null, { offset: String(writes.length), is_error: false })
      },
    })
    const transport = new NexusSessionTransport({ client, endpoint, authToken: 'owner-token',
      onMessage(message) { received.push(message.params.text); if (received.length === 2) resolveDone() },
      onClose(error) { if (error) rejectDone(error) },
    })
    try {
      transport.start()
      await transport.send({ jsonrpc: '2.0', id: 'input', method: 'session/prompt', params: {} })
      await done
      assert.deepEqual(received, ['one', 'two'])
      assert.deepEqual(offsets.slice(0, 3), ['0', '1', '1'])
      assert.equal(writes.length, 1, 'read recovery must not replay submitted input')
    } finally { await transport.close(); await close() }
  })
}

test('explicit close interrupts a cancelled-read retry without reopening the attachment', { timeout: 5000 }, async () => {
  let reads = 0
  let writes = 0
  let cancelled
  const firstRead = new Promise(resolve => { cancelled = resolve })
  const { client, close } = await fixture({
    streamReadAt(_call, reply) {
      reads++
      reply({ code: grpc.status.CANCELLED, details: 'Timeout expired' })
      cancelled()
    },
    streamWriteNowait(_call, reply) { writes++; reply(null, { offset: '0', is_error: false }) },
  })
  const closed = []
  const transport = new NexusSessionTransport({ client, endpoint, authToken: '',
    onMessage() { assert.fail('no server messages were sent') }, onClose(error) { closed.push(error) },
  })
  try {
    transport.start()
    await firstRead
    await transport.close()
    assert.equal(reads, 1)
    assert.equal(writes, 1, 'one controller close frame')
    assert.deepEqual(closed, [undefined])
  } finally { await transport.close(); await close() }
})

test('a cancelled write is attempted once and preserves its uncertain outcome', { timeout: 5000 }, async () => {
  let writes = 0
  const { client, close } = await fixture({
    streamReadAt(call, reply) { reply(null, { data: Buffer.alloc(0), next_offset: call.request.offset, timed_out: true, eof: true }) },
    streamWriteNowait(_call, reply) { writes++; reply({ code: grpc.status.CANCELLED, details: 'Timeout expired' }) },
  })
  let failure
  const transport = new NexusSessionTransport({ client, endpoint, authToken: '',
    onMessage() {}, onClose(error) { failure = error },
  })
  try {
    transport.start()
    await assert.rejects(transport.send({ jsonrpc: '2.0', id: 'input', method: 'session/prompt', params: {} }),
      error => error.code === grpc.status.CANCELLED)
    assert.equal(writes, 1)
    assert.match(failure.message, /delivery outcome is unknown/)
    assert.equal(failure.cause.code, grpc.status.CANCELLED)
  } finally { await transport.close(); await close() }
})
