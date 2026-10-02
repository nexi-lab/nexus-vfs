import assert from 'node:assert/strict'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { NexusSessionTransport, SessionCodec, SESSION_PROTOCOL } from '../dist/index.js'

const endpoint = {
  protocol: SESSION_PROTOCOL,
  channel_id: 'generation-1',
  agent: 'worker', controller: 'operator',
  transcript: '/conversations/0123456789abcdef0123456789abcdef/transcript',
}
const rpc = (message) => ({ type: 'rpc', message: { jsonrpc: '2.0', ...message } })

test('session codec preserves reverse requests, ID zero, content blocks, and extensions', () => {
  const agent = new SessionCodec(endpoint, 'agent')
  const controller = new SessionCodec(endpoint)
  const permission = rpc({ id: 0, method: 'session/request_permission', params: {
    sessionId: 'durable', toolCall: { toolCallId: 'edit', rawInput: { path: '/repo/a' } },
    options: [{ optionId: 'yes', kind: 'allow_once', name: 'Allow' }], _meta: { extension: [1, 2] },
  } })
  const bytes = agent.encode(permission)
  assert.deepEqual(controller.decode(bytes), permission)
  assert.equal(controller.decode(bytes), undefined)
  assert.equal(agent.decode(bytes), undefined)
  const answer = rpc({ id: 0, result: { outcome: { outcome: 'selected', optionId: 'yes' } } })
  assert.deepEqual(agent.decode(controller.encode(answer)), answer)
})

test('old generations are ignored, missing frames and forged senders fail', () => {
  const agent = new SessionCodec(endpoint, 'agent')
  const controller = new SessionCodec(endpoint)
  const cancel = rpc({ method: 'session/cancel', params: { sessionId: 'durable' } })
  const first = controller.encode(cancel)
  assert.throws(() => agent.decode(controller.encode(cancel)), /gap/)
  const forged = JSON.parse(first)
  forged.from = 'intruder'
  assert.throws(() => agent.decode(Buffer.from(JSON.stringify(forged))), /participants/)
  const old = new SessionCodec({ ...endpoint, channel_id: 'previous' })
  assert.equal(agent.decode(old.encode(cancel)), undefined)
  assert.deepEqual(agent.decode(first), cancel)
})

test('mailbox reader continues while a permission callback is waiting', async () => {
  const records = []
  const agent = new SessionCodec(endpoint, 'agent')
  const received = []
  let complete
  const completed = new Promise((resolve) => { complete = resolve })
  let transport
  const client = {
    async streamReadAt(path, offset) {
      assert.equal(path, endpoint.transcript)
      const record = records[Number(offset)]
      if (!record) await delay(5)
      return { data: record ?? Buffer.alloc(0), nextOffset: record ? String(Number(offset) + 1) : offset, eof: false, timedOut: !record }
    },
    async streamWrite(path, bytes) {
      assert.equal(path, endpoint.transcript)
      records.push(bytes)
      const message = agent.decode(bytes)
      if (message?.type !== 'rpc') return
      if (message.message.method === 'session/prompt') {
        records.push(agent.encode(rpc({ id: 0, method: 'session/request_permission', params: { sessionId: 'durable' } })))
        records.push(agent.encode(rpc({ method: 'session/update', params: { sessionId: 'durable', update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: 'still streaming' } } } })))
      } else if (message.message.method === 'session/cancel') {
        records.push(agent.encode(rpc({ id: 'turn', result: { stopReason: 'cancelled' } })))
      }
    },
  }
  let approvalEntered = false
  let releaseApproval
  const approval = new Promise((resolve) => { releaseApproval = resolve })
  transport = new NexusSessionTransport({ client, endpoint, authToken: '',
    onMessage: async (message) => {
      received.push(message)
      if (message.method === 'session/request_permission') {
        approvalEntered = true
        await approval
      } else if (message.method === 'session/update') {
        assert.equal(approvalEntered, true)
        await transport.send({ jsonrpc: '2.0', method: 'session/cancel', params: { sessionId: 'durable' } })
      } else if (message.id === 'turn') complete()
    },
    onClose: (error) => { assert.equal(error, undefined) },
  })
  transport.start()
  try {
    await transport.send({ jsonrpc: '2.0', id: 'turn', method: 'session/prompt', params: { sessionId: 'durable' } })
    await Promise.race([completed, delay(1000).then(() => { throw new Error('cancel blocked behind approval') })])
    assert.deepEqual(received.at(-1).result, { stopReason: 'cancelled' })
  } finally {
    releaseApproval()
    await transport.close()
  }
})

test('an uncertain append closes the channel without silently resubmitting the turn', async () => {
  let writes = 0
  const closed = []
  const transport = new NexusSessionTransport({ endpoint, authToken: '',
    client: {
      async streamReadAt(_path, offset) { await delay(5); return { data: Buffer.alloc(0), nextOffset: offset, timedOut: true } },
      async streamWrite() { writes++; throw new Error('connection dropped after append') },
    },
    onMessage() {}, onClose(error) { closed.push(error) },
  })
  transport.start()
  await assert.rejects(transport.send({ jsonrpc: '2.0', id: 1, method: 'session/prompt' }))
  assert.equal(writes, 1)
  assert.equal(transport.connected, false)
  assert.match(closed[0].message, /outcome is unknown/)
  await assert.rejects(transport.send({ jsonrpc: '2.0', id: 2, method: 'session/prompt' }), /closed/)
  await transport.close()
  assert.equal(closed.length, 1)
})


test('transient read failure preserves the cursor and does not duplicate a delta', async () => {
  const agent = new SessionCodec(endpoint, 'agent')
  const records = [agent.encode(rpc({ method: 'session/update', params: { text: 'one' } })),
    agent.encode(rpc({ method: 'session/update', params: { text: 'two' } }))]
  const received = []
  const offsets = []
  let failed = false
  let complete
  const done = new Promise(resolve => { complete = resolve })
  const transport = new NexusSessionTransport({ endpoint, authToken: '',
    client: {
      async streamReadAt(_path, offset) {
        offsets.push(offset)
        if (offset === '1' && !failed) { failed = true; throw Object.assign(new Error('reconnecting'), {code: 14}) }
        const record = records[Number(offset)]
        if (!record) await delay(5)
        return {data: record ?? Buffer.alloc(0), nextOffset: record ? String(Number(offset) + 1) : offset}
      },
      async streamWrite() {},
    },
    onMessage(message) { received.push(message.params.text); if (received.length === 2) complete() },
    onClose(error) { assert.equal(error, undefined) },
  })
  transport.start()
  try {
    await Promise.race([done, delay(2000).then(() => {throw new Error('read recovery timed out')})])
    assert.deepEqual(received, ['one', 'two'])
    assert.deepEqual(offsets.slice(0, 3), ['0', '1', '1'])
  } finally { await transport.close() }
})
