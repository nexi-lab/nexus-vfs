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

test('a new attachment reads a retained log without replaying an older generation', async () => {
  const old = new SessionCodec({ ...endpoint, channel_id: 'previous' }, 'agent')
  const agent = new SessionCodec(endpoint, 'agent')
  const records = [old.encode(rpc({ id: 1, result: { stale: true } })), agent.encode(rpc({ id: 0, result: { initialized: true } }))]
  const offsets = []
  const received = []
  let complete
  const done = new Promise(resolve => { complete = resolve })
  const transport = new NexusSessionTransport({ endpoint, authToken: '',
    client: {
      async streamReadAt(_path, offset) {
        offsets.push(offset)
        if (offset === '0') throw new Error(JSON.stringify({ code: -32019, message: 'offset 0 trimmed; earliest 512' }))
        const record = records[Number(offset) - 512]
        if (!record) await delay(5)
        return { data: record ?? Buffer.alloc(0), nextOffset: record ? String(Number(offset) + 1) : offset }
      },
      async streamWrite() {},
    },
    onMessage(message) { received.push(message); complete() },
    onClose(error) { assert.equal(error, undefined) },
  })
  transport.start()
  try {
    await Promise.race([done, delay(1000).then(() => { throw new Error('retained initialization timed out') })])
    assert.deepEqual(received, [{ jsonrpc: '2.0', id: 0, result: { initialized: true } }])
    assert.deepEqual(offsets.slice(0, 3), ['0', '512', '513'])
  } finally { await transport.close() }
})

test('recovering the initial retention floor still rejects a missing frame in this generation', async () => {
  const agent = new SessionCodec(endpoint, 'agent')
  agent.encode(rpc({ method: 'session/update', params: { text: 'lost' } }))
  const retained = agent.encode(rpc({ id: 1, result: { stopReason: 'end_turn' } }))
  const received = []
  let complete
  const done = new Promise(resolve => { complete = resolve })
  const transport = new NexusSessionTransport({ endpoint, authToken: '',
    client: {
      async streamReadAt(_path, offset) {
        if (offset === '0') throw new Error(JSON.stringify({ code: -32019, message: 'offset 0 trimmed; earliest 512' }))
        return { data: retained, nextOffset: '513' }
      },
      async streamWrite() {},
    },
    onMessage(message) { received.push(message) },
    onClose(error) { complete(error) },
  })
  transport.start()
  try {
    const error = await Promise.race([done, delay(1000).then(() => { throw new Error('missing-frame failure timed out') })])
    assert.match(error.message, /gap/)
    assert.deepEqual(received, [])
  } finally { await transport.close() }
})

for (const failure of [
  { code: -32019, message: 'offset 1 trimmed; earliest 512' },
  { code: -32019, message: 'offset 0 trimmed; earliest 0' },
  { code: -32001, message: 'offset 0 trimmed; earliest 512' },
]) test(`unrelated or invalid retention error closes the channel: ${JSON.stringify(failure)}`, async () => {
  let reads = 0
  let complete
  const done = new Promise(resolve => { complete = resolve })
  const transport = new NexusSessionTransport({ endpoint, authToken: '',
    client: {
      async streamReadAt() { reads++; throw new Error(JSON.stringify(failure)) },
      async streamWrite() {},
    },
    onMessage() { assert.fail('failed reads must not deliver messages') },
    onClose(error) { complete(error) },
  })
  transport.start()
  try {
    const error = await Promise.race([done, delay(1000).then(() => { throw new Error('retention rejection timed out') })])
    assert.equal(error.message, JSON.stringify(failure))
    assert.equal(reads, 1)
  } finally { await transport.close() }
})

test('retention overtaking an active attachment fails without dropping current traffic', async () => {
  const agent = new SessionCodec(endpoint, 'agent')
  const first = agent.encode(rpc({ method: 'session/update', params: { text: 'first' } }))
  const failure = JSON.stringify({ code: -32019, message: 'offset 1 trimmed; earliest 512' })
  const received = []
  let complete
  const done = new Promise(resolve => { complete = resolve })
  const transport = new NexusSessionTransport({ endpoint, authToken: '',
    client: {
      async streamReadAt(_path, offset) {
        if (offset === '0') return { data: first, nextOffset: '1' }
        throw new Error(failure)
      },
      async streamWrite() {},
    },
    onMessage(message) { received.push(message.params.text) },
    onClose(error) { complete(error) },
  })
  transport.start()
  try {
    const error = await Promise.race([done, delay(1000).then(() => { throw new Error('active retention failure timed out') })])
    assert.equal(error.message, failure)
    assert.deepEqual(received, ['first'])
  } finally { await transport.close() }
})
