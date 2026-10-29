import assert from 'node:assert/strict'
import test from 'node:test'
import * as grpc from '@grpc/grpc-js'
import { NexusConditionalContentError } from '../dist/index.js'
import { fixture } from './helpers/vfs-fixture.mjs'

const version = Buffer.from([0, 255, 128, 12, 34])
const isFailure = kind => error => error instanceof NexusConditionalContentError && error.kind === kind

test('versioned reads distinguish an empty file, absence and a malformed answer', async () => {
  const requests = []
  const { client, close } = await fixture({ readVersioned(call, reply) {
    requests.push(call.request)
    if (call.request.path === '/missing') reply(null, { absent: {} })
    else if (call.request.path === '/malformed') reply(null, {})
    else reply(null, { snapshot: { content: Buffer.alloc(0), version } })
  } })
  try {
    assert.deepEqual(await client.readVersioned('/empty', 'owner'), { content: Buffer.alloc(0), version })
    assert.equal(await client.readVersioned('/missing', 'owner'), null)
    await assert.rejects(client.readVersioned('/malformed', 'owner'), isFailure('failed'))
    assert(requests.every(request => request.auth_token === 'owner'))
  } finally { await close() }
})

test('conditional writes preserve absent preconditions, opaque tokens and both conflict images', async () => {
  const requests = []
  const { client, close } = await fixture({ writeIfVersion(call, reply) {
    requests.push(call.request)
    if (call.request.path === '/missing') reply(null, { conflict: {} })
    else if (call.request.path === '/present') reply(null, { conflict: { current_version: version } })
    else reply(null, { committed_version: version })
  } })
  try {
    assert.deepEqual(await client.writeIfVersion('/created', Buffer.from('image'), null, 'owner'), { kind: 'committed', version })
    assert.equal(requests[0]._expected_version, undefined)
    assert.deepEqual(await client.writeIfVersion('/present', Buffer.from('other'), version, 'owner'), { kind: 'conflict', currentVersion: version })
    assert.equal(requests[1]._expected_version, 'expected_version')
    assert.deepEqual(requests[1].expected_version, version)
    assert.deepEqual(await client.writeIfVersion('/missing', Buffer.alloc(0), version, 'owner'), { kind: 'conflict', currentVersion: null })
    assert(requests.every(request => request.auth_token === 'owner'))
  } finally { await close() }
})

for (const kind of ['unsupported', 'failed', 'unknown']) {
  test(`the wire preserves the typed ${kind} result`, async () => {
    const response = { failure: { kind: kind.toUpperCase(), message: 'fixture outcome' } }
    const { client, close } = await fixture({
      readVersioned(_call, reply) { reply(null, response) },
      writeIfVersion(_call, reply) { reply(null, response) },
    })
    try {
      await assert.rejects(client.readVersioned('/file', ''), isFailure(kind))
      await assert.rejects(client.writeIfVersion('/file', Buffer.from('image'), null, ''), isFailure(kind))
    } finally { await close() }
  })
}

test('an older service refuses both operations without an unconditional-write fallback', async () => {
  let writes = 0
  const { client, close } = await fixture({ write(_call, reply) { writes++; reply(null, {}) } })
  try {
    await assert.rejects(client.readVersioned('/file', ''), isFailure('unsupported'))
    await assert.rejects(client.writeIfVersion('/file', Buffer.from('image'), null, ''), isFailure('unsupported'))
    assert.equal(writes, 0)
  } finally { await close() }
})

test('a lost write reply is unknown and the client sends exactly one request', async () => {
  let requests = 0
  let content
  const { client, close } = await fixture({
    writeIfVersion(call, reply) {
      requests++
      content = call.request.content
      reply({ code: grpc.status.UNAVAILABLE, details: 'response lost after submission' })
    },
    readVersioned(_call, reply) { reply(null, { snapshot: { content, version } }) },
  })
  try {
    await assert.rejects(client.writeIfVersion('/register', Buffer.from('consumer fence'), null, ''), isFailure('unknown'))
    assert.equal(requests, 1)
    assert.deepEqual(await client.readVersioned('/register', ''), { content: Buffer.from('consumer fence'), version })
  } finally { await close() }
})

test('invalid tokens fail locally and incomplete write responses remain unknown', async () => {
  let requests = 0
  const { client, close } = await fixture({ writeIfVersion(_call, reply) { requests++; reply(null, {}) } })
  try {
    for (const invalid of [undefined, Buffer.alloc(0), 'text']) {
      await assert.rejects(client.writeIfVersion('/register', Buffer.alloc(0), invalid, ''), isFailure('failed'))
    }
    assert.equal(requests, 0)
    await assert.rejects(client.writeIfVersion('/register', Buffer.alloc(0), null, ''), isFailure('unknown'))
    assert.equal(requests, 1)
  } finally { await close() }
})

test('empty returned versions and future failure kinds cannot imply a rejected write', async () => {
  const responses = [
    { committed_version: Buffer.alloc(0) },
    { conflict: { current_version: Buffer.alloc(0) } },
    { failure: { kind: 99, message: 'future outcome' } },
  ]
  const { client, close } = await fixture({ writeIfVersion(_call, reply) { reply(null, responses.shift()) } })
  try {
    for (let index = 0; index < 3; index++) {
      await assert.rejects(client.writeIfVersion('/register', Buffer.alloc(0), null, ''), isFailure('unknown'))
    }
    assert.equal(responses.length, 0)
  } finally { await close() }
})

test('server info advertises the paired protocol separately from per-path storage support', async () => {
  let protocol = 0
  const { client, close } = await fixture({ ping(_call, reply) {
    reply(null, { version: 'fixture', conditional_content_version: protocol })
  } })
  try {
    assert.equal((await client.serverInfo('')).conditional_content_version, 0)
    protocol = 1
    assert.equal((await client.serverInfo('')).conditional_content_version, 1)
  } finally { await close() }
})
