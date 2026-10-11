import assert from 'node:assert/strict'
import { createHash, verify, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'
import { NexusVfsClient, NexusZoneApiClient } from '../dist/index.js'
import { CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO, VFS_PROTO } from '../dist/generated/proto.js'

// Public test keys, signed by a dedicated test CA. No fixture is shipped in
// the package and the CA signing key is not retained.
const fixture = JSON.parse(readFileSync(new URL('./fixtures/renewal-tls.json', import.meta.url), 'utf8'))
const tls = name => ({ ca: Buffer.from(fixture.ca), cert: Buffer.from(fixture[name].cert), key: Buffer.from(fixture[name].key) })
const credential = name => ({ certPem: tls(name).cert, keyPem: tls(name).key, caPem: tls(name).ca, subjectId: 'session-alice' })
const response = name => ({ success: true, agent_cert_pem: tls(name).cert, agent_key_pem: tls(name).key, ca_pem: tls(name).ca, subject_id: 'session-alice' })

async function serve(t, handlers) {
  const root = new protobuf.Root()
  for (const source of [CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO, VFS_PROTO]) {
    protobuf.parse(source, root, { keepCase: true })
  }
  root.resolveAll()
  const definition = protoLoader.fromJSON(root.toJSON(), { keepCase: true, longs: String, defaults: true })
  const server = new grpc.Server()
  for (const [service, methods] of Object.entries(handlers)) server.addService(definition[service], methods)
  const material = tls('server')
  const port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0',
    grpc.ServerCredentials.createSsl(material.ca, [{ private_key: material.key, cert_chain: material.cert }], true),
    (error, bound) => error ? reject(error) : resolve(bound)))
  t.after(() => server.forceShutdown())
  return `127.0.0.1:${port}`
}

test('renewal moves signed bytes over real mTLS and rejects substituted identities', async t => {
  let request
  let reply = response('renewed')
  const endpoint = await serve(t, { 'nexus.raft.ZoneApiService': {
    RenewSessionAgent(call, callback) { request = call.request; callback(null, reply) },
  } })
  const zone = NexusZoneApiClient.withMtls(endpoint, tls('minter'), { connectTimeoutMs: 2000 })
  t.after(() => zone.close())
  const renewed = await zone.renewSessionAgent(credential('old'), { validitySecs: 300 })
  assert.equal(renewed.subjectId, 'session-alice')
  assert.deepEqual(renewed.keyPem, tls('renewed').key)
  assert.equal(request.owner_id, undefined)
  assert.equal(request.subject_id, undefined)
  const numbers = Buffer.alloc(16)
  numbers.writeBigUInt64BE(300n, 0)
  numbers.writeBigUInt64BE(BigInt(request.issued_at_unix_ms), 8)
  const message = Buffer.concat([
    Buffer.from('nexus/session-renewal/v1\0'),
    createHash('sha256').update(new X509Certificate(fixture.old.cert).raw).digest(),
    createHash('sha256').update(new X509Certificate(fixture.minter.cert).raw).digest(),
    numbers,
  ])
  assert.equal(verify('sha256', message, new X509Certificate(fixture.old.cert).publicKey, request.proof), true)
  for (const invalid of [
    { ...response('renewed'), subject_id: 'session-bob' },
    response('other'),
    { ...response('renewed'), agent_key_pem: tls('other').key },
  ]) {
    reply = invalid
    await assert.rejects(zone.renewSessionAgent(credential('old'), { validitySecs: 300 }), /inconsistent credentials/)
  }
  reply = { success: false, error: 'revoked' }
  await assert.rejects(zone.renewSessionAgent(credential('old'), { validitySecs: 300 }), /refused: revoked/)
  for (const validitySecs of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(zone.renewSessionAgent(credential('old'), { validitySecs }), /positive integer/)
  }
})

test('rotation preserves an active poll and new calls use a new TLS connection', async t => {
  let finishRead
  let firstPeer
  let nextPeer
  let markStarted
  const started = new Promise(resolve => { markStarted = resolve })
  const endpoint = await serve(t, { 'nexus.grpc.vfs.NexusVFSService': {
    StreamReadAt(call, callback) { firstPeer = call.getPeer(); finishRead = callback; markStarted() },
    Read(call, callback) { nextPeer = call.getPeer(); callback(null, { content: Buffer.from('durable bytes') }) },
  } })
  const client = NexusVfsClient.withMtls(endpoint, tls('old'), { connectTimeoutMs: 2000 })
  t.after(() => client.close())
  const poll = client.streamReadAt('/proc/1/stdout', '0', '', { blocking: true, timeoutMs: 5000 })
  await started
  await client.rotateTls(tls('renewed'))
  assert.equal((await client.read('/agents/a/history', '')).toString(), 'durable bytes')
  assert.notEqual(nextPeer, firstPeer, 'new calls must leave the old TLS connection')
  finishRead(null, { data: Buffer.from('approval output'), next_offset: '15', eof: false, timed_out: false })
  assert.equal((await poll).data.toString(), 'approval output')
  await assert.rejects(client.rotateTls({ ...tls('renewed'), serverName: 'wrong-name' }))
  assert.equal((await client.read('/agents/a/history', '')).toString(), 'durable bytes', 'failed preparation keeps current channel')
  client.close()
  await assert.rejects(client.read('/agents/a/history', ''), /closed/)
  await assert.rejects(client.rotateTls(tls('old')), /closed/)
})

test('closing the client promptly cancels a poll still draining on the old credential', { timeout: 5000 }, async t => {
  let markStarted
  const started = new Promise(resolve => { markStarted = resolve })
  const endpoint = await serve(t, { 'nexus.grpc.vfs.NexusVFSService': {
    StreamReadAt() { markStarted() },
  } })
  const client = NexusVfsClient.withMtls(endpoint, tls('old'), { connectTimeoutMs: 2000 })
  t.after(() => client.close())
  const poll = client.streamReadAt('/proc/1/stdout', '0', '', { blocking: true, timeoutMs: 5000 })
  const rejected = assert.rejects(poll, { status: 'CANCELLED' })
  await started
  await client.rotateTls(tls('renewed'))
  client.close()
  await rejected
})

test('closing during channel preparation also releases the candidate connection', { timeout: 5000 }, async t => {
  const endpoint = await serve(t, { 'nexus.grpc.vfs.NexusVFSService': {
    Read(_call, callback) { callback(null, { content: Buffer.from('ready') }) },
  } })
  const client = NexusVfsClient.withMtls(endpoint, tls('old'), { connectTimeoutMs: 10000 })
  t.after(() => client.close())
  const rotating = client.rotateTls({ ...tls('renewed'), serverName: 'wrong-name' })
  const rejected = assert.rejects(rotating)
  client.close()
  await rejected
})

test('automatic renewal keeps the actor, permits new calls and stops with the client', { timeout: 6000 }, async t => {
  const endpoint = await serve(t, { 'nexus.grpc.vfs.NexusVFSService': {
    Read(_call, callback) { callback(null, { content: Buffer.from('original session') }) },
  } })
  const client = NexusVfsClient.withMtls(endpoint, tls('old'), { connectTimeoutMs: 2000 })
  t.after(() => client.close())
  let renewals = 0
  let completed
  const renewedTwice = new Promise(resolve => { completed = resolve })
  const started = []
  client.maintainSessionCredential(credential('old'), {
    validitySecs: 1,
    renew: async (current, signal) => {
      assert.equal(current.subjectId, 'session-alice')
      started.push(signal)
      renewals++
      if (renewals === 2) completed()
      return credential('renewed')
    },
  })
  await renewedTwice
  assert.equal((await client.read('/agents/a/history', '')).toString(), 'original session')
  client.close()
  assert.equal(started.every(signal => signal.aborted), true)
  const stoppedAt = renewals
  await new Promise(resolve => setTimeout(resolve, 750))
  assert.equal(renewals, stoppedAt, 'a closed controller cannot start another issuance')
})

test('a refused or substituted renewal closes the client without using another identity', { timeout: 6000 }, async t => {
  const endpoint = await serve(t, { 'nexus.grpc.vfs.NexusVFSService': {
    Read(_call, callback) { callback(null, { content: Buffer.from('original session') }) },
  } })
  for (const [renew, expected] of [
    [async () => { throw new Error('renewal revoked') }, /renewal revoked/],
    [async () => credential('other'), /inconsistent credentials/],
  ]) {
    const client = NexusVfsClient.withMtls(endpoint, tls('old'), { connectTimeoutMs: 2000 })
    t.after(() => client.close())
    client.maintainSessionCredential(credential('old'), { validitySecs: 1, renew })
    await new Promise(resolve => setTimeout(resolve, 850))
    await assert.rejects(client.read('/agents/a/history', ''), expected)
  }
})
