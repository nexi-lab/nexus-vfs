import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'
import { NexusNodeOperatorClient, NexusZoneApiClient, NexusRpcError, NexusOperatorOutcomeUnknown } from '../dist/index.js'
import { CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO } from '../dist/generated/proto.js'

const fixture = JSON.parse(readFileSync(new URL('./fixtures/renewal-tls.json', import.meta.url), 'utf8'))
const tls = name => ({ ca: Buffer.from(fixture.ca), cert: Buffer.from(fixture[name].cert), key: Buffer.from(fixture[name].key) })
async function serve(t, handlers) {
  const root = new protobuf.Root()
  for (const source of [CORE_METADATA_PROTO,RAFT_COMMANDS_PROTO,RAFT_TRANSPORT_PROTO]) protobuf.parse(source,root,{ keepCase:true })
  root.resolveAll()
  const definitions = protoLoader.fromJSON(root.toJSON(), { keepCase:true,longs:String,defaults:true })
  const server = new grpc.Server()
  server.addService(definitions['nexus.raft.ZoneApiService'], handlers)
  const material = tls('server')
  const port = await new Promise((resolve,reject) => server.bindAsync('127.0.0.1:0',
    grpc.ServerCredentials.createSsl(material.ca,[{ private_key:material.key,cert_chain:material.cert }],true),
    (error,bound) => error ? reject(error) : resolve(bound)))
  t.after(() => server.forceShutdown())
  return `127.0.0.1:${port}`
}

// Real mTLS transport/proto fixtures; native Node authorization is a separate
// daemon acceptance gate, never established by this scripted server.
test('operator is separate and an already-present grant performs no mutation', async t => {
  let mutations = 0
  const endpoint = await serve(t, {
    ListSessionMinters(_call,reply) { reply(null,{ success:true,agent_ids:['moss'] }) },
    AllowSessionMinter(_call,reply) { mutations++; reply(null,{ success:true }) },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  const agent = NexusZoneApiClient.withMtls(endpoint,tls('minter'))
  t.after(() => { operator.close(); agent.close() })
  for (const method of ['allowSessionMinter','denySessionMinter','listSessionMinters','ensureSessionMinter']) assert.equal(agent[method],undefined)
  const result = await operator.ensureSessionMinter('moss')
  assert.equal(result.mutationSubmitted,false)
  assert.equal(result.mutationResponse,'not-needed')
  assert.equal(mutations,0)
})

test('append-then-lost mutation reply is reconciled with a read and never resent', async t => {
  const allowed = new Set()
  let mutations = 0
  const endpoint = await serve(t, {
    ListSessionMinters(_call,reply) { reply(null,{ success:true,agent_ids:[...allowed] }) },
    AllowSessionMinter(call,reply) {
      mutations++; allowed.add(call.request.agent_id)
      reply({ code:grpc.status.UNAVAILABLE,details:'reply lost after applying grant' })
    },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'),{ connectTimeoutMs:2000 })
  t.after(() => operator.close())
  const result = await operator.ensureSessionMinter('moss')
  assert.equal(result.present,true)
  assert.equal(result.mutationResponse,'unknown')
  assert.equal(result.mutationError.code,grpc.status.UNAVAILABLE)
  assert.equal(result.automaticResend,false)
  assert.equal(mutations,1)
})

test('unobserved mutation remains unknown and Node-gated errors retain native status', async t => {
  let mutations = 0
  const endpoint = await serve(t, {
    ListSessionMinters(_call,reply) { reply(null,{ success:true,agent_ids:[] }) },
    AllowSessionMinter(_call,reply) { mutations++; reply({ code:grpc.status.PERMISSION_DENIED,details:'node credential required' }) },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'),{ connectTimeoutMs:2000 })
  t.after(() => operator.close())
  await assert.rejects(operator.ensureSessionMinter('moss'),/outcome unknown/)
  assert.equal(mutations,1)
  await assert.rejects(operator.allowSessionMinter('moss'), error => error instanceof NexusRpcError && error.code===grpc.status.PERMISSION_DENIED)
  assert.equal(mutations,2)
  await assert.rejects(operator.ensureSessionMinter(''),/must not be empty/)
  assert.equal(mutations,2)
})

test('failed reconciliation retains both original errors without another mutation', async t => {
  let reads = 0, mutations = 0
  const endpoint = await serve(t, {
    ListSessionMinters(_call,reply) {
      reads++
      if (reads===1) reply(null,{ success:true,agent_ids:[] })
      else reply({ code:grpc.status.PERMISSION_DENIED,details:'authority removed before reconciliation' })
    },
    AllowSessionMinter(_call,reply) { mutations++; reply({ code:grpc.status.UNAVAILABLE,details:'mutation response lost' }) },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'),{ connectTimeoutMs:2000 })
  t.after(() => operator.close())
  await assert.rejects(operator.ensureSessionMinter('moss'), error => {
    assert(error instanceof NexusOperatorOutcomeUnknown)
    assert.equal(error.outcome,'unknown')
    assert.equal(error.mutationError.code,grpc.status.UNAVAILABLE)
    assert.equal(error.reconciliationError.code,grpc.status.PERMISSION_DENIED)
    return true
  })
  assert.equal(mutations,1)
  assert.equal(reads,2)
})
