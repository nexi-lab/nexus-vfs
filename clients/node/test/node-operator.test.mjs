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
  for (const method of ['allowSessionMinter','denySessionMinter','listSessionMinters','ensureSessionMinter',
    'controlReplica','issueReplicaCsr','queryReplicaCsr']) assert.equal(agent[method],undefined)
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

const originalJson = () => Buffer.from('{"operation_id":"original","generation":18446744073709551615}')
const csrRequest = () => ({
  preparation_json: originalJson(), publication_operation_id: 'original-publication',
  csr_pem: Buffer.from('original CSR bytes'),
  renewal: { issued_at_unix_ms: '18446744073709551615', signature: Buffer.from('original holder signature') },
})
const controlFields = ['apply_binding_json','current_binding_json','reconcile_binding_json',
  'apply_issuer_json','current_issuer','reconcile_issuer_json']

for (const field of controlFields) {
  test(`replica control ${field} preserves the native operation and opaque bytes`, async t => {
    let calls = 0
    const original = originalJson()
    const endpoint = await serve(t, {
      ControlReplicaV1(call,reply) {
        calls++
        assert.deepEqual(controlFields.filter(key => call.request[key] != null), [field])
        assert.deepEqual(call.request[field], field === 'current_issuer' ? {} : original)
        reply(null,{ state:1,result_json:original })
      },
    })
    const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
    t.after(() => operator.close())
    const value = field === 'current_issuer' ? {} : new Uint8Array(original)
    const pending = operator.controlReplica({ [field]:value })
    if (value instanceof Uint8Array) value.fill(0)
    const result = await pending
    assert.equal(result.state,'REPLICA_CONTROL_STATE_RESULT')
    assert.deepEqual(result.result_json,original)
    assert.equal(calls,1)
  })
}

test('replica CSR copies original proof bytes and full uint64 before the mTLS call', async t => {
  let calls = 0
  const expected = csrRequest()
  const endpoint = await serve(t, {
    IssueReplicaCsrV1(call,reply) {
      calls++
      assert.deepEqual(call.request,expected)
      reply(null,{ state:1,operation_id:expected.publication_operation_id,
        preparation_json:expected.preparation_json,certificate_der:Buffer.from('native leaf'),ca_pem:Buffer.from('native CA') })
    },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  t.after(() => operator.close())
  const request = csrRequest()
  const pending = operator.issueReplicaCsr(request)
  request.preparation_json.fill(0); request.csr_pem.fill(0); request.renewal.signature.fill(0)
  request.renewal.issued_at_unix_ms = '1'; request.publication_operation_id = 'replacement'
  const response = await pending
  assert.equal(response.state,'REPLICA_CSR_STATE_PUBLISHED')
  assert.equal(response.operation_id,expected.publication_operation_id)
  assert.deepEqual(response.preparation_json,expected.preparation_json)
  assert.deepEqual(response.certificate_der,Buffer.from('native leaf'))
  assert.deepEqual(response.ca_pem,Buffer.from('native CA'))
  assert.equal(calls,1)
})

test('lost CSR reply uses one original issuance and explicit byte-identical query', async t => {
  let issues = 0, queries = 0
  const original = csrRequest()
  const endpoint = await serve(t, {
    IssueReplicaCsrV1(call,reply) {
      issues++; assert.deepEqual(call.request,original)
      reply({ code:grpc.status.UNAVAILABLE,details:'reply lost after original publication' })
    },
    QueryReplicaCsrV1(call,reply) {
      queries++; assert.deepEqual(call.request,original)
      reply(null,{ state:2,operation_id:'original-publication',preparation_json:original.preparation_json })
    },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  t.after(() => operator.close())
  await assert.rejects(operator.issueReplicaCsr(original), error => error instanceof NexusRpcError && error.code===grpc.status.UNAVAILABLE)
  assert.equal(issues,1); assert.equal(queries,0)
  const result = await operator.queryReplicaCsr(original)
  assert.equal(result.state,'REPLICA_CSR_STATE_PREPARED')
  assert.deepEqual(result.preparation_json,original.preparation_json)
  assert.equal(issues,1); assert.equal(queries,1)
})

test('lost control reply preserves the original bytes for explicit reconcile only', async t => {
  let mutations = 0, queries = 0
  const original = originalJson()
  const endpoint = await serve(t, {
    ControlReplicaV1(call,reply) {
      if (call.request.apply_binding_json != null) {
        mutations++; assert.deepEqual(call.request.apply_binding_json,original)
        reply({ code:grpc.status.UNAVAILABLE,details:'original binding response lost' })
      } else {
        queries++; assert.deepEqual(call.request.reconcile_binding_json,original)
        reply(null,{ state:2 })
      }
    },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  t.after(() => operator.close())
  await assert.rejects(operator.controlReplica({ apply_binding_json:original }), NexusRpcError)
  assert.equal(mutations,1); assert.equal(queries,0)
  assert.equal((await operator.controlReplica({ reconcile_binding_json:original })).state,'REPLICA_CONTROL_STATE_NOT_OBSERVED')
  assert.equal(mutations,1); assert.equal(queries,1)
})

test('native replica states and refusal details remain observations at the client boundary', async t => {
  let state = 1, controls = 0, csrs = 0
  const endpoint = await serve(t, {
    ControlReplicaV1(_call,reply) { controls++; reply(null,{ state,error:'native observation' }) },
    QueryReplicaCsrV1(_call,reply) { csrs++; reply(null,{ state,error:'native observation' }) },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  t.after(() => operator.close())
  for (const name of ['RESULT','NOT_OBSERVED','REFUSED','UNKNOWN']) {
    const result = await operator.controlReplica({ current_issuer:{} })
    assert.equal(result.state,`REPLICA_CONTROL_STATE_${name}`)
    assert.equal(result.error,'native observation'); state++
  }
  state = 1
  for (const name of ['PUBLISHED','PREPARED','NOT_OBSERVED','REFUSED','UNKNOWN']) {
    const result = await operator.queryReplicaCsr(csrRequest())
    assert.equal(result.state,`REPLICA_CSR_STATE_${name}`)
    assert.equal(result.error,'native observation'); state++
  }
  assert.equal(controls,4); assert.equal(csrs,5)
  state = 0
  await assert.rejects(operator.controlReplica({ current_issuer:{} }),/Invalid native replica control state/)
  await assert.rejects(operator.queryReplicaCsr(csrRequest()),/Invalid native replica CSR state/)
  assert.equal(controls,5); assert.equal(csrs,6)
})

test('invalid replica fields refuse before any transport invocation', async t => {
  let calls = 0
  const endpoint = await serve(t, {
    ControlReplicaV1(_call,reply) { calls++; reply(null,{ state:1 }) },
    IssueReplicaCsrV1(_call,reply) { calls++; reply(null,{ state:1 }) },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  t.after(() => operator.close())
  for (const request of [{}, { current_issuer:{ extra:true } }, { unknown:originalJson() },
    { apply_binding_json:originalJson(),apply_issuer_json:originalJson() }, { apply_binding_json:'{}' }]) {
    await assert.rejects(operator.controlReplica(request))
  }
  for (const value of [1,'-1','01','+1','1.0','18446744073709551616']) {
    const request = csrRequest(); request.renewal.issued_at_unix_ms = value
    await assert.rejects(operator.issueReplicaCsr(request),/exact uint64/)
  }
  assert.equal(calls,0)
})

test('an older peer explicitly refuses replica calls without falling back to session minting', async t => {
  let ordinaryMints = 0
  const endpoint = await serve(t, {
    MintUserRuntime(_call,reply) { ordinaryMints++; reply(null,{ success:true }) },
  })
  const operator = new NexusNodeOperatorClient(endpoint,tls('minter'))
  t.after(() => operator.close())
  for (const call of [() => operator.issueReplicaCsr(csrRequest()),
    () => operator.queryReplicaCsr(csrRequest()), () => operator.controlReplica({ current_issuer:{} })]) {
    await assert.rejects(call(), error => error instanceof NexusRpcError && error.code===grpc.status.UNIMPLEMENTED)
  }
  assert.equal(ordinaryMints,0)
  operator.close()
  await assert.rejects(operator.controlReplica({ current_issuer:{} }),/closed/)
  await assert.rejects(operator.issueReplicaCsr(csrRequest()),/closed/)
  await assert.rejects(operator.queryReplicaCsr(csrRequest()),/closed/)
})
