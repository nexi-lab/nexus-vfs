// The session-mint gate, end to end against a real auth-on cluster. Opt-in:
// set NEXUS_ZONE_API_ENDPOINT and NEXUS_ZONE_API_TLS_DIR (a daemon's own
// `<data-dir>/tls`, holding ca.pem / node.pem / node-key.pem).
//
// zone-api.test.mjs proves the service loads and that failures arrive typed.
// Neither says anything about the gate, because an unreachable target refuses
// everything: a client that had lost its credentials entirely would pass it.
// What has to hold is that the SAME call is refused before an agent is
// allow-listed and granted after — so the refusal comes first here, and the
// success is only meaningful because of it.
//
// Administering the allow-list is node-gated and deliberately absent from the
// client, so the operator half is built here from the protos the package
// already ships. A test that could not operate the gate could not prove one.
import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { createServer, request } from 'node:https'

import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'

import { NexusVfsClient, NexusZoneApiClient, userRuntimeServerName } from '../dist/index.js'
import {
  CORE_METADATA_PROTO,
  RAFT_COMMANDS_PROTO,
  RAFT_TRANSPORT_PROTO,
} from '../dist/generated/proto.js'

const endpoint = process.env.NEXUS_ZONE_API_ENDPOINT
const tlsDir = process.env.NEXUS_ZONE_API_TLS_DIR
const SERVER_NAME = 'nexus-node'
const OWNER = `live-owner-${process.pid}`
const AGENT = `live-minter-${process.pid}`
const VALIDITY_SECS = 120

function adminStub(tls) {
  const root = new protobuf.Root()
  for (const source of [CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO]) {
    protobuf.parse(source, root, { keepCase: true })
  }
  root.resolveAll()
  const ZoneApi = grpc.loadPackageDefinition(
    protoLoader.fromJSON(root.toJSON(), { keepCase: true, longs: String, defaults: true }),
  ).nexus.raft.ZoneApiService
  const credentials = tls
    ? grpc.credentials.createSsl(tls.caPem, tls.keyPem, tls.certPem)
    : grpc.credentials.createSsl(readFileSync(join(tlsDir, 'ca.pem')),
      readFileSync(join(tlsDir, 'node-key.pem')), readFileSync(join(tlsDir, 'node.pem')))
  return new ZoneApi(endpoint, credentials, {
    'grpc.ssl_target_name_override': SERVER_NAME,
    'grpc.default_authority': SERVER_NAME,
  })
}

function adminCall(stub, method, request) {
  return new Promise((resolve, reject) => {
    const metadata = new grpc.Metadata({ waitForReady: true })
    stub[method](request, metadata, { deadline: Date.now() + 30_000 }, (error, response) => {
      if (error) reject(new Error(`${method}: ${grpc.status[error.code]}: ${error.details || error.message}`))
      else resolve(response)
    })
  })
}

test(
  'the session-mint allow-list gates minting',
  { skip: endpoint && tlsDir ? false : 'set NEXUS_ZONE_API_ENDPOINT and NEXUS_ZONE_API_TLS_DIR to run' },
  async (t) => {
    const admin = adminStub()
    t.after(() => admin.close())

    // An agent identity to act as: the allow-list names agents, so the caller
    // has to be one. A node cert would prove nothing — nodes administer.
    const minted = await adminCall(admin, 'MintAgent', { subject_id: AGENT, display_name: AGENT })
    assert.equal(minted.success, true, `MintAgent failed: ${minted.error}`)
    // Dialled straight from the bytes the daemon returned. Nothing is written
    // to disk: a minted credential that had to become a file first would make
    // "this client never persists it" false for its only real use.
    const agent = NexusZoneApiClient.withMtls(endpoint, {
      ca: minted.ca_pem,
      cert: minted.agent_cert_pem,
      key: minted.agent_key_pem,
    })
    t.after(() => agent.close())

    await t.test('the client exposes no way to administer the list', () => {
      for (const method of ['allowSessionMinter', 'denySessionMinter', 'listSessionMinters']) {
        assert.equal(
          typeof agent[method],
          'undefined',
          `${method} is node-gated; an agent-facing client must not offer it`,
        )
      }
    })

    await t.test('an agent that is not allow-listed is refused', async () => {
      const error = await agent
        .mintSessionAgent(OWNER, { validitySecs: VALIDITY_SECS })
        .then(() => null, err => err)
      assert.ok(error, 'minting must not succeed before the agent is allow-listed')
      assert.match(error.message, /refused/, 'a refusal is reported as one')
      await assert.rejects(agent.mintUserRuntime(OWNER, { validitySecs: 120 }), /refused/)
    })

    await t.test('a node can put the agent on the list', async () => {
      const before = await adminCall(admin, 'ListSessionMinters', {})
      assert.equal(before.success, true, before.error)
      assert.ok(!(before.agent_ids ?? []).includes(AGENT), 'the agent starts off the list')

      const allowed = await adminCall(admin, 'AllowSessionMinter', { agent_id: AGENT })
      assert.equal(allowed.success, true, allowed.error)
      t.after(() => adminCall(admin, 'DenySessionMinter', { agent_id: AGENT }).catch(() => {}))

      const after = await adminCall(admin, 'ListSessionMinters', {})
      assert.ok((after.agent_ids ?? []).includes(AGENT), 'the write is readable back')
    })

    await t.test('the same call now mints a credential bound to the owner', async () => {
      const credential = await agent.mintSessionAgent(OWNER, { validitySecs: VALIDITY_SECS })

      assert.match(
        credential.subjectId,
        /^session-[0-9a-f-]{36}$/,
        'the subject is minted server-side, not chosen by the caller',
      )
      assert.ok(credential.keyPem.length > 0, 'the private key comes back with the certificate')

      const cert = new X509Certificate(credential.certPem)
      const sans = cert.subjectAltName ?? ''
      assert.ok(
        sans.includes(`URI:nexus://agent/${credential.subjectId}`),
        `the certificate carries its own identity: ${sans}`,
      )
      assert.ok(
        sans.includes(`URI:nexus://owner/${OWNER}`),
        `the certificate carries the owner it acts for: ${sans}`,
      )

      const lifetimeSecs = (Date.parse(cert.validTo) - Date.parse(cert.validFrom)) / 1000
      assert.ok(
        lifetimeSecs > 0 && lifetimeSecs <= VALIDITY_SECS,
        `a session credential is short-lived, and the server may clamp: got ${lifetimeSecs}s`,
      )

      await agent.revokeAgentCert(credential.certPem)
    })

    await t.test('a runtime serves real mutual TLS for its signed owner and renews without node authority', async () => {
      const minter = adminStub({ caPem: minted.ca_pem, keyPem: minted.agent_key_pem, certPem: minted.agent_cert_pem })
      try {
        for (const validity_secs of ['0', '301', '18446744073709551615']) {
          const rejected = await adminCall(minter, 'MintUserRuntime', { owner_id: OWNER, validity_secs })
          assert.equal(rejected.success, false, 'the issuer enforces its own lifetime bound')
        }
      } finally { minter.close() }
      const original = await agent.mintUserRuntime(OWNER, { validitySecs: 120 })
      const credential = await agent.renewSessionAgent(original, { validitySecs: 120 })
      assert.equal(credential.subjectId, original.subjectId)
      assert.notDeepEqual(credential.keyPem, original.keyPem)
      const cert = new X509Certificate(credential.certPem)
      assert.equal(cert.ca, false)
      assert.equal(cert.subjectAltName, new X509Certificate(original.certPem).subjectAltName)
      assert.deepEqual(cert.keyUsage, ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1'])
      assert.ok(cert.subjectAltName.includes(`URI:nexus://owner/${OWNER}`))
      assert.ok(!cert.subjectAltName.includes('nexus://zone/'))
      const serverName = userRuntimeServerName(OWNER)
      const server = createServer({ key: credential.keyPem, cert: credential.certPem,
        ca: credential.caPem, requestCert: true, rejectUnauthorized: true }, (_req, res) => res.end('runtime-ok'))
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
      const port = server.address().port
      const fetch = name => new Promise((resolve, reject) => {
        const req = request({ host: '127.0.0.1', port, servername: name, ca: credential.caPem,
          key: readFileSync(join(tlsDir, 'node-key.pem')), cert: readFileSync(join(tlsDir, 'node.pem')),
          agent: false, timeout: 3000 }, res => {
          const chunks = []
          res.on('data', chunk => chunks.push(chunk))
          res.on('end', () => resolve(Buffer.concat(chunks).toString()))
        })
        req.on('error', reject)
        req.on('timeout', () => req.destroy(new Error('runtime TLS request timeout')))
        req.end()
      })
      try {
        assert.equal(await fetch(serverName), 'runtime-ok')
        await assert.rejects(fetch(userRuntimeServerName('another-owner')), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
        await assert.rejects(fetch(SERVER_NAME), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
      } finally { await new Promise(resolve => server.close(resolve)) }
      const runtime = NexusZoneApiClient.withMtls(endpoint, { ca: credential.caPem, cert: credential.certPem, key: credential.keyPem })
      const unprivileged = adminStub(credential)
      try {
        await assert.rejects(runtime.mintSessionAgent('another-owner', { validitySecs: 120 }), /refused/)
        await assert.rejects(runtime.mintUserRuntime('another-owner', { validitySecs: 120 }), /refused/)
        assert.equal((await adminCall(unprivileged, 'MintAgent', { subject_id: `forged-${process.pid}` })).success, false)
        assert.equal((await adminCall(unprivileged, 'AllowSessionMinter', { agent_id: credential.subjectId })).success, false)
      } finally { runtime.close(); unprivileged.close() }
      await agent.revokeAgentCert(credential.certPem)
      await assert.rejects(agent.renewSessionAgent(credential, { validitySecs: 120 }), /revoked/)
    })

    await t.test('renewal preserves the actor, bytes and a pending watch across real certificate expiry', async () => {
      const validitySecs = 6
      const original = await agent.mintSessionAgent(OWNER, { validitySecs })
      const originalTls = { ca: original.caPem, cert: original.certPem, key: original.keyPem }
      const expired = NexusVfsClient.withMtls(endpoint, originalTls, { connectTimeoutMs: 3000 })
      const active = NexusVfsClient.withMtls(endpoint, originalTls, { connectTimeoutMs: 3000 })
      const path = `/agents/credential-renewal-${process.pid}`
      const before = Buffer.from('before real certificate expiry')
      const after = Buffer.from('same actor after real certificate expiry')
      let current = original
      let renewals = 0
      try {
        await expired.write(path, before, '')
        const watch = active.watch(path, '', { timeoutMs: 20000 })
        void watch.catch(() => {})
        active.maintainSessionCredential(original, {
          validitySecs,
          renew: async (credential, signal) => {
            assert.equal(signal.aborted, false)
            current = await agent.renewSessionAgent(credential, { validitySecs })
            assert.equal(current.subjectId, original.subjectId)
            renewals++
            return current
          },
        })
        const until = Date.parse(new X509Certificate(original.certPem).validTo) + 6500
        await new Promise(resolve => setTimeout(resolve, Math.max(0, until - Date.now())))
        assert.ok(renewals >= 2, `expected continuous renewal, got ${renewals}`)
        await assert.rejects(expired.read(path, ''), 'the original established TLS connection must lose authority')
        assert.deepEqual(await active.read(path, ''), before)
        await active.write(path, after, '')
        assert.equal((await watch).matched, true, 'the poll started under the original certificate completes after rotation')
        assert.deepEqual(await active.read(path, ''), after)
        active.close()
        await agent.revokeAgentCert(current.certPem)
        await assert.rejects(agent.renewSessionAgent(current, { validitySecs }), /revoked/)
      } finally {
        expired.close()
        active.close()
      }
    })

    await t.test('taking the agent off the list refuses it again', async () => {
      const removed = await adminCall(admin, 'DenySessionMinter', { agent_id: AGENT })
      assert.equal(removed.success, true, removed.error)

      const error = await agent
        .mintSessionAgent(OWNER, { validitySecs: VALIDITY_SECS })
        .then(() => null, err => err)
      assert.ok(error, 'revoking the permission has to take effect')
      await assert.rejects(agent.mintUserRuntime(OWNER, { validitySecs: 120 }), /refused/)
    })
  },
)
