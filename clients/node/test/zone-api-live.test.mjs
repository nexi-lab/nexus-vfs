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
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'

import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'

import { NexusZoneApiClient } from '../dist/index.js'
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

function adminStub() {
  const root = new protobuf.Root()
  for (const source of [CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO]) {
    protobuf.parse(source, root, { keepCase: true })
  }
  root.resolveAll()
  const ZoneApi = grpc.loadPackageDefinition(
    protoLoader.fromJSON(root.toJSON(), { keepCase: true, longs: String, defaults: true }),
  ).nexus.raft.ZoneApiService
  const credentials = grpc.credentials.createSsl(
    readFileSync(join(tlsDir, 'ca.pem')),
    readFileSync(join(tlsDir, 'node-key.pem')),
    readFileSync(join(tlsDir, 'node.pem')),
  )
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
    const workDir = mkdtempSync(join(tmpdir(), 'nexus-zone-api-live-'))
    t.after(() => {
      admin.close()
      rmSync(workDir, { recursive: true, force: true })
    })

    // An agent identity to act as: the allow-list names agents, so the caller
    // has to be one. A node cert would prove nothing — nodes administer.
    const minted = await adminCall(admin, 'MintAgent', { subject_id: AGENT, display_name: AGENT })
    assert.equal(minted.success, true, `MintAgent failed: ${minted.error}`)
    const caPath = join(workDir, 'ca.pem')
    const certPath = join(workDir, 'agent.pem')
    const keyPath = join(workDir, 'agent-key.pem')
    writeFileSync(caPath, minted.ca_pem)
    writeFileSync(certPath, minted.agent_cert_pem)
    writeFileSync(keyPath, minted.agent_key_pem)

    const agent = NexusZoneApiClient.withMtls(endpoint, { caPath, certPath, keyPath })
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

    await t.test('taking the agent off the list refuses it again', async () => {
      const removed = await adminCall(admin, 'DenySessionMinter', { agent_id: AGENT })
      assert.equal(removed.success, true, removed.error)

      const error = await agent
        .mintSessionAgent(OWNER, { validitySecs: VALIDITY_SECS })
        .then(() => null, err => err)
      assert.ok(error, 'revoking the permission has to take effect')
    })
  },
)
