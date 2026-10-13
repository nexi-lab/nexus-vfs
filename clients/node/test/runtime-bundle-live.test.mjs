// The public bundle producer must work with the real serve-user reader and
// certificate watcher, including rotation after the original cert expires.
import assert from 'node:assert/strict'
import test from 'node:test'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { mkdtemp, mkdir, writeFile, rename, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'
import { NexusVfsClient, NexusZoneApiClient, createUserRuntimeCredentialBundle, userRuntimeServerName } from '../dist/index.js'
import { CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO } from '../dist/generated/proto.js'

const endpoint = process.env.NEXUS_ZONE_API_ENDPOINT
const tlsDir = process.env.NEXUS_ZONE_API_TLS_DIR
const binary = process.env.NEXUS_USER_RUNTIME_BIN

test('SDK bundles start serve-user and rotate its real TLS server atomically', {
  skip: endpoint && tlsDir && binary ? false : 'set NEXUS_ZONE_API_ENDPOINT, NEXUS_ZONE_API_TLS_DIR and NEXUS_USER_RUNTIME_BIN',
  timeout: 60000,
}, async () => {
  const root = new protobuf.Root()
  for (const source of [CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO]) protobuf.parse(source, root, { keepCase: true })
  root.resolveAll()
  const ZoneApi = grpc.loadPackageDefinition(protoLoader.fromJSON(root.toJSON(), { keepCase: true, longs: String, defaults: true })).nexus.raft.ZoneApiService
  const admin = new ZoneApi(endpoint, grpc.credentials.createSsl(await readFile(join(tlsDir, 'ca.pem')),
    await readFile(join(tlsDir, 'node-key.pem')), await readFile(join(tlsDir, 'node.pem'))), {
    'grpc.ssl_target_name_override': 'nexus-node', 'grpc.default_authority': 'nexus-node',
  })
  const call = (method, input) => new Promise((resolve, reject) => admin[method](input,
    new grpc.Metadata({ waitForReady: true }), { deadline: Date.now() + 10000 }, (error, value) => error ? reject(error) : resolve(value)))
  const work = await mkdtemp(join(tmpdir(), 'nexus-sdk-runtime-bundle-'))
  const clients = []
  let minter
  let child
  const subject = `bundle-minter-${process.pid}`
  try {
    const minted = await call('MintAgent', { subject_id: subject, display_name: subject })
    assert.equal(minted.success, true, minted.error)
    assert.equal((await call('AllowSessionMinter', { agent_id: subject })).success, true)
    minter = NexusZoneApiClient.withMtls(endpoint, { ca: minted.ca_pem, cert: minted.agent_cert_pem, key: minted.agent_key_pem })
    const owner = `bundle-owner-${process.pid}`
    const original = await minter.mintUserRuntime(owner, { validitySecs: 15 })
    const user = await minter.mintSessionAgent(owner, { validitySecs: 120 })
    const directory = join(work, 'volatile-credential')
    await mkdir(directory)
    async function deliver(credential) {
      const bundle = createUserRuntimeCredentialBundle(owner, credential)
      for (const [name, bytes] of Object.entries(bundle.files)) await writeFile(join(directory, name), bytes, { mode: 0o600 })
      const temporary = join(directory, bundle.manifestName + '.next')
      await writeFile(temporary, bundle.manifest, { mode: 0o600 })
      await rename(temporary, join(directory, bundle.manifestName))
    }
    await deliver(original)
    const socket = createServer()
    await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve))
    const port = socket.address().port
    await new Promise(resolve => socket.close(resolve))
    child = spawn(binary, ['--data-dir', join(work, 'durable-data'), '--bind-addr', `127.0.0.1:${port}`,
      'serve-user', '--owner', owner, '--credential', directory], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let daemonLog = ''
    child.stdout.on('data', bytes => { daemonLog += bytes.toString() })
    child.stderr.on('data', bytes => { daemonLog += bytes.toString() })
    child.on('error', error => { daemonLog += String(error) })
    const tls = { ca: user.caPem, cert: user.certPem, key: user.keyPem, serverName: userRuntimeServerName(owner) }
    const before = NexusVfsClient.withMtls(`127.0.0.1:${port}`, tls, { connectTimeoutMs: 10000 })
    clients.push(before)
    const path = '/bundle-proof'
    const content = Buffer.from('owner file survives TLS server rotation')
    try { await before.write(path, content, '') } catch (error) {
      throw new Error('serve-user did not accept the owner file: ' + daemonLog, { cause: error })
    }
    const originalExpiry = Date.parse(new X509Certificate(original.certPem).validTo)
    await setTimeout(Math.max(0, originalExpiry - 7000 - Date.now()))
    const renewed = await minter.renewSessionAgent(original, { validitySecs: 15 })
    assert.ok(!renewed.keyPem.equals(original.keyPem), 'renewal rotates the private key')
    await deliver(renewed)
    await setTimeout(Math.max(0, originalExpiry + 250 - Date.now()))
    const after = NexusVfsClient.withMtls(`127.0.0.1:${port}`, tls, { connectTimeoutMs: 3000 })
    clients.push(after)
    assert.deepEqual(await after.read(path, ''), content, 'a new TLS connection after expiry uses the renewed server certificate')
    await assert.rejects(readFile(join(work, 'durable-data/tls/ca-key.pem')), { code: 'ENOENT' })
  } finally {
    for (const client of clients) client.close()
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve))
      child.kill()
      await exited
    }
    minter?.close()
    try { await call('DenySessionMinter', { agent_id: subject }) } finally { admin.close() }
    await rm(work, { recursive: true, force: true })
  }
})
