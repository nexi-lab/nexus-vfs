import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

import grpc from '@grpc/grpc-js'
import protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'

import { NexusVfsClient } from '../dist/index.js'
import { VFS_PROTO } from '../dist/generated/proto.js'

const binary = process.env.NEXUS_LOCAL_MOUNT_BINARY

async function freePort() {
  const start = 20_000 + (process.pid * 37) % 12_000
  for (let offset = 0; offset < 12_000; offset++) {
    const port = 20_000 + (start - 20_000 + offset) % 12_000
    const server = createServer()
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen(port, '127.0.0.1', resolve)
      })
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
      return port
    } catch (error) {
      server.close()
      if (error.code !== 'EADDRINUSE') throw error
    }
  }
  throw new Error('No local test port is available')
}

function mountStub(endpoint) {
  const root = protobuf.parse(VFS_PROTO, { keepCase: true }).root
  const definition = protoLoader.fromJSON(root.toJSON(), {
    keepCase: true, longs: String, defaults: true,
  })
  const Service = grpc.loadPackageDefinition(definition).nexus.grpc.vfs.NexusVFSService
  return new Service(endpoint, grpc.credentials.createInsecure())
}

function mount(stub, request) {
  return new Promise((resolve, reject) => {
    stub.Setattr({ entry_type: 2, auth_token: '', ...request },
      { deadline: Date.now() + 30_000 },
      (error, response) => error ? reject(error) : resolve(response))
  })
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  const closed = once(child, 'close')
  child.kill('SIGKILL')
  await closed
}

test('local mounts store bytes in the requested directory across process death', {
  skip: binary ? false : 'set NEXUS_LOCAL_MOUNT_BINARY to run',
  timeout: 180_000,
}, async () => {
  const temporaryRoot = await realpath(tmpdir())
  const directory = await mkdtemp(join(temporaryRoot, 'nexus-local-mount-'))
  const endpoint = `127.0.0.1:${await freePort()}`
  const backing = join(directory, '真实目录')
  const expected = Buffer.from(Array.from({ length: 256 }, (_, index) => index))
  const keep = new Set([
    'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'APPDATA',
    'LOCALAPPDATA', 'PROGRAMDATA', 'ALLUSERSPROFILE', 'PROGRAMFILES',
    'PROGRAMFILES(X86)', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)',
    'PROCESSOR_ARCHITECTURE', 'COMSPEC', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH',
  ])
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => keep.has(name.toUpperCase())))
  Object.assign(env, {
    NEXUS_DATA_DIR: join(directory, 'data'),
    NEXUS_IDENTITY_DIR: join(directory, 'identity'),
    NEXUS_ADVERTISE_ADDR: endpoint,
    NEXUS_NO_TLS: 'true',
    NEXUS_INSECURE_NO_AUTH: 'true',
    RUST_LOG: 'info,h2=warn,hyper=warn,tower=warn,tonic=warn',
  })
  try {
    for (let turn = 0; turn < 2; turn++) {
      const child = spawn(binary, ['--bind-addr', endpoint], { env, windowsHide: true })
      let log = ''
      child.stdout.on('data', chunk => { log = (log + chunk).slice(-65_536) })
      child.stderr.on('data', chunk => { log = (log + chunk).slice(-65_536) })
      const client = new NexusVfsClient(endpoint, { connectTimeoutMs: 90_000 })
      const stub = mountStub(endpoint)
      try {
        await new Promise((resolve, reject) => stub.waitForReady(Date.now() + 90_000,
          error => error ? reject(error) : resolve()))
        await client.serverInfo('')
        if (turn === 0) {
          await client.write('/seed.bin', Buffer.from('existing root'), '')
          for (const path of ['/', '/missing-root']) {
            const refused = await mount(stub, { path, backend_type: 'path_local' })
            assert.equal(refused.is_error, true)
            assert.equal(refused.created, false)
          }
          assert.equal(await client.exists('/missing-root', ''), false)
        }
        assert.deepEqual(await client.read('/seed.bin', ''), Buffer.from('existing root'))
        const installed = await mount(stub, {
          path: '/workspace', backend_name: 'local', backend_type: 'path_local',
          backend_params: { local_root: backing, fsync: 'true' },
        })
        assert.equal(installed.is_error, false, installed.error_payload.toString())
        assert.equal(installed.created, true)
        if (turn === 0) await client.write('/workspace/二进制.bin', expected, '')
        assert.deepEqual(await client.read('/workspace/二进制.bin', ''), expected)
        assert.deepEqual(await readFile(join(backing, '二进制.bin')), expected)
        await assert.rejects(readFile(join(directory, 'data/rootfs/workspace/二进制.bin')), { code: 'ENOENT' })
      } catch (error) {
        throw new Error(`${error.stack}\nNative daemon log:\n${log}`, { cause: error })
      } finally {
        stub.close()
        client.close()
        await stop(child)
      }
    }
  } finally {
    const target = await realpath(directory)
    assert.equal(dirname(target), temporaryRoot)
    await rm(target, { recursive: true, force: true })
  }
})
