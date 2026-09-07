// Consumers bundle their server into a single file, and that used to break
// this client: it read the .proto off disk, and protobufjs resolves `fs`
// through a dynamic require that a bundler leaves null — so loading the service
// definition failed with "Cannot read properties of null (reading
// 'readFileSync')", but only in the bundled build, never in tests or a plain
// `node` run.
//
// The invariant that prevents it is simpler than any particular bundler:
// nothing under dist/ may touch the filesystem to load the definition. Assert
// that directly by running dist/ somewhere the proto/ directory does not exist.
import assert from 'node:assert/strict'
import { cpSync, mkdirSync, rmSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { pathToFileURL, fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))

test('loads the service definition with no proto file on disk', async () => {
  // Inside the package so Node still resolves @grpc/* from node_modules, but
  // at a path where `../proto/...` does not exist.
  const isolated = join(packageRoot, '.test-isolated-dist')
  rmSync(isolated, { recursive: true, force: true })
  try {
    mkdirSync(isolated, { recursive: true })
    cpSync(join(packageRoot, 'dist'), join(isolated, 'dist'), { recursive: true })
    assert.ok(!existsSync(join(isolated, 'proto')), 'the proto tree must not be copied')

    const { NexusVfsClient } = await import(
      pathToFileURL(join(isolated, 'dist', 'index.js')).href
    )
    // Constructing parses the service definition — the step that used to reach
    // for the filesystem.
    const client = new NexusVfsClient('127.0.0.1:1')
    assert.equal(client.target, '127.0.0.1:1')
    assert.equal(typeof client.streamReadAt, 'function')
    client.close()
  } finally {
    rmSync(isolated, { recursive: true, force: true })
  }
})
