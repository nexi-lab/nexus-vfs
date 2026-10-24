#!/usr/bin/env node
// Deployment operator only. No credential is passed to an application runtime.
import assert from 'node:assert/strict'
import { readFileSync, statSync } from 'node:fs'
import { NexusNodeOperatorClient, NexusOperatorOutcomeUnknown } from '../dist/index.js'

const [operation, configFile, agentId] = process.argv.slice(2)
assert(['list-session-minters','ensure-session-minter'].includes(operation), 'Expected list-session-minters or ensure-session-minter')
assert(configFile, 'Supply a private operator configuration file')
if (process.platform !== 'win32') {
  const metadata = statSync(configFile)
  assert.equal(metadata.uid, process.getuid(), 'Operator configuration must belong to the current user')
  assert.equal(metadata.mode & 0o077, 0, 'Operator configuration must be owner-only')
}
const config = JSON.parse(readFileSync(configFile, 'utf8'))
assert(typeof config.endpoint === 'string' && config.tls, 'Explicit endpoint and native Node mTLS are required')
const client = new NexusNodeOperatorClient(config.endpoint, config.tls)
try {
  const result = operation === 'list-session-minters'
    ? { agentIds: await client.listSessionMinters(), mutationSubmitted: false }
    : await client.ensureSessionMinter(agentId)
  console.log(JSON.stringify(result))
} catch (error) {
  const diagnostic = value => value instanceof Error
    ? { message:value.message, ...(typeof value.code === 'number' ? { code:value.code,status:value.status } : {}) }
    : undefined
  console.error(JSON.stringify({ error:diagnostic(error), ...(error instanceof NexusOperatorOutcomeUnknown
    ? { outcome:'unknown',mutationError:diagnostic(error.mutationError),reconciliationError:diagnostic(error.reconciliationError) }
    : {}) }))
  process.exitCode = 1
} finally { client.close() }
