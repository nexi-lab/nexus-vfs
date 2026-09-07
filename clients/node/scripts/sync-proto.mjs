#!/usr/bin/env node
// Copies the service definition from this repository's proto tree into the
// package so it can ship to npm. The copy is generated, never committed
// (see .gitignore) — that is what makes drift structurally impossible:
// there is exactly one editable vfs.proto in this repo, and every Node
// consumer loads a byte-identical copy of it.
//
// `--check` verifies an existing copy is current instead of writing, for CI.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const repoRoot = dirname(dirname(packageRoot))

const RELATIVE_PROTO = join('proto', 'nexus', 'grpc', 'vfs', 'vfs.proto')
const source = join(repoRoot, RELATIVE_PROTO)
const destination = join(packageRoot, RELATIVE_PROTO)

if (!existsSync(source)) {
  console.error(`sync-proto: source proto not found at ${source}`)
  process.exit(1)
}

const contents = readFileSync(source)

if (process.argv.includes('--check')) {
  if (!existsSync(destination) || !readFileSync(destination).equals(contents)) {
    console.error(`sync-proto: ${RELATIVE_PROTO} is stale — run \`npm run sync-proto\``)
    process.exit(1)
  }
  console.log('sync-proto: up to date')
  process.exit(0)
}

mkdirSync(dirname(destination), { recursive: true })
writeFileSync(destination, contents)
console.log(`sync-proto: ${RELATIVE_PROTO} <- ${source}`)
