#!/usr/bin/env node
/** Producer-side runtime archive; the target needs Node, never npm or a compiler. */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const clientRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const [output] = process.argv.slice(2)
assert(output && isAbsolute(output) && !existsSync(output) && !existsSync(output+'.receipt.json'), 'Use a new absolute archive destination')
assert(process.env.npm_execpath && existsSync(process.env.npm_execpath), 'Invoke through npm run package:operator')
const git = (...args) => execFileSync('git',args,{ cwd:clientRoot,encoding:'utf8' }).trim()
assert.equal(git('status','--porcelain','--','.'),'','Operator producer source must be clean')
const source = git('rev-parse','HEAD'), repo = git('rev-parse','--show-toplevel')
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const staging = mkdtempSync(join(tmpdir(),'nexus-node-operator-'))
const runtime = join(staging,'runtime')
try {
  mkdirSync(runtime,{ mode:0o700 })
  for (const name of ['dist','bin','package.json','package-lock.json','README.md','OPERATOR.md']) cpSync(join(clientRoot,name),join(runtime,name),{ recursive:true })
  const install = spawnSync(process.execPath,[process.env.npm_execpath,'ci','--omit=dev','--ignore-scripts','--no-audit','--no-fund'],
    { cwd:runtime,stdio:'inherit' })
  assert.equal(install.status,0,'Producer runtime dependency install failed')
  // npm's generated convenience launchers vary by producer OS. The archive
  // runs the canonical bin/*.mjs with Node and needs none of those launchers.
  const launchers = join(runtime,'node_modules/.bin')
  assert(resolve(launchers).startsWith(resolve(staging)+ '/'.replace('/',process.platform==='win32'?'\\':'/')))
  rmSync(launchers,{ recursive:true,force:true })
  const inventory = {}
  function walk(directory) {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory,name), info = lstatSync(path)
      assert(!info.isSymbolicLink(),'Runtime archive must not depend on symlink resolution')
      if (info.isDirectory()) walk(path)
      else {
        assert(info.isFile() && !/\.(node|exe|dll)$/i.test(name),'Expected a portable JavaScript runtime')
        inventory[relative(runtime,path).replaceAll('\\','/')] = { bytes:info.size,sha256:sha(readFileSync(path)) }
      }
    }
  }
  walk(runtime)
  const sourceFiles = {}
  for (const name of git('ls-files','--','.').split('\n').filter(Boolean)) sourceFiles[name] = sha(readFileSync(join(clientRoot,name)))
  for (const name of ['proto/nexus/raft/transport.proto','proto/nexus/raft/commands.proto','proto/nexus/core/metadata.proto','proto/nexus/grpc/vfs/vfs.proto']) sourceFiles[name] = sha(readFileSync(join(repo,name)))
  const manifest = { schemaVersion:1,source,sourceFiles,files:inventory,entry:'bin/nexus-node-operator.mjs',nodeRequired:'>=18',targetNpmRequired:false }
  writeFileSync(join(runtime,'operator-manifest.json'),JSON.stringify(manifest,null,2)+'\n')
  const archive = spawnSync('tar',['-czf',output,'-C',staging,'runtime'],{ stdio:'inherit' })
  assert.equal(archive.status,0,'Producer archive creation failed')
  const receipt = { schemaVersion:1,source,archive:output,bytes:lstatSync(output).size,
    sha256:sha(readFileSync(output)),manifestSha256:sha(readFileSync(join(runtime,'operator-manifest.json'))),
    files:Object.keys(inventory).length,nodeRequired:'>=18',targetNpmRequired:false }
  writeFileSync(output+'.receipt.json',JSON.stringify(receipt,null,2)+'\n',{ flag:'wx' })
  console.log(JSON.stringify(receipt))
} finally {
  assert.equal(dirname(staging),resolve(tmpdir()))
  assert(staging.startsWith(join(resolve(tmpdir()),'nexus-node-operator-')))
  rmSync(staging,{ recursive:true,force:true })
}
