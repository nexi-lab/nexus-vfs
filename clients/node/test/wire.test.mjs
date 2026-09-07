// The service definition is built by parsing the proto in memory and handing
// the descriptor to proto-loader. Checking that the definition has the right
// shape is not enough — it can have every method and callable serializers and
// still not move bytes correctly — so exercise the serializers themselves.
//
// This does not reproduce the protobufjs 7.5.4 failure that motivated the
// version floor (that one survives a round-trip and only shows against a live
// server); it guards the narrower invariant it can actually assert offline.
import assert from 'node:assert/strict'
import test from 'node:test'

import * as grpc from '@grpc/grpc-js'
import * as protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'

import { VFS_PROTO } from '../dist/generated/proto.js'

function definition() {
  const root = protobuf.parse(VFS_PROTO, { keepCase: true }).root
  return protoLoader.fromJSON(root.toJSON(), {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  })
}

test('the Call RPC serializers round-trip', () => {
  const service = definition()['nexus.grpc.vfs.NexusVFSService']
  const call = service.Call

  assert.equal(call.path, '/nexus.grpc.vfs.NexusVFSService/Call')
  const wire = call.requestSerialize({
    method: 'get_mount_points',
    payload: Buffer.from('{"a":1}'),
    auth_token: 'tok',
  })
  assert.ok(wire.length > 0, 'the request serialized to nothing')

  const decoded = call.requestDeserialize(wire)
  assert.equal(decoded.method, 'get_mount_points')
  assert.equal(decoded.auth_token, 'tok')
  assert.equal(Buffer.from(decoded.payload).toString(), '{"a":1}')
})

test('the typed content RPCs carry bytes intact', () => {
  const service = definition()['nexus.grpc.vfs.NexusVFSService']
  const bytes = Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x80])

  const wire = service.Write.requestSerialize({
    path: '/f',
    content: bytes,
    auth_token: '',
  })
  const decoded = service.Write.requestDeserialize(wire)
  assert.equal(decoded.path, '/f')
  assert.deepEqual(Buffer.from(decoded.content), bytes)
})

test('the loaded package exposes the service constructor', () => {
  const pkg = grpc.loadPackageDefinition(definition())
  assert.equal(typeof pkg.nexus.grpc.vfs.NexusVFSService, 'function')
})
