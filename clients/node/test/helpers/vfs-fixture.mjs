import * as grpc from '@grpc/grpc-js'
import * as loader from '@grpc/proto-loader'
import protobuf from 'protobufjs'
import { NexusVfsClient } from '../../dist/index.js'
import { VFS_PROTO } from '../../dist/generated/proto.js'

export async function fixture(handlers, options = {}) {
  const root = protobuf.parse(VFS_PROTO, { keepCase: true }).root
  const definition = loader.fromJSON(root.toJSON(), { keepCase: true, defaults: true, oneofs: true, enums: String })
  const server = new grpc.Server()
  server.addService(definition['nexus.grpc.vfs.NexusVFSService'], handlers)
  const port = await new Promise((resolve, reject) => server.bindAsync(
    '127.0.0.1:0', grpc.ServerCredentials.createInsecure(),
    (error, value) => error ? reject(error) : resolve(value),
  ))
  const client = new NexusVfsClient(`127.0.0.1:${port}`, options)
  return { client, async close() {
    client.close()
    await new Promise((resolve, reject) => server.tryShutdown(error => error ? reject(error) : resolve()))
  } }
}
