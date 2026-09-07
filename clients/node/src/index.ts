/**
 * Official Node client for the Nexus VFS gRPC service.
 *
 * The service definition is loaded from this repository's own
 * `proto/nexus/grpc/vfs/vfs.proto` (copied into the package by
 * `scripts/sync-proto.mjs` at build time), so a Node consumer and the
 * server are wire-compatible by construction rather than by convention.
 *
 * Pure JavaScript over `@grpc/grpc-js` — no native addon, so consumers
 * need neither a Rust toolchain to install nor an ABI rebuild per Electron
 * release.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import * as grpc from '@grpc/grpc-js'
import * as protoLoader from '@grpc/proto-loader'

const PROTO_PATH = join(
  dirname(dirname(fileURLToPath(import.meta.url))),
  'proto',
  'nexus',
  'grpc',
  'vfs',
  'vfs.proto',
)

/**
 * The DNS SAN every `nexusd-cluster` node certificate carries. An mTLS
 * client validates against this name rather than the dialed host/IP, so a
 * cluster reachable on several addresses still presents one identity.
 */
export const DEFAULT_CLUSTER_SERVER_NAME = 'nexus-node'

const PROTO_LOADER_OPTIONS: protoLoader.Options = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
}

/** Paths to the PEM material an mTLS connection needs. */
export interface NexusVfsTlsConfig {
  /** Cluster CA certificate that signed the server cert. */
  caPath: string
  /** This client's certificate. */
  certPath: string
  /** This client's private key. */
  keyPath: string
  /** Server-cert SAN to validate. Defaults to {@link DEFAULT_CLUSTER_SERVER_NAME}. */
  serverName?: string
}

export interface NexusVfsClientOptions {
  /**
   * Largest response the client will accept, in bytes. Defaults to the
   * gRPC default of 4 MiB, matching the Rust client this replaces.
   */
  maxReceiveMessageBytes?: number
  /** When set, connect with mutual TLS instead of plaintext. */
  tls?: NexusVfsTlsConfig
}

interface UnaryClient {
  Call: GrpcMethod<CallRequest, CallResponse>
  Read: GrpcMethod<ReadRequest, ReadResponse>
  Write: GrpcMethod<WriteRequest, WriteResponse>
  Delete: GrpcMethod<DeleteRequest, DeleteResponse>
  Ping: GrpcMethod<PingRequest, PingResponse>
  close(): void
}

type GrpcMethod<Req, Res> = (
  request: Req,
  callback: (error: grpc.ServiceError | null, response: Res) => void,
) => void

interface CallRequest {
  method: string
  payload: Buffer
  auth_token: string
}
interface CallResponse {
  payload: Buffer
  is_error: boolean
}
interface ReadRequest {
  path: string
  auth_token: string
}
interface ReadResponse {
  content: Buffer
  is_error: boolean
  error_payload: Buffer
}
interface WriteRequest {
  path: string
  content: Buffer
  auth_token: string
}
interface WriteResponse {
  is_error: boolean
  error_payload: Buffer
}
interface DeleteRequest {
  path: string
  auth_token: string
  recursive: boolean
}
interface DeleteResponse {
  is_error: boolean
  error_payload: Buffer
}
interface PingRequest {
  auth_token: string
}
/** Server identity and liveness, from the typed `Ping` RPC. */
export interface NexusServerInfo {
  version: string
  zone_id: string
  uptime_seconds: string
}
type PingResponse = NexusServerInfo

let cachedServiceConstructor: grpc.ServiceClientConstructor | null = null

function serviceConstructor(): grpc.ServiceClientConstructor {
  if (!cachedServiceConstructor) {
    const definition = protoLoader.loadSync(PROTO_PATH, PROTO_LOADER_OPTIONS)
    const loaded = grpc.loadPackageDefinition(definition) as unknown as {
      nexus: { grpc: { vfs: { NexusVFSService: grpc.ServiceClientConstructor } } }
    }
    cachedServiceConstructor = loaded.nexus.grpc.vfs.NexusVFSService
  }
  return cachedServiceConstructor
}

/**
 * gRPC targets are `host:port`. Callers historically passed a URL because
 * the Rust client took a tonic endpoint, so accept both spellings.
 */
function toGrpcTarget(endpoint: string): string {
  return endpoint.replace(/^https?:\/\//, '').replace(/\/+$/, '')
}

/** An in-band VFS error: the RPC succeeded, the operation did not. */
function vfsError(payload: Buffer | undefined, operation: string): Error {
  const detail = payload?.length ? payload.toString('utf8') : `gRPC ${operation} failed`
  return new Error(detail)
}

export class NexusVfsClient {
  /** The resolved `host:port` this client dials. */
  readonly target: string

  private readonly client: UnaryClient

  /**
   * Connect to `endpoint`, plaintext by default — that is what the
   * trusted-loopback `serve-local` daemon (`--no-tls`) serves. Pass
   * `options.tls`, or use {@link withMtls}, for an auth-on cluster. The
   * connection is lazy: it is established on the first RPC.
   */
  constructor(endpoint: string, options: NexusVfsClientOptions = {}) {
    const Service = serviceConstructor()
    const channelOptions: grpc.ChannelOptions = {}
    let credentials = grpc.credentials.createInsecure()

    if (options.tls) {
      const serverName = options.tls.serverName ?? DEFAULT_CLUSTER_SERVER_NAME
      credentials = grpc.credentials.createSsl(
        readPem(options.tls.caPath, 'CA certificate'),
        readPem(options.tls.keyPath, 'client key'),
        readPem(options.tls.certPath, 'client certificate'),
      )
      channelOptions['grpc.ssl_target_name_override'] = serverName
      channelOptions['grpc.default_authority'] = serverName
    }
    if (options.maxReceiveMessageBytes !== undefined) {
      channelOptions['grpc.max_receive_message_length'] = options.maxReceiveMessageBytes
    }

    this.target = toGrpcTarget(endpoint)
    this.client = new Service(this.target, credentials, channelOptions) as unknown as UnaryClient
  }

  /**
   * Connect with mutual TLS, required to reach an auth-on production
   * `nexusd-cluster` (it rejects plaintext clients). Caller identity still
   * rides the per-request auth token; the certificate authenticates the
   * process, not the user.
   */
  static withMtls(
    endpoint: string,
    tls: NexusVfsTlsConfig,
    options: Omit<NexusVfsClientOptions, 'tls'> = {},
  ): NexusVfsClient {
    return new NexusVfsClient(endpoint, { ...options, tls })
  }

  /** Generic dispatch: method name, JSON payload, auth token; JSON back. */
  async call(method: string, payload: string, authToken: string): Promise<string> {
    const response = await this.callBinary(method, Buffer.from(payload, 'utf8'), authToken)
    return response.toString('utf8')
  }

  /**
   * Generic dispatch with raw bytes both ways, for plugin methods whose
   * wire format is protobuf rather than JSON (e.g. `password-vault.*`).
   */
  async callBinary(method: string, payload: Buffer, authToken: string): Promise<Buffer> {
    const response = await this.unary<CallRequest, CallResponse>('Call', 'call', {
      method,
      payload,
      auth_token: authToken,
    })
    if (response.is_error) throw vfsError(response.payload, 'call')
    return response.payload
  }

  /** Read a VFS path. Returns raw bytes. */
  async read(path: string, authToken: string): Promise<Buffer> {
    const response = await this.unary<ReadRequest, ReadResponse>('Read', 'read', {
      path,
      auth_token: authToken,
    })
    if (response.is_error) throw vfsError(response.error_payload, 'read')
    return response.content
  }

  /** Write raw bytes to a VFS path. */
  async write(path: string, content: Buffer, authToken: string): Promise<void> {
    const response = await this.unary<WriteRequest, WriteResponse>('Write', 'write', {
      path,
      content,
      auth_token: authToken,
    })
    if (response.is_error) throw vfsError(response.error_payload, 'write')
  }

  /** Delete a VFS path. Non-recursive, matching the Rust client. */
  async delete(path: string, authToken: string): Promise<void> {
    const response = await this.unary<DeleteRequest, DeleteResponse>('Delete', 'delete', {
      path,
      auth_token: authToken,
      recursive: false,
    })
    if (response.is_error) throw vfsError(response.error_payload, 'delete')
  }

  /**
   * Liveness check through the generic dispatch path, so it exercises the
   * same route as real traffic. Returns the raw JSON response.
   */
  async ping(authToken: string): Promise<string> {
    return this.call('ping', '{}', authToken)
  }

  /** Server version, zone and uptime, from the typed `Ping` RPC. */
  async serverInfo(authToken: string): Promise<NexusServerInfo> {
    return this.unary<PingRequest, PingResponse>('Ping', 'ping', { auth_token: authToken })
  }

  /** Close the underlying channel. */
  close(): void {
    this.client.close()
  }

  private unary<Req, Res>(rpc: keyof UnaryClient, operation: string, request: Req): Promise<Res> {
    return new Promise((resolve, reject) => {
      const method = this.client[rpc] as unknown as GrpcMethod<Req, Res>
      method.call(this.client, request, (error, response) => {
        if (error) {
          reject(new Error(`gRPC ${operation} failed: ${error.details || error.message}`))
          return
        }
        resolve(response)
      })
    })
  }
}

function readPem(path: string, what: string): Buffer {
  try {
    return readFileSync(path)
  } catch (error) {
    throw new Error(`read nexus ${what} '${path}': ${(error as Error).message}`)
  }
}
