/**
 * Official Node client for the Nexus VFS gRPC service.
 *
 * The service definition comes from this repository's own
 * `proto/nexus/grpc/vfs/vfs.proto`, which `scripts/sync-proto.mjs` compiles
 * into a module at build time, so a Node consumer and the server are
 * wire-compatible by construction rather than by convention. It is parsed from
 * memory rather than read at runtime: protobufjs resolves `fs` dynamically and
 * a bundler leaves that null, which is how a bundled consumer used to fail.
 *
 * Pure JavaScript over `@grpc/grpc-js` — no native addon, so consumers
 * need neither a Rust toolchain to install nor an ABI rebuild per Electron
 * release.
 */

import { readFileSync } from 'node:fs'

import * as grpc from '@grpc/grpc-js'
import * as protoLoader from '@grpc/proto-loader'
import protobuf from 'protobufjs'

import { VFS_PROTO } from './generated/proto.js'

/**
 * The DNS SAN every `nexusd-cluster` node certificate carries. An mTLS
 * client validates against this name rather than the dialed host/IP, so a
 * cluster reachable on several addresses still presents one identity.
 */
export const DEFAULT_CLUSTER_SERVER_NAME = 'nexus-node'

/** Default bound on how long a call waits for the channel to come up. */
export const DEFAULT_CONNECT_TIMEOUT_MS = 30_000

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
  /**
   * How long a call may wait for the channel to come up, in milliseconds.
   * Calls queue rather than fail while the connection is being established --
   * the Rust client this replaces did the same, and callers dial a daemon they
   * have just spawned. Defaults to
   * {@link DEFAULT_CONNECT_TIMEOUT_MS}; the wait is bounded so an unreachable
   * server surfaces as DEADLINE_EXCEEDED instead of hanging.
   */
  connectTimeoutMs?: number
}

interface UnaryClient {
  Call: GrpcMethod<CallRequest, CallResponse>
  Read: GrpcMethod<ReadRequest, ReadResponse>
  Write: GrpcMethod<WriteRequest, WriteResponse>
  Delete: GrpcMethod<DeleteRequest, DeleteResponse>
  Ping: GrpcMethod<PingRequest, PingResponse>
  StreamReadAt: GrpcMethod<StreamReadAtRequest, StreamReadAtResponse>
  StreamWriteNowait: GrpcMethod<StreamWriteRequest, StreamWriteResponse>
  close(): void
}

type GrpcMethod<Req, Res> = (
  request: Req,
  metadata: grpc.Metadata,
  options: grpc.CallOptions,
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
interface StreamReadAtRequest {
  path: string
  offset: string
  blocking: boolean
  timeout_ms: string
  auth_token: string
}
interface StreamReadAtResponse {
  data: Buffer
  next_offset: string
  eof: boolean
  is_error: boolean
  error_payload: Buffer
  timed_out: boolean
}
interface StreamWriteRequest {
  path: string
  data: Buffer
  auth_token: string
}
interface StreamWriteResponse {
  offset: string
  is_error: boolean
  error_payload: Buffer
}

/** One non-blocking read from an IPC stream. */
export interface StreamReadResult {
  data: Buffer
  /** Where the next read should pick up. */
  nextOffset: string
  /** No data available right now. Not end of stream. */
  eof: boolean
  /**
   * A blocking read reached its timeout with no frame -- a normal long-poll
   * expiry, so re-read from the same offset. `eof` is also true for older
   * servers, which is why a reader that only checks `eof` still re-polls;
   * a real disconnect raises instead.
   */
  timedOut: boolean
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
    const root = protobuf.parse(VFS_PROTO, { keepCase: true }).root
    const definition = protoLoader.fromJSON(root.toJSON(), PROTO_LOADER_OPTIONS)
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
  private readonly connectTimeoutMs: number

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

    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS
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
   * Liveness check: the typed `Ping` RPC, which answers with the zone that
   * served the call — so a success names a live zone rather than proving a
   * socket accepted.
   *
   * This used to go through the generic `Call` surface, which does not carry
   * a `ping` method and never has: every call came back `unknown Call
   * method: ping`. Reach for `serverInfo` when you want the fields; this
   * returns the version string for callers that just want a heartbeat.
   */
  async ping(authToken: string): Promise<string> {
    const info = await this.serverInfo(authToken)
    return info.version
  }

  /**
   * Append bytes to an IPC stream. Does not wait for a reader.
   */
  async streamWrite(path: string, data: Buffer, authToken: string): Promise<void> {
    const response = await this.unary<StreamWriteRequest, StreamWriteResponse>(
      'StreamWriteNowait',
      'stream write',
      { path, data, auth_token: authToken },
    )
    if (response.is_error) throw vfsError(response.error_payload, 'stream write')
  }

  /**
   * Read from an IPC stream at `offset`. Non-blocking by default; pass
   * `blocking` with a `timeoutMs` to long-poll. A closed stream or an exited
   * writer raises -- that is the disconnect signal, distinct from `eof`.
   */
  async streamReadAt(
    path: string,
    offset: string,
    authToken: string,
    options: { blocking?: boolean; timeoutMs?: number } = {},
  ): Promise<StreamReadResult> {
    const response = await this.unary<StreamReadAtRequest, StreamReadAtResponse>(
      'StreamReadAt',
      'stream read',
      {
        path,
        offset,
        blocking: options.blocking ?? false,
        timeout_ms: String(options.timeoutMs ?? 0),
        auth_token: authToken,
      },
    )
    if (response.is_error) throw vfsError(response.error_payload, 'stream read')
    return {
      data: response.data?.length ? response.data : Buffer.alloc(0),
      nextOffset: response.next_offset ?? offset,
      eof: response.eof ?? false,
      timedOut: response.timed_out ?? false,
    }
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
      // Queue the call while the channel connects instead of failing fast:
      // callers dial a daemon they have just spawned, and grpc-js otherwise
      // rejects with an empty status before the first connection lands. In
      // grpc-js this is a Metadata flag, not a CallOption.
      const metadata = new grpc.Metadata({ waitForReady: true })
      const callOptions: grpc.CallOptions = { deadline: Date.now() + this.connectTimeoutMs }
      const method = this.client[rpc] as unknown as GrpcMethod<Req, Res>
      method.call(this.client, request, metadata, callOptions, (error, response) => {
        if (error) {
          // Name the status, not just the detail text. Callers distinguish a
          // missing plugin method (UNIMPLEMENTED) from a real failure by
          // matching on the message, and the detail alone need not say which.
          const status = grpc.status[error.code] ?? error.code
          reject(new Error(`gRPC ${operation} failed: ${status}: ${error.details || error.message}`))
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
