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

import {
  CORE_METADATA_PROTO,
  RAFT_COMMANDS_PROTO,
  RAFT_TRANSPORT_PROTO,
  VFS_PROTO,
} from './generated/proto.js'

/**
 * The DNS SAN every `nexusd-cluster` node certificate carries. An mTLS
 * client validates against this name rather than the dialed host/IP, so a
 * cluster reachable on several addresses still presents one identity.
 */
export const DEFAULT_CLUSTER_SERVER_NAME = 'nexus-node'

/** Default bound on how long a call waits for the channel to come up. */
export const DEFAULT_CONNECT_TIMEOUT_MS = 30_000

/**
 * Head-room added to a blocking read's own timeout when setting its RPC
 * deadline. The daemon answers a long poll with `timed_out` at `timeoutMs`;
 * the deadline only needs to outlast that answer's trip back, so this covers
 * scheduling and network jitter rather than the wait itself.
 */
export const BLOCKING_READ_DEADLINE_MARGIN_MS = 15_000

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
   *
   * This bounds the wait for the channel, NOT the server's own processing: a
   * blocking `streamReadAt` sets its deadline from the poll it asked for. See
   * {@link blockingReadMarginMs}.
   */
  connectTimeoutMs?: number
  /**
   * Head-room added to a blocking read's `timeoutMs` when setting that call's
   * deadline. Defaults to {@link BLOCKING_READ_DEADLINE_MARGIN_MS}; lower it
   * in tests that need the deadline to expire quickly.
   */
  blockingReadMarginMs?: number
}

interface UnaryClient {
  Call: GrpcMethod<CallRequest, CallResponse>
  Read: GrpcMethod<ReadRequest, ReadResponse>
  Write: GrpcMethod<WriteRequest, WriteResponse>
  Delete: GrpcMethod<DeleteRequest, DeleteResponse>
  Ping: GrpcMethod<PingRequest, PingResponse>
  Stat: GrpcMethod<StatRequest, StatResponse>
  Readdir: GrpcMethod<ReaddirRequest, ReaddirResponse>
  Mkdir: GrpcMethod<MkdirRequest, MkdirResponse>
  StreamReadAt: GrpcMethod<StreamReadAtRequest, StreamReadAtResponse>
  StreamWriteNowait: GrpcMethod<StreamWriteRequest, StreamWriteResponse>
  Lock: GrpcMethod<LockRequest, LockResponse>
  Unlock: GrpcMethod<UnlockRequest, UnlockResponse>
  Watch: GrpcMethod<WatchRequest, WatchResponse>
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
interface StatRequest {
  path: string
  auth_token: string
  zone_id: string
}
interface StatResponse {
  found: boolean
  path: string
  size: string
  content_id: string
  mime_type: string
  is_directory: boolean
  entry_type: number
  mode: number
  version: number
  zone_id: string
  created_at_ms?: string
  modified_at_ms?: string
  last_writer_address: string
  link_target: string
  owner_id: string
  is_error: boolean
  error_payload: Buffer
}
interface ReaddirRequest {
  path: string
  auth_token: string
  zone_id: string
}
interface ReaddirEntry {
  name: string
  entry_type: number
}
interface ReaddirResponse {
  entries: ReaddirEntry[]
  is_error: boolean
  error_payload: Buffer
}
interface MkdirRequest {
  path: string
  auth_token: string
  parents: boolean
  exist_ok: boolean
}
interface MkdirResponse {
  hit: boolean
  is_error: boolean
  error_payload: Buffer
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
interface LockRequest {
  path: string
  auth_token: string
  lock_id: string
  timeout_ms: string
}
interface LockResponse {
  acquired: boolean
  lock_id: string
  is_error: boolean
  error_payload: Buffer
}
interface UnlockRequest {
  path: string
  auth_token: string
  lock_id: string
  force: boolean
}
interface UnlockResponse {
  released: boolean
  is_error: boolean
  error_payload: Buffer
}
interface WatchRequest {
  path: string
  auth_token: string
  timeout_ms: string
}
interface WatchResponse {
  matched: boolean
  path: string
  event_type: string
  is_error: boolean
  error_payload: Buffer
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
/** One entry from {@link NexusVfsClient.readdir}. */
export interface NexusDirEntry {
  /** Child path, as the daemon reports it. */
  name: string
  /** `DT_*` code: 0 file, 1 dir, 2 mount, 4 stream. */
  entryType: number
}

/** Metadata from {@link NexusVfsClient.stat}. */
export interface NexusStat {
  path: string
  size: number
  contentId?: string
  mimeType?: string
  isDirectory: boolean
  entryType: number
  mode: number
  version: number
  zoneId?: string
  createdAtMs?: number
  modifiedAtMs?: number
  /** Origin node for federated content; powers cross-node fetch. */
  lastWriterAddress?: string
  linkTarget?: string
  ownerId?: string
}

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

let cachedZoneApiConstructor: grpc.ServiceClientConstructor | null = null

/**
 * The zone-api plane's service constructor.
 *
 * Unlike the VFS proto this one is a closure: `transport.proto` imports
 * `commands.proto`, which imports `core/metadata.proto`. protobufjs resolves
 * an import against what is already in the root, so all three parse into one
 * root, leaf first — parsing only the file that declares the service would
 * leave `RaftCommand` and its neighbours unresolvable.
 */
function zoneApiConstructor(): grpc.ServiceClientConstructor {
  if (!cachedZoneApiConstructor) {
    const root = new protobuf.Root()
    for (const source of [CORE_METADATA_PROTO, RAFT_COMMANDS_PROTO, RAFT_TRANSPORT_PROTO]) {
      protobuf.parse(source, root, { keepCase: true })
    }
    root.resolveAll()
    const definition = protoLoader.fromJSON(root.toJSON(), PROTO_LOADER_OPTIONS)
    const loaded = grpc.loadPackageDefinition(definition) as unknown as {
      nexus: { raft: { ZoneApiService: grpc.ServiceClientConstructor } }
    }
    cachedZoneApiConstructor = loaded.nexus.raft.ZoneApiService
  }
  return cachedZoneApiConstructor
}

/**
 * A failed RPC, carrying the gRPC status as data.
 *
 * The status name is in the message for a human, but a caller deciding what
 * to do next reads {@link status}: matching the text means a server-supplied
 * detail that happens to contain a status name is misread as that status.
 */
export class NexusRpcError extends Error {
  /** Numeric gRPC status code. */
  readonly code: number
  /** Status name, e.g. `DEADLINE_EXCEEDED`. */
  readonly status: string
  /** The operation label this client used, e.g. `stream read`. */
  readonly operation: string

  constructor(code: number, status: string, operation: string, detail: string) {
    super(`gRPC ${operation} failed: ${status}: ${detail}`)
    this.name = 'NexusRpcError'
    this.code = code
    this.status = status
    this.operation = operation
  }
}

/** Channel terms shared by every plane this package dials. */
interface Dialled {
  target: string
  credentials: grpc.ChannelCredentials
  channelOptions: grpc.ChannelOptions
}

/**
 * Resolve the endpoint and TLS material once, so both planes dial a daemon on
 * identical terms and neither grows its own copy of the credential rules.
 */
function dial(endpoint: string, options: NexusVfsClientOptions): Dialled {
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

  return { target: toGrpcTarget(endpoint), credentials, channelOptions }
}

/**
 * One unary call. Shared by every plane: the queue-while-connecting and
 * deadline rules are channel behaviour, not VFS behaviour.
 */
function invoke<Req, Res>(
  owner: object,
  method: GrpcMethod<Req, Res>,
  operation: string,
  request: Req,
  deadlineMs: number,
): Promise<Res> {
  return new Promise((resolve, reject) => {
    // Queue the call while the channel connects instead of failing fast:
    // callers dial a daemon they have just spawned, and grpc-js otherwise
    // rejects with an empty status before the first connection lands. In
    // grpc-js this is a Metadata flag, not a CallOption.
    const metadata = new grpc.Metadata({ waitForReady: true })
    const callOptions: grpc.CallOptions = { deadline: Date.now() + deadlineMs }
    method.call(owner, request, metadata, callOptions, (error, response) => {
      if (error) {
        const status = String(grpc.status[error.code] ?? error.code)
        reject(new NexusRpcError(error.code, status, operation, error.details || error.message))
        return
      }
      resolve(response)
    })
  })
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
  private readonly blockingReadMarginMs: number

  /**
   * Connect to `endpoint`, plaintext by default — that is what the
   * trusted-loopback `serve-local` daemon (`--no-tls`) serves. Pass
   * `options.tls`, or use {@link withMtls}, for an auth-on cluster. The
   * connection is lazy: it is established on the first RPC.
   */
  constructor(endpoint: string, options: NexusVfsClientOptions = {}) {
    const Service = serviceConstructor()
    const { target, credentials, channelOptions } = dial(endpoint, options)

    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS
    this.blockingReadMarginMs =
      options.blockingReadMarginMs ?? BLOCKING_READ_DEADLINE_MARGIN_MS
    this.target = target
    this.client = new Service(target, credentials, channelOptions) as unknown as UnaryClient
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
   * Metadata for a VFS path, or `null` when the path does not exist.
   *
   * `null` means the daemon answered and said "no such path" — every other
   * failure throws. Callers that collapse both into a boolean lose the
   * distinction that matters: a probe which cannot tell "absent" from
   * "the call failed" reports a healthy-looking `false` forever.
   */
  async stat(path: string, authToken: string): Promise<NexusStat | null> {
    const response = await this.unary<StatRequest, StatResponse>('Stat', 'stat', {
      path,
      auth_token: authToken,
      zone_id: '',
    })
    if (response.is_error) throw vfsError(response.error_payload, 'stat')
    if (!response.found) return null
    return {
      path: response.path,
      size: Number(response.size ?? 0),
      contentId: response.content_id || undefined,
      mimeType: response.mime_type || undefined,
      isDirectory: response.is_directory,
      entryType: response.entry_type,
      mode: response.mode,
      version: response.version,
      zoneId: response.zone_id || undefined,
      createdAtMs: response.created_at_ms ? Number(response.created_at_ms) : undefined,
      modifiedAtMs: response.modified_at_ms ? Number(response.modified_at_ms) : undefined,
      lastWriterAddress: response.last_writer_address || undefined,
      linkTarget: response.link_target || undefined,
      ownerId: response.owner_id || undefined,
    }
  }

  /**
   * Does the path exist? Throws on any failure that is not a clean
   * "not found" — see {@link stat}.
   */
  async exists(path: string, authToken: string): Promise<boolean> {
    return (await this.stat(path, authToken)) !== null
  }

  /** List a directory's immediate children. */
  async readdir(path: string, authToken: string): Promise<NexusDirEntry[]> {
    const response = await this.unary<ReaddirRequest, ReaddirResponse>('Readdir', 'readdir', {
      path,
      auth_token: authToken,
      zone_id: '',
    })
    if (response.is_error) throw vfsError(response.error_payload, 'readdir')
    return (response.entries ?? []).map((e) => ({ name: e.name, entryType: e.entry_type }))
  }

  /**
   * Create a directory. `parents` creates missing ancestors; `existOk`
   * makes an already-present directory a success rather than an error.
   */
  async mkdir(
    path: string,
    authToken: string,
    options: { parents?: boolean; existOk?: boolean } = {},
  ): Promise<void> {
    const response = await this.unary<MkdirRequest, MkdirResponse>('Mkdir', 'mkdir', {
      path,
      auth_token: authToken,
      parents: options.parents ?? false,
      exist_ok: options.existOk ?? false,
    })
    if (response.is_error) throw vfsError(response.error_payload, 'mkdir')
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
    // A blocking read asks the daemon to hold the response for up to
    // `timeoutMs`, so the RPC must outlive the poll it just requested. Bounding
    // it by `connectTimeoutMs` instead made every long poll at or above that
    // value expire on the client first: the caller saw DEADLINE_EXCEEDED rather
    // than the daemon's own `timed_out` answer, and — because a throw from this
    // method is the stream-closed signal — reported a live writer as exited.
    const deadlineMs =
      options.blocking && options.timeoutMs
        ? options.timeoutMs + this.blockingReadMarginMs
        : undefined
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
      deadlineMs,
    )
    if (response.is_error) throw vfsError(response.error_payload, 'stream read')
    return {
      data: response.data?.length ? response.data : Buffer.alloc(0),
      nextOffset: response.next_offset ?? offset,
      eof: response.eof ?? false,
      timedOut: response.timed_out ?? false,
    }
  }

  /**
   * Take the advisory lock on `path`. The kernel holds this path's lock as
   * Exclusive with a single holder, and leases it for `timeoutMs`, so a holder
   * that dies releases it without operator action.
   *
   * `acquired: false` is contention, not failure -- the caller backs off. Only
   * a throw means the call itself failed.
   */
  async lock(
    path: string,
    authToken: string,
    options: { lockId?: string; timeoutMs?: number } = {},
  ): Promise<{ acquired: boolean; lockId: string }> {
    const response = await this.unary<LockRequest, LockResponse>('Lock', 'lock', {
      path,
      auth_token: authToken,
      lock_id: options.lockId ?? '',
      timeout_ms: String(options.timeoutMs ?? 0),
    })
    if (response.is_error) throw vfsError(response.error_payload, 'lock')
    return { acquired: response.acquired ?? false, lockId: response.lock_id ?? '' }
  }

  /** Release a lock taken by `lock`. `force` drops it without owning `lockId`. */
  async unlock(
    path: string,
    authToken: string,
    options: { lockId?: string; force?: boolean } = {},
  ): Promise<boolean> {
    const response = await this.unary<UnlockRequest, UnlockResponse>('Unlock', 'unlock', {
      path,
      auth_token: authToken,
      lock_id: options.lockId ?? '',
      force: options.force ?? false,
    })
    if (response.is_error) throw vfsError(response.error_payload, 'unlock')
    return response.released ?? false
  }

  /**
   * Block until a file event matches `path`, inotify-shaped.
   *
   * `matched: false` means the wait expired with no event -- re-issue at the
   * same path to keep following. As with the blocking branch of
   * `streamReadAt`, the RPC deadline must outlive the wait the daemon was just
   * asked to hold, or the client expires first and a quiet-but-healthy watch
   * reads as a failure.
   */
  async watch(
    path: string,
    authToken: string,
    options: { timeoutMs?: number } = {},
  ): Promise<{ matched: boolean; path: string; eventType: string }> {
    const deadlineMs = options.timeoutMs
      ? options.timeoutMs + this.blockingReadMarginMs
      : undefined
    const response = await this.unary<WatchRequest, WatchResponse>(
      'Watch',
      'watch',
      { path, auth_token: authToken, timeout_ms: String(options.timeoutMs ?? 0) },
      deadlineMs,
    )
    if (response.is_error) throw vfsError(response.error_payload, 'watch')
    return {
      matched: response.matched ?? false,
      path: response.path ?? path,
      eventType: response.event_type ?? '',
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

  private unary<Req, Res>(
    rpc: keyof UnaryClient,
    operation: string,
    request: Req,
    deadlineMs?: number,
  ): Promise<Res> {
    // `connectTimeoutMs` bounds how long a call waits for the channel, which is
    // the right bound for an RPC the server answers immediately. A call that
    // asks the server to hold the response needs its own, longer bound — see
    // the blocking branch of `streamReadAt`.
    return invoke(
      this.client,
      this.client[rpc] as unknown as GrpcMethod<Req, Res>,
      operation,
      request,
      deadlineMs ?? this.connectTimeoutMs,
    )
  }
}

/** A freshly minted session credential. This client never persists it. */
export interface SessionCredential {
  certPem: Buffer
  keyPem: Buffer
  caPem: Buffer
  /** The minted subject (`session-<uuid>`), so a holder can log what it has. */
  subjectId: string
}

interface MintSessionAgentRequest {
  owner_id: string
  validity_secs: string
}
interface MintSessionAgentResponse {
  success: boolean
  error?: string
  agent_cert_pem: Buffer
  agent_key_pem: Buffer
  ca_pem: Buffer
  subject_id: string
}
interface RevokeAgentCertRequest {
  agent_cert_pem: Buffer
}
interface RevokeAgentCertResponse {
  success: boolean
  error?: string
}

interface ZoneApiMethods {
  MintSessionAgent: GrpcMethod<MintSessionAgentRequest, MintSessionAgentResponse>
  RevokeAgentCert: GrpcMethod<RevokeAgentCertRequest, RevokeAgentCertResponse>
  close(): void
}

/**
 * The zone-api plane: session credentials and their revocation.
 *
 * Separate from the VFS client because it is a separate service with its own
 * authentication rule — these RPCs authenticate the caller by its mTLS
 * certificate and take no auth token, where every VFS call carries one. The
 * two planes share how they dial, not what they expose.
 *
 * The allow-list administration RPCs beside these are node-gated by design, so
 * they are deliberately absent: a client holding an agent certificate could
 * never call them.
 */
export class NexusZoneApiClient {
  /** The resolved `host:port` this client dials. */
  readonly target: string

  private readonly client: ZoneApiMethods
  private readonly connectTimeoutMs: number

  constructor(endpoint: string, options: NexusVfsClientOptions = {}) {
    const Service = zoneApiConstructor()
    const { target, credentials, channelOptions } = dial(endpoint, options)
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS
    this.target = target
    this.client = new Service(target, credentials, channelOptions) as unknown as ZoneApiMethods
  }

  /** Connect with mutual TLS, which an auth-on cluster requires. */
  static withMtls(
    endpoint: string,
    tls: NexusVfsTlsConfig,
    options: Omit<NexusVfsClientOptions, 'tls'> = {},
  ): NexusZoneApiClient {
    return new NexusZoneApiClient(endpoint, { ...options, tls })
  }

  /**
   * Mint a session credential bound to `ownerId`.
   *
   * The subject is not the caller's to choose: the daemon mints a fresh
   * `session-<uuid>` per call, so nobody can ask for a stable or a colliding
   * identity. The owner is signed in as a `nexus://owner/` SAN and read back
   * kernel-side as the operation's principal.
   *
   * Reachable with an agent certificate — that is the point: a front door
   * obtains an identity for a person without ever holding a node certificate,
   * which would carry admin and system privilege it has no use for. The caller
   * must be on the daemon's replicated allow-list, and a refusal is terse by
   * design, because a caller that learns why it was refused learns about the
   * list.
   *
   * The owner's truthfulness stays the caller's responsibility: this stops an
   * agent forging its OWN identity, it does not make the cluster an authority
   * on who a person is.
   */
  async mintSessionAgent(
    ownerId: string,
    options: { validitySecs: number },
  ): Promise<SessionCredential> {
    const response = await invoke<MintSessionAgentRequest, MintSessionAgentResponse>(
      this.client,
      this.client.MintSessionAgent,
      'mint session agent',
      { owner_id: ownerId, validity_secs: String(options.validitySecs) },
      this.connectTimeoutMs,
    )
    if (!response.success) {
      throw new Error(`mint session agent refused: ${response.error || 'no reason given'}`)
    }
    return {
      certPem: response.agent_cert_pem,
      keyPem: response.agent_key_pem,
      caPem: response.ca_pem,
      subjectId: response.subject_id,
    }
  }

  /**
   * Revoke a credential by handing back the certificate itself.
   *
   * A session credential is never written to disk, so there is no bundle to
   * read a serial out of — the holder is the one party that has it. The daemon
   * verifies the certificate chains to its own CA before recording anything.
   * Revocation lands on a CRL refresh, so it is eventually consistent.
   */
  async revokeAgentCert(certPem: Buffer): Promise<void> {
    const response = await invoke<RevokeAgentCertRequest, RevokeAgentCertResponse>(
      this.client,
      this.client.RevokeAgentCert,
      'revoke agent cert',
      { agent_cert_pem: certPem },
      this.connectTimeoutMs,
    )
    if (!response.success) {
      throw new Error(`revoke agent cert failed: ${response.error || 'no reason given'}`)
    }
  }

  /** Close the underlying channel. */
  close(): void {
    this.client.close()
  }
}

function readPem(path: string, what: string): Buffer {
  try {
    return readFileSync(path)
  } catch (error) {
    throw new Error(`read nexus ${what} '${path}': ${(error as Error).message}`)
  }
}
