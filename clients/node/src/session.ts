import { setTimeout as delay } from 'node:timers/promises'
import type { NexusVfsClient } from './index.js'

export const SESSION_PROTOCOL = 'acp-mailbox/1' as const
const MAX_FRAME_BYTES = 4 * 1024 * 1024

/** The control plane supplies the canonical conversation address. */
export interface NexusSessionEndpoint {
  protocol: typeof SESSION_PROTOCOL
  channel_id: string
  agent: string
  controller: string
  transcript: string
}

export interface SessionRpcMessage {
  jsonrpc: '2.0'
  id?: string | number
  method?: string
  params?: unknown
  result?: unknown
  error?: unknown
  [key: string]: unknown
}

type Payload = { type: 'rpc'; message: SessionRpcMessage } | { type: 'closed'; reason: string }
interface Frame {
  protocol: string
  channel_id: string
  sequence: number
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function rpcMessage(value: unknown): SessionRpcMessage {
  if (!isObject(value) || value.jsonrpc !== '2.0') throw new Error('Session RPC requires a JSON-RPC 2.0 object')
  if ('id' in value && typeof value.id !== 'string' && !Number.isSafeInteger(value.id)) {
    throw new Error('Session RPC ID must be a string or safe integer')
  }
  if ('method' in value) {
    if (typeof value.method !== 'string' || 'result' in value || 'error' in value) {
      throw new Error('Invalid session RPC request')
    }
  } else if (!('id' in value) || ('result' in value) === ('error' in value)) {
    throw new Error('Session RPC response requires an ID and one result or error')
  }
  return value as SessionRpcMessage
}

/** One instance survives network reconnects; a daemon restart needs a new endpoint. */
export class SessionCodec {
  private sent = 0
  private received = 0
  private readonly sender: string
  private readonly recipient: string

  constructor(readonly endpoint: NexusSessionEndpoint, side: 'agent' | 'controller' = 'controller') {
    if (endpoint.protocol !== SESSION_PROTOCOL) throw new Error(`Unsupported session protocol: ${endpoint.protocol}`)
    if (!endpoint.channel_id || !endpoint.agent || !endpoint.controller || endpoint.agent === endpoint.controller) {
      throw new Error('Session endpoint requires a channel and distinct participants')
    }
    if (!/^\/conversations\/[a-f0-9]{32}\/transcript$/.test(endpoint.transcript)) {
      throw new Error('Session endpoint must name a conversation transcript')
    }
    this.sender = side === 'agent' ? endpoint.agent : endpoint.controller
    this.recipient = side === 'agent' ? endpoint.controller : endpoint.agent
  }

  encode(payload: Payload): Buffer {
    if (payload.type === 'rpc') rpcMessage(payload.message)
    const sequence = this.sent + 1
    if (!Number.isSafeInteger(sequence)) throw new Error('Session sequence exhausted')
    const frame: Frame & Payload = {
      protocol: SESSION_PROTOCOL,
      channel_id: this.endpoint.channel_id,
      sequence,
      ...payload,
    }
    const bytes = Buffer.from(JSON.stringify({
      from: this.sender, to: this.recipient, kind: 'session', body: JSON.stringify(frame),
    }))
    if (bytes.length > MAX_FRAME_BYTES) throw new Error('Session frame exceeds the size limit')
    this.sent = sequence
    return bytes
  }

  decode(bytes: Buffer): Payload | undefined {
    const envelope: unknown = JSON.parse(bytes.toString('utf8'))
    if (!isObject(envelope) || envelope.kind !== 'session') return
    if (bytes.length > MAX_FRAME_BYTES) throw new Error('Session frame exceeds the size limit')
    if (envelope.from === this.sender && envelope.to === this.recipient) return
    if (typeof envelope.body !== 'string') throw new Error('Session envelope requires a structured string body')
    const frame: unknown = JSON.parse(envelope.body)
    if (!isObject(frame)) throw new Error('Invalid session frame')
    if (frame.channel_id !== this.endpoint.channel_id) return
    if (envelope.from !== this.recipient || envelope.to !== this.sender) {
      throw new Error('Session frame participants do not match the attachment')
    }
    if (frame.protocol !== SESSION_PROTOCOL) throw new Error(`Unsupported session protocol: ${frame.protocol}`)
    if (!Number.isSafeInteger(frame.sequence) || (frame.sequence as number) < 1) throw new Error('Invalid session sequence')
    const sequence = frame.sequence as number
    if (sequence <= this.received) return
    if (sequence !== this.received + 1) throw new Error(`Session sequence gap: expected ${this.received + 1}, received ${sequence}`)
    let payload: Payload
    if (frame.type === 'rpc') payload = { type: 'rpc', message: rpcMessage(frame.message) }
    else if (frame.type === 'closed' && typeof frame.reason === 'string') payload = { type: 'closed', reason: frame.reason }
    else throw new Error('Unknown session frame type')
    this.received = sequence
    return payload
  }
}

export interface NexusSessionTransportOptions {
  client: Pick<NexusVfsClient, 'streamReadAt' | 'streamWrite'>
  endpoint: NexusSessionEndpoint
  authToken: string
  /** Called synchronously in log order. Start asynchronous work without awaiting it here. */
  onMessage: (message: SessionRpcMessage) => void
  onClose: (reason: Error | undefined) => void
}

/**
 * The hosted-session transport used by embedders. Both hosting modes consume
 * this conversation protocol. It has no fd path or subprocess-shaped facade.
 */
export class NexusSessionTransport {
  private readonly codec: SessionCodec
  private offset = '0'
  private isClosed = false
  private isStarted = false
  private writes: Promise<void> = Promise.resolve()
  private readLoop: Promise<void> | undefined
  private readonly stopped = new AbortController()

  constructor(private readonly options: NexusSessionTransportOptions) {
    this.codec = new SessionCodec(options.endpoint)
  }

  get connected(): boolean { return this.isStarted && !this.isClosed }

  start(): void {
    if (this.isStarted || this.isClosed) throw new Error('Session transport cannot be restarted')
    this.isStarted = true
    this.readLoop = this.read()
  }

  send(message: SessionRpcMessage): Promise<void> {
    if (!this.connected) return Promise.reject(new Error('Session transport is closed'))
    // Encode before queuing so invalid input does not poison a valid channel.
    let bytes: Buffer
    try { bytes = this.codec.encode({ type: 'rpc', message }) }
    catch (error) { return Promise.reject(error) }
    return this.append(bytes)
  }

  private append(bytes: Buffer): Promise<void> {
    const write = this.writes.then(async () => {
      if (this.isClosed) throw new Error('Session transport is closed')
      await this.options.client.streamWrite(this.options.endpoint.transcript, bytes, this.options.authToken)
    })
    this.writes = write.catch((error: unknown) => {
      this.finish(new Error('Session append failed; delivery outcome is unknown', { cause: error }))
    })
    return write
  }

  async close(): Promise<void> {
    if (!this.isClosed && this.isStarted) {
      try { await this.append(this.codec.encode({ type: 'closed', reason: 'controller disconnected' })) }
      finally { this.finish(undefined) }
    } else this.finish(undefined)
    await this.readLoop
  }

  private finish(error: Error | undefined): void {
    if (this.isClosed) return
    this.isClosed = true
    this.stopped.abort()
    this.options.onClose(error)
  }

  private async read(): Promise<void> {
    try {
      let retryMs = 200
      while (!this.isClosed) {
        let result
        try {
          result = await this.options.client.streamReadAt(
            this.options.endpoint.transcript, this.offset, this.options.authToken,
            { blocking: true, timeoutMs: 1000 },
          )
          retryMs = 200
        } catch (error) {
          // Reads have no effects: keep the cursor and codec across a transient
          // gRPC failure. Writes deliberately have different retry semantics.
          const code = isObject(error) ? error.code : undefined
          if (![4, 8, 10, 14, 'DEADLINE_EXCEEDED', 'RESOURCE_EXHAUSTED', 'ABORTED', 'UNAVAILABLE'].includes(code as string | number)) throw error
          await delay(retryMs, undefined, { signal: this.stopped.signal })
          retryMs = Math.min(retryMs * 2, 5000)
          continue
        }
        if (this.isClosed) return
        if (!result.data.length) {
          // Some backends return an empty record immediately despite blocking.
          await delay(10, undefined, { signal: this.stopped.signal })
          continue
        }
        if (BigInt(result.nextOffset) <= BigInt(this.offset)) throw new Error('Session stream did not advance its cursor')
        const payload = this.codec.decode(result.data)
        this.offset = result.nextOffset
        if (payload?.type === 'closed') this.finish(new Error(payload.reason))
        else if (payload?.type === 'rpc') this.options.onMessage(payload.message)
      }
    } catch (error) {
      this.finish(error instanceof Error ? error : new Error(String(error)))
    }
  }
}
