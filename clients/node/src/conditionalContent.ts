/** Coherent file images and atomic replacement results from the typed VFS pair. */
export interface NexusVersionedContent {
  content: Buffer
  version: Buffer
}

export type NexusConditionalWriteResult =
  | { kind: 'committed'; version: Buffer }
  | { kind: 'conflict'; currentVersion: Buffer | null }

export type NexusConditionalFailureKind = 'unsupported' | 'failed' | 'unknown'

/** An uncertain write requires readback of the consumer's durable fence. */
export class NexusConditionalContentError extends Error {
  constructor(readonly kind: NexusConditionalFailureKind, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'NexusConditionalContentError'
  }
}

interface WireFailure {
  kind: string
  message: string
}

export interface ReadVersionedResponse {
  outcome?: string
  snapshot?: NexusVersionedContent
  absent?: object
  failure?: WireFailure
}

export interface WriteIfVersionResponse {
  outcome?: string
  committed_version?: Buffer
  conflict?: { current_version?: Buffer }
  failure?: WireFailure
}

function isVersion(value: unknown): value is Buffer {
  return Buffer.isBuffer(value) && value.length > 0
}

function failure(value: WireFailure): NexusConditionalContentError {
  const kind = value.kind === 'UNSUPPORTED' ? 'unsupported' : value.kind === 'FAILED' ? 'failed' : 'unknown'
  return new NexusConditionalContentError(kind, value.message || 'conditional content operation failed')
}

/** Decode the selected oneof; an incomplete response cannot represent absence. */
export function decodeVersionedContent(response: ReadVersionedResponse): NexusVersionedContent | null {
  if (response.outcome === 'snapshot' && response.snapshot &&
      Buffer.isBuffer(response.snapshot.content) && isVersion(response.snapshot.version)) return response.snapshot
  if (response.outcome === 'absent' && response.absent) return null
  if (response.outcome === 'failure' && response.failure) throw failure(response.failure)
  throw new NexusConditionalContentError('failed', 'invalid versioned-content response')
}

/** An incomplete write answer cannot prove that a replacement was rejected. */
export function decodeConditionalWrite(response: WriteIfVersionResponse): NexusConditionalWriteResult {
  if (response.outcome === 'committed_version' && isVersion(response.committed_version)) {
    return { kind: 'committed', version: response.committed_version }
  }
  if (response.outcome === 'conflict' && response.conflict) {
    const current = response.conflict.current_version
    if (current === undefined || isVersion(current)) return { kind: 'conflict', currentVersion: current ?? null }
  }
  if (response.outcome === 'failure' && response.failure) throw failure(response.failure)
  throw new NexusConditionalContentError('unknown', 'invalid conditional-write response')
}
