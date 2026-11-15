/** Native replica control envelopes. Embedded JSON stays opaque across languages. */
export type NexusReplicaControlRequest =
  | { apply_binding_json: Uint8Array }
  | { current_binding_json: Uint8Array }
  | { reconcile_binding_json: Uint8Array }
  | { apply_issuer_json: Uint8Array }
  | { current_issuer: Record<string, never> }
  | { reconcile_issuer_json: Uint8Array }

export interface NexusReplicaCsrRequest {
  preparation_json: Uint8Array
  publication_operation_id: string
  csr_pem: Uint8Array
  renewal?: { issued_at_unix_ms: string; signature: Uint8Array }
}

export type NexusReplicaControlState =
  | 'REPLICA_CONTROL_STATE_RESULT'
  | 'REPLICA_CONTROL_STATE_NOT_OBSERVED'
  | 'REPLICA_CONTROL_STATE_REFUSED'
  | 'REPLICA_CONTROL_STATE_UNKNOWN'

export interface NexusReplicaControlResponse {
  state: NexusReplicaControlState
  error?: string
  result_json: Buffer
}

export type NexusReplicaCsrState =
  | 'REPLICA_CSR_STATE_PUBLISHED'
  | 'REPLICA_CSR_STATE_PREPARED'
  | 'REPLICA_CSR_STATE_NOT_OBSERVED'
  | 'REPLICA_CSR_STATE_REFUSED'
  | 'REPLICA_CSR_STATE_UNKNOWN'

export interface NexusReplicaCsrResponse {
  state: NexusReplicaCsrState
  error?: string
  operation_id: string
  preparation_json: Buffer
  certificate_der: Buffer
  ca_pem: Buffer
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid replica envelope')
  return value as Record<string, unknown>
}

function fields(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  const allowed = new Set([...required, ...optional])
  if (Object.keys(value).some(key => !allowed.has(key)) || required.some(key => !Object.hasOwn(value, key))) {
    throw new Error('Invalid replica envelope fields')
  }
}

function bytes(value: unknown, requireContent: boolean): Buffer {
  if (!(value instanceof Uint8Array) || (requireContent && value.length === 0)) throw new Error('Invalid replica byte field')
  return Buffer.from(value)
}

/** Copy request bytes synchronously before dialing or waiting for a channel. */
export function copyReplicaControlRequest(value: NexusReplicaControlRequest): NexusReplicaControlRequest {
  const request = object(value)
  const names = Object.keys(request)
  if (names.length !== 1) throw new Error('Replica control requires exactly one operation')
  const field = names[0]!
  if (field === 'current_issuer') {
    fields(object(request[field]), [])
    return { current_issuer: {} }
  }
  switch (field) {
    case 'apply_binding_json': return { apply_binding_json: bytes(request[field], true) }
    case 'current_binding_json': return { current_binding_json: bytes(request[field], true) }
    case 'reconcile_binding_json': return { reconcile_binding_json: bytes(request[field], true) }
    case 'apply_issuer_json': return { apply_issuer_json: bytes(request[field], true) }
    case 'reconcile_issuer_json': return { reconcile_issuer_json: bytes(request[field], true) }
    default: throw new Error('Unknown replica control operation')
  }
}

export function copyReplicaCsrRequest(value: NexusReplicaCsrRequest): NexusReplicaCsrRequest {
  const request = object(value)
  fields(request, ['preparation_json', 'publication_operation_id', 'csr_pem'], ['renewal'])
  if (typeof request.publication_operation_id !== 'string' || !request.publication_operation_id) {
    throw new Error('Replica publication requires the original operation ID')
  }
  let renewal: NexusReplicaCsrRequest['renewal']
  if (request.renewal !== undefined) {
    const proof = object(request.renewal)
    fields(proof, ['issued_at_unix_ms', 'signature'])
    const issued = proof.issued_at_unix_ms
    if (typeof issued !== 'string' || !/^(0|[1-9][0-9]*)$/.test(issued) ||
      issued.length > 20 || BigInt(issued) > 18446744073709551615n) {
      throw new Error('Replica renewal requires an exact uint64 decimal string')
    }
    renewal = { issued_at_unix_ms: issued, signature: bytes(proof.signature, true) }
  }
  return {
    preparation_json: bytes(request.preparation_json, true),
    publication_operation_id: request.publication_operation_id,
    csr_pem: bytes(request.csr_pem, true),
    ...(renewal === undefined ? {} : { renewal }),
  }
}

function responseError(response: Record<string, unknown>): { error?: string } {
  if (response.error === undefined) return {}
  if (typeof response.error !== 'string') throw new Error('Invalid replica error field')
  return { error: response.error }
}

/** Native outcome states are observations; the controller decides recovery. */
export function decodeReplicaControlResponse(value: unknown): NexusReplicaControlResponse {
  const response = object(value)
  const state = response.state
  if (typeof state !== 'string' || !['REPLICA_CONTROL_STATE_RESULT', 'REPLICA_CONTROL_STATE_NOT_OBSERVED',
    'REPLICA_CONTROL_STATE_REFUSED', 'REPLICA_CONTROL_STATE_UNKNOWN'].includes(state)) {
    throw new Error('Invalid native replica control state; reconcile the original operation')
  }
  return { state: state as NexusReplicaControlState, ...responseError(response), result_json: bytes(response.result_json, false) }
}

export function decodeReplicaCsrResponse(value: unknown): NexusReplicaCsrResponse {
  const response = object(value)
  const state = response.state
  if (typeof state !== 'string' || !['REPLICA_CSR_STATE_PUBLISHED', 'REPLICA_CSR_STATE_PREPARED',
    'REPLICA_CSR_STATE_NOT_OBSERVED', 'REPLICA_CSR_STATE_REFUSED', 'REPLICA_CSR_STATE_UNKNOWN'].includes(state)) {
    throw new Error('Invalid native replica CSR state; reconcile the original operation')
  }
  if (typeof response.operation_id !== 'string') throw new Error('Invalid native replica operation ID')
  return {
    state: state as NexusReplicaCsrState, ...responseError(response), operation_id: response.operation_id,
    preparation_json: bytes(response.preparation_json, false),
    certificate_der: bytes(response.certificate_der, false), ca_pem: bytes(response.ca_pem, false),
  }
}
