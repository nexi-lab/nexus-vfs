import { createHash, createPrivateKey, X509Certificate } from 'node:crypto'

/** A freshly minted credential. The client never persists its private key. */
export interface SessionCredential {
  certPem: Buffer
  keyPem: Buffer
  caPem: Buffer
  subjectId: string
}

/** The issuer's owner-bound TLS name; independent of the runtime address. */
export function userRuntimeServerName(ownerId: string): string {
  if (!ownerId || Buffer.byteLength(ownerId) > 256 || /\p{Cc}/u.test(ownerId)) {
    throw new Error('invalid user runtime owner')
  }
  return 'nexus-user-' + createHash('sha256').update(ownerId).digest('hex').slice(0, 40)
}

/** Validate the signed runtime capabilities before mint acceptance or delivery. */
export function assertUserRuntimeCredential(credential: SessionCredential, ownerId: string, maxValiditySecs: number): void {
  const certificate = new X509Certificate(credential.certPem)
  const ca = new X509Certificate(credential.caPem)
  const serverName = userRuntimeServerName(ownerId)
  if (certificate.ca || certificate.checkHost(serverName, { subject: 'never' }) !== serverName
    || !certificate.verify(ca.publicKey) || !certificate.checkPrivateKey(createPrivateKey(credential.keyPem))
    || Date.parse(certificate.validFrom) > Date.now() || Date.parse(certificate.validTo) <= Date.now()
    || (Date.parse(certificate.validTo) - Date.parse(certificate.validFrom)) / 1000 > maxValiditySecs
    || !/^session-[0-9a-f-]{36}$/.test(credential.subjectId)
    || !certificate.subjectAltName?.split(', ').includes(`URI:nexus://agent/${credential.subjectId}`)
    || !certificate.subjectAltName?.split(', ').includes(`URI:nexus://owner/${ownerId}`)
    || certificate.subjectAltName?.includes('URI:nexus://zone/')
    || !certificate.keyUsage?.includes('1.3.6.1.5.5.7.3.1')
    || !certificate.keyUsage?.includes('1.3.6.1.5.5.7.3.2')) {
    throw new Error('user runtime credential does not match its signed owner or capabilities')
  }
}

/** Bytes for the standard AgentCredential manifest and its referenced PEMs. */
export interface UserRuntimeCredentialBundle {
  manifestName: string
  manifest: Buffer
  files: Readonly<Record<string, Buffer>>
}

/**
 * Prepare a serve-user bundle without writing secrets to disk. Write its files
 * into runtime tmpfs, then atomically replace manifestName with manifest. Unique
 * generation filenames keep readers from combining an old cert and a new key.
 */
export function createUserRuntimeCredentialBundle(ownerId: string, credential: SessionCredential): UserRuntimeCredentialBundle {
  assertUserRuntimeCredential(credential, ownerId, 300)
  const generation = createHash('sha256').update(credential.certPem).digest('hex')
  const ca = `${generation}.ca.pem`
  const cert = `${generation}.cert.pem`
  const key = `${generation}.key.pem`
  return {
    manifestName: 'credential.json',
    manifest: Buffer.from(JSON.stringify({ version: 1, agent: credential.subjectId,
      server_name: userRuntimeServerName(ownerId), ca, cert, key })),
    files: { [ca]: credential.caPem, [cert]: credential.certPem, [key]: credential.keyPem },
  }
}
