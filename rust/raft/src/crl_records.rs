//! Existing collaboration CRL keys shared by the typed writer and readers.

const SNAPSHOT_PREFIX: &str = "crl-v1:";
const REVOKED_PREFIX: &str = "certificate-revoked-v1:";

pub(crate) fn is_crl_record(namespace: &str, key: &str) -> bool {
    namespace == contracts::constants::CONTROL_NS_COLLABORATION
        && (key.starts_with(SNAPSHOT_PREFIX) || key.starts_with(REVOKED_PREFIX))
}

#[cfg(all(feature = "grpc", has_protos))]
pub(crate) const REVOKED: &[u8] = b"collaboration-certificate-revoked-v1";

#[cfg(all(feature = "grpc", has_protos))]
pub(crate) fn snapshot_key(authority: &[u8; 32]) -> String {
    format!("{SNAPSHOT_PREFIX}{}", hex(authority))
}

/// The caller must canonicalize and validate the certificate serial first.
#[cfg(all(feature = "grpc", has_protos))]
pub(crate) fn revoked_key(authority: &[u8; 32], serial: &[u8]) -> String {
    format!("{REVOKED_PREFIX}{}:{}", hex(authority), hex(serial))
}

#[cfg(all(feature = "grpc", has_protos))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
