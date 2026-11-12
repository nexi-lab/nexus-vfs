//! One credential snapshot shared by the transports of a running node.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use super::TlsConfig;

/// The local transport policy, supplied by the credential owner.
pub enum TlsPolicy {
    Plaintext,
    Configured(TlsConfig),
    Rejected(&'static str),
}

/// Immutable material and identity for one credential installation.
///
/// Identity is allocation based: reinstalling identical bytes still invalidates
/// a connection admitted before the replacement.
#[derive(Clone)]
pub struct TlsSnapshot(Arc<InstalledTls>);

struct InstalledTls {
    policy: TlsPolicy,
    validity: Result<Option<(i64, i64)>, &'static str>,
}

impl InstalledTls {
    fn new(policy: TlsPolicy) -> Self {
        let validity = match &policy {
            TlsPolicy::Configured(tls) => credential_validity(&tls.cert_pem).map(Some),
            TlsPolicy::Plaintext | TlsPolicy::Rejected(_) => Ok(None),
        };
        Self { policy, validity }
    }
}

fn credential_validity(cert_pem: &[u8]) -> Result<(i64, i64), &'static str> {
    use x509_parser::prelude::FromDer;
    let der = super::first_certificate_der(cert_pem, "local TLS certificate")
        .map_err(|_| "local TLS certificate PEM is invalid")?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|_| "local TLS certificate DER is invalid")?;
    Ok((
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    ))
}

impl TlsSnapshot {
    /// Whether this installation selects mTLS; validity is checked by `config`.
    pub fn uses_tls(&self) -> bool {
        matches!(&self.0.policy, TlsPolicy::Configured(_))
    }

    pub fn config(&self) -> Result<Option<&TlsConfig>, &'static str> {
        if let Some((not_before, not_after)) = self.0.validity? {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "local TLS clock is before the epoch")?
                .as_secs();
            let now = i64::try_from(now).map_err(|_| "local TLS clock is out of range")?;
            if now < not_before || now >= not_after {
                return Err("local TLS credential is outside its validity window");
            }
        }
        self.configured_material()
    }

    /// Prepare listener trust without admitting a request or a handshake.
    /// A listener may wait for a projected replacement of an expired certificate.
    pub(super) fn configured_material(&self) -> Result<Option<&TlsConfig>, &'static str> {
        self.0.validity?;
        match &self.0.policy {
            TlsPolicy::Plaintext => Ok(None),
            TlsPolicy::Configured(tls) => Ok(Some(tls)),
            TlsPolicy::Rejected(reason) => Err(reason),
        }
    }

    pub fn same_installation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for TlsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self.0.policy {
            TlsPolicy::Plaintext => "TlsSnapshot(plaintext)",
            TlsPolicy::Configured(_) => "TlsSnapshot(configured)",
            TlsPolicy::Rejected(_) => "TlsSnapshot(rejected)",
        })
    }
}

/// Shared live credentials. Certificate authorization belongs to the caller.
///
/// Cache lookup/publication uses a read transaction, so replacement cannot
/// interleave with publishing a channel established from an older snapshot.
#[derive(Clone, Debug)]
pub struct SharedTlsConfig(Arc<RwLock<TlsSnapshot>>);

impl SharedTlsConfig {
    pub fn new(tls: Option<TlsConfig>) -> Self {
        Self(Arc::new(RwLock::new(TlsSnapshot(Arc::new(
            InstalledTls::new(tls.map_or(TlsPolicy::Plaintext, TlsPolicy::Configured)),
        )))))
    }

    pub fn replace(&self, policy: TlsPolicy) {
        let replacement = TlsSnapshot(Arc::new(InstalledTls::new(policy)));
        *self.0.write() = replacement;
    }

    /// Publish validated credentials only while their original installation is current.
    pub fn replace_if_current(&self, expected: &TlsSnapshot, policy: TlsPolicy) -> bool {
        let replacement = TlsSnapshot(Arc::new(InstalledTls::new(policy)));
        let mut current = self.0.write();
        if !current.same_installation(expected) || current.config().is_err() {
            return false;
        }
        *current = replacement;
        true
    }

    pub fn snapshot(&self) -> TlsSnapshot {
        self.read(Clone::clone)
    }

    /// The callback is synchronous and must not reenter this credential source.
    pub fn read<T>(&self, read: impl FnOnce(&TlsSnapshot) -> T) -> T {
        read(&self.0.read())
    }

    /// Run a cache publication only while its captured installation is current.
    pub fn with_current<T>(
        &self,
        snapshot: &TlsSnapshot,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        self.read(|current| {
            (current.same_installation(snapshot) && current.config().is_ok()).then(publish)
        })
    }

    pub fn is_current(&self, snapshot: &TlsSnapshot) -> bool {
        self.read(|current| current.same_installation(snapshot) && current.config().is_ok())
    }
}

impl Default for SharedTlsConfig {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_is_shared_and_cannot_revalidate_an_old_installation() {
        let source = SharedTlsConfig::default();
        let consumer = source.clone();
        let original = consumer.snapshot();
        source.replace(TlsPolicy::Rejected("renewal unavailable"));
        assert_eq!(consumer.snapshot().config(), Err("renewal unavailable"));
        source.replace(TlsPolicy::Plaintext);
        assert!(consumer.snapshot().config().unwrap().is_none());
        assert!(!consumer.is_current(&original));
        assert!(consumer
            .with_current(&original, || panic!("stale publication"))
            .is_none());
    }

    #[test]
    fn independent_sources_do_not_share_installation_identity() {
        let first = SharedTlsConfig::default();
        let second = SharedTlsConfig::default();
        assert!(!second.is_current(&first.snapshot()));
        assert_eq!(first.with_current(&first.snapshot(), || 7), Some(7));
    }

    #[test]
    fn conditional_replacement_preserves_intervening_installations() {
        let source = SharedTlsConfig::default();
        let original = source.snapshot();
        source.replace(TlsPolicy::Plaintext);
        let reinstalled = source.snapshot();
        assert!(!source.replace_if_current(&original, TlsPolicy::Rejected("stale")));
        assert!(source.is_current(&reinstalled));
        assert!(source.replace_if_current(&reinstalled, TlsPolicy::Rejected("revoked")));
        let rejected = source.snapshot();
        assert!(!source.replace_if_current(&reinstalled, TlsPolicy::Plaintext));
        assert!(!source.replace_if_current(&rejected, TlsPolicy::Plaintext));
        assert_eq!(source.snapshot().config(), Err("revoked"));
    }

    #[test]
    fn expired_credentials_refuse_both_cached_reads_and_publication() {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let source = SharedTlsConfig::new(Some(TlsConfig {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
            ca_pem: cert.pem().into_bytes(),
        }));
        let snapshot = source.snapshot();
        assert_eq!(
            snapshot.config(),
            Err("local TLS credential is outside its validity window")
        );
        assert!(!source.is_current(&snapshot));
        assert!(source
            .with_current(&snapshot, || panic!("expired publication"))
            .is_none());
        assert!(!format!("{source:?}").contains("PRIVATE KEY"));
    }
}
