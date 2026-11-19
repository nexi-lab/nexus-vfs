//! A confined runtime admits agent certificates only against a current,
//! CA-signed revocation list. Without one it refuses every request rather than
//! trust a certificate its issuer may have revoked.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kernel::kernel::OperationContext;
use lib::transport_primitives::{verify_signed_crl, VerifiedCrl, CRL_MAXIMUM_AGE_SECS};
use transport::auth::{AuthCredentials, AuthProvider};

/// How often the runtime fetches its list, the cluster's own refresh cadence.
pub(super) const REFRESH: Duration = Duration::from_secs(10);
const FETCH_TIMEOUT_SECS: u64 = 5;

/// Where a runtime reads its CA-signed revocation list.
#[derive(Clone, Debug)]
pub(crate) enum CrlSource {
    /// The issuer's enrollment endpoint (`host:port`), which serves `GetCrl`.
    Endpoint(String),
    /// A signed CRL file that another component keeps current.
    File(PathBuf),
}

impl CrlSource {
    async fn fetch(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Endpoint(address) => {
                nexus_raft::transport::call_get_crl(address, FETCH_TIMEOUT_SECS)
                    .await
                    .map_err(|error| format!("fetch revocation list from {address}: {error}"))
            }
            Self::File(path) => tokio::fs::read(path)
                .await
                .map_err(|error| format!("read revocation list {}: {error}", path.display())),
        }
    }
}

/// The runtime's authentication: certificate identity, refused while the
/// revocation list is missing or older than the freshness budget.
pub(super) struct RevocationGate {
    identity: auth::ApiKeyAuthProvider,
    ca_pem: Vec<u8>,
    current: RwLock<Option<VerifiedCrl>>,
}

impl RevocationGate {
    /// `ca_pem` is the authority the runtime trusts for client certificates;
    /// only a list it signed can revoke them.
    pub(super) fn new(identity: auth::ApiKeyAuthProvider, ca_pem: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            identity,
            ca_pem,
            current: RwLock::new(None),
        })
    }

    /// Install the source's list if it is signed, fresh and not older than the
    /// one in force. Returns whether the list in force changed.
    pub(super) async fn refresh(&self, source: &CrlSource) -> Result<bool, String> {
        let pem = source.fetch().await?;
        let crl = verify_signed_crl(&pem, &self.ca_pem)?;
        crl.check_freshness(now(), CRL_MAXIMUM_AGE_SECS)?;
        let mut current = self.current.write().expect("revocation list lock");
        if let Some(previous) = current.as_ref() {
            crl.check_successor(previous)?;
            if previous.signed_der_sha256() == crl.signed_der_sha256() {
                *current = Some(crl);
                return Ok(false);
            }
        }
        self.identity.set_revoked_serials(
            crl.revoked_serials()
                .iter()
                .cloned()
                .collect::<HashSet<_>>(),
        );
        *current = Some(crl);
        Ok(true)
    }

    fn admit(&self) -> Result<(), tonic::Status> {
        match self.current.read().expect("revocation list lock").as_ref() {
            Some(crl) if crl.check_freshness(now(), CRL_MAXIMUM_AGE_SECS).is_ok() => Ok(()),
            _ => Err(tonic::Status::unavailable(
                "certificate revocation status is not current",
            )),
        }
    }
}

impl AuthProvider for RevocationGate {
    fn resolve(&self, creds: &AuthCredentials<'_>) -> Result<OperationContext, tonic::Status> {
        self.admit()?;
        self.identity.resolve(creds)
    }

    fn resolve_forwarded_agent(
        &self,
        user_id: &str,
        agent_id: &str,
    ) -> Result<OperationContext, tonic::Status> {
        self.admit()?;
        self.identity.resolve_forwarded_agent(user_id, agent_id)
    }

    fn mode(&self) -> &'static str {
        self.identity.mode()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
