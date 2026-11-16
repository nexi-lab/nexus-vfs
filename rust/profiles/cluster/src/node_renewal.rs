//! Node certificate renewal: the daemon re-issues its own leaf through the CA
//! holder well before it expires, persists it, and serves it without a restart.
//!
//! One renewal function serves the schedule and the operator's
//! `renew-certificate`. The daemon is the only writer of its identity files and
//! generates the new key itself; the CA holder certifies the key for the Node
//! the current leaf names. The founder reaches itself over loopback, the first
//! of the candidates every CA-holder request asks.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nexus_raft::transport::TlsConfig;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::CommonArgs;

/// How often the daemon checks its leaf. A check is one in-memory parse; the
/// interval also bounds how long a failed renewal waits to be retried.
const CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Added to each interval, drawn uniformly, so Nodes enrolled together do not
/// all ask the CA holder at the same moment.
const CHECK_JITTER: Duration = Duration::from_secs(15 * 60);

/// Whether a leaf valid over `[not_before, not_after]` is due at `now`: once
/// less than a third of its lifetime remains (30 days of a 90-day leaf), which
/// leaves room for many hourly retries while the CA holder is away.
fn renewal_due(not_before: i64, not_after: i64, now: i64) -> bool {
    now >= not_after - (not_after - not_before) / 3
}

/// The wait before the next check, given a jitter draw in `[0, 1)`.
fn next_check_delay(jitter: f64) -> Duration {
    CHECK_INTERVAL + CHECK_JITTER.mul_f64(jitter.clamp(0.0, 1.0))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// The validity window `[not_before, not_after]` of `tls`'s leaf, Unix seconds.
fn validity(tls: &TlsConfig) -> Result<(i64, i64), String> {
    let der = lib::transport_primitives::first_certificate_der(&tls.cert_pem, "Node")?;
    let (_, leaf) =
        X509Certificate::from_der(&der).map_err(|_| "Node certificate is not X.509".to_string())?;
    Ok((
        leaf.validity().not_before.timestamp(),
        leaf.validity().not_after.timestamp(),
    ))
}

pub(super) struct NodeRenewal {
    zm: Arc<nexus_raft::ZoneManager>,
    common: CommonArgs,
    /// One renewal at a time: the schedule and an operator request never race
    /// to publish two different keys.
    running: tokio::sync::Mutex<()>,
}

impl NodeRenewal {
    pub(super) fn new(zm: Arc<nexus_raft::ZoneManager>, common: CommonArgs) -> Arc<Self> {
        Arc::new(Self {
            zm,
            common,
            running: tokio::sync::Mutex::new(()),
        })
    }

    fn tls_dir(&self) -> PathBuf {
        self.common.data_dir.join("tls")
    }

    /// Re-issue this Node's certificate for a fresh key through the CA holder,
    /// persist the pair, and serve it. Returns the new leaf's notAfter.
    pub(super) async fn renew(&self) -> Result<i64, String> {
        let _one = self.running.lock().await;
        let current = self
            .zm
            .node_tls()?
            .ok_or("a plaintext node has no certificate to renew")?;
        let (csr_pem, key_pem) = nexus_raft::transport::generate_node_key_request()?;
        let candidates = super::ca_holder_candidates(&self.common).map_err(|e| e.to_string())?;
        let (issuer, cert_pem) = super::ask_ca_holder(&candidates, |endpoint| {
            let (csr_pem, current) = (csr_pem.clone(), current.clone());
            async move {
                nexus_raft::transport::call_renew_node_certificate_rpc(
                    &endpoint, &csr_pem, current, 15,
                )
                .await
            }
        })
        .await
        .map_err(|error| match error {
            super::CaHolderError::Refused(msg) | super::CaHolderError::Unreachable(msg) => msg,
        })?;
        let renewed = TlsConfig {
            cert_pem,
            key_pem,
            ca_pem: current.ca_pem,
        };
        self.zm.check_node_identity(&renewed)?;
        nexus_raft::transport::persist_node_identity(
            &self.tls_dir(),
            &renewed.cert_pem,
            &renewed.key_pem,
        )?;
        let (_, not_after) = validity(&renewed)?;
        self.zm.install_node_identity(renewed)?;
        tracing::info!(%issuer, not_after, "renewed this Node's certificate");
        Ok(not_after)
    }

    /// Check now and then once per jittered interval, renewing when due. An
    /// expired leaf can no longer authenticate a renewal; it is reported until
    /// an operator re-enrolls.
    pub(super) async fn run(self: Arc<Self>) {
        loop {
            self.check(unix_now()).await;
            tokio::time::sleep(next_check_delay(rand::random::<f64>())).await;
        }
    }

    async fn check(&self, now: i64) {
        let current = match self.zm.node_tls() {
            Ok(Some(current)) => current,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(%error, "Node credential installation is unavailable; re-enrollment is required");
                return;
            }
        };
        let (not_before, not_after) = match validity(&current) {
            Ok(window) => window,
            Err(error) => {
                tracing::error!(%error, "cannot read this Node's certificate validity");
                return;
            }
        };
        if now > not_after {
            tracing::error!(
                not_after,
                "this Node's certificate has expired and can no longer authenticate a renewal; \
                 re-enroll with `nexusd-cluster enroll <founder_host:port> <join_token>`"
            );
            return;
        }
        if !renewal_due(not_before, not_after, now) {
            return;
        }
        if let Err(error) = self.renew().await {
            tracing::warn!(%error, not_after, "Node certificate renewal failed; will retry");
        }
    }
}

#[tonic::async_trait]
impl nexus_raft::ca_issuer::LocalNodeRenewer for NodeRenewal {
    async fn renew_now(&self) -> Result<i64, String> {
        self.renew().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn renewal_is_due_once_a_third_of_the_lifetime_remains() {
        let (issued, expires) = (1_000 * DAY, 1_090 * DAY);
        assert!(!renewal_due(issued, expires, issued));
        assert!(!renewal_due(issued, expires, expires - 30 * DAY - 1));
        assert!(renewal_due(issued, expires, expires - 30 * DAY));
        assert!(renewal_due(issued, expires, expires - 1));
        assert!(renewal_due(issued, expires, expires + DAY));
        // A short-lived leaf follows the same fraction, not a fixed margin.
        assert!(!renewal_due(0, 300, 199));
        assert!(renewal_due(0, 300, 200));
    }

    #[test]
    fn checks_recur_hourly_plus_a_bounded_jitter() {
        assert_eq!(next_check_delay(0.0), CHECK_INTERVAL);
        assert_eq!(next_check_delay(0.5), CHECK_INTERVAL + CHECK_JITTER / 2);
        assert!(next_check_delay(0.999_999) < CHECK_INTERVAL + CHECK_JITTER);
        assert_eq!(next_check_delay(7.0), CHECK_INTERVAL + CHECK_JITTER);
    }
}
