//! Channels bound to the credential policy that admitted their connection.
use std::time::Duration;

use dashmap::DashMap;
pub(crate) use lib::transport_primitives::TlsPolicy;
use lib::transport_primitives::{create_channel, ClientConfig, SharedTlsConfig, TlsSnapshot};
use tonic::transport::Channel;

struct CachedChannel {
    snapshot: TlsSnapshot,
    channel: Channel,
}

pub(crate) struct PeerChannels {
    credentials: SharedTlsConfig,
    channels: DashMap<String, CachedChannel>,
    request_timeout: Duration,
}

impl PeerChannels {
    pub(crate) fn new(credentials: SharedTlsConfig, request_timeout: Duration) -> Self {
        Self {
            credentials,
            channels: DashMap::new(),
            request_timeout,
        }
    }

    pub(crate) fn replace_tls(&self, tls: TlsPolicy) {
        self.credentials.replace(tls);
        self.channels.clear();
    }

    pub(crate) async fn channel_for(&self, address: &str) -> Result<Channel, String> {
        let (snapshot, cached) = self.credentials.read(|snapshot| {
            snapshot.config().map_err(str::to_owned)?;
            if let Some(cached) = self.channels.get(address) {
                if cached.snapshot.same_installation(snapshot) {
                    return Ok((snapshot.clone(), Some(cached.channel.clone())));
                }
            }
            Ok::<_, String>((snapshot.clone(), None))
        })?;
        if let Some(cached) = cached {
            return Ok(cached);
        }
        let tls = snapshot.config()?.cloned();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let endpoint = if address.starts_with("http://") || address.starts_with("https://") {
            address.to_string()
        } else {
            format!("{scheme}://{address}")
        };
        let config = ClientConfig {
            tls,
            request_timeout: self.request_timeout,
            ..Default::default()
        };
        let channel = create_channel(&endpoint, &config)
            .await
            .map_err(|error| format!("peer channel {address}: {error}"))?;
        self.credentials
            .with_current(&snapshot, || {
                self.channels.insert(
                    address.to_string(),
                    CachedChannel {
                        snapshot: snapshot.clone(),
                        channel: channel.clone(),
                    },
                );
                channel
            })
            .ok_or_else(|| "peer TLS configuration changed while connecting".into())
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub(crate) fn uses_tls(&self) -> bool {
        self.credentials.read(TlsSnapshot::uses_tls)
    }
}
