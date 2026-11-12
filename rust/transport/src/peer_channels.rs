//! Channels bound to the credential policy that admitted their connection.
use std::time::Duration;

use dashmap::DashMap;
use lib::transport_primitives::{create_channel, ClientConfig, TlsConfig};
use parking_lot::RwLock;
use tonic::transport::Channel;

pub(crate) enum TlsPolicy {
    Plaintext,
    Configured(TlsConfig),
    Rejected(&'static str),
}

struct ConnectionPolicy {
    generation: u64,
    tls: TlsPolicy,
}

struct CachedChannel {
    generation: u64,
    channel: Channel,
}

pub(crate) struct PeerChannels {
    policy: RwLock<ConnectionPolicy>,
    channels: DashMap<String, CachedChannel>,
    request_timeout: Duration,
}

impl PeerChannels {
    pub(crate) fn new(tls: Option<TlsConfig>, request_timeout: Duration) -> Self {
        Self {
            policy: RwLock::new(ConnectionPolicy {
                generation: 0,
                tls: tls.map_or(TlsPolicy::Plaintext, TlsPolicy::Configured),
            }),
            channels: DashMap::new(),
            request_timeout,
        }
    }

    pub(crate) fn replace_tls(&self, tls: TlsPolicy) {
        let mut policy = self.policy.write();
        policy.tls = match policy.generation.checked_add(1) {
            Some(generation) => {
                policy.generation = generation;
                tls
            }
            None => TlsPolicy::Rejected("peer TLS generation exhausted"),
        };
        // A completing dial holds the same policy lock while publishing.
        self.channels.clear();
    }

    pub(crate) async fn channel_for(&self, address: &str) -> Result<Channel, String> {
        let (generation, tls) = {
            let policy = self.policy.read();
            if let TlsPolicy::Rejected(error) = &policy.tls {
                return Err((*error).into());
            }
            if let Some(cached) = self.channels.get(address) {
                if cached.generation == policy.generation {
                    return Ok(cached.channel.clone());
                }
            }
            let tls = match &policy.tls {
                TlsPolicy::Configured(tls) => Some(tls.clone()),
                TlsPolicy::Plaintext | TlsPolicy::Rejected(_) => None,
            };
            (policy.generation, tls)
        };
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
        let policy = self.policy.read();
        if policy.generation != generation || matches!(policy.tls, TlsPolicy::Rejected(_)) {
            return Err("peer TLS configuration changed while connecting".into());
        }
        let cached = self
            .channels
            .entry(address.to_string())
            .or_insert_with(|| CachedChannel {
                generation,
                channel,
            });
        Ok(cached.channel.clone())
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    pub(crate) fn uses_tls(&self) -> bool {
        matches!(self.policy.read().tls, TlsPolicy::Configured(_))
    }
}
