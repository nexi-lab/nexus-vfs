//! Service-level local host capability; this does not extend kernel syscalls.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Emitted by the native runtime after opening its one engine session.
pub const HOST_READY_METHOD: &str = "_nexus/host_ready";
pub const HOST_STATE_METHOD: &str = "_nexus/host_state";

/// A one-use local host offer passed through an authenticated service call.
/// This is a control-channel capability, never an OS identity or credential.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalHostOffer {
    endpoint: SocketAddr,
    token: String,
}

impl LocalHostOffer {
    pub fn new(endpoint: SocketAddr, token: String) -> Result<Self, &'static str> {
        let offer = Self { endpoint, token };
        offer.validate()?;
        Ok(offer)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.endpoint.ip() != Ipv4Addr::LOCALHOST
            || self.endpoint.port() == 0
            || self.token.len() != 32
            || !self.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid local host capability");
        }
        Ok(())
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for LocalHostOffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalHostOffer")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// A live native CLI selected a different durable transcript.
pub const HOST_SESSION_METHOD: &str = "_nexus/host_session";
