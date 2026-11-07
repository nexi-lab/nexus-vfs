//! Service-level local launch capability; this does not extend kernel syscalls.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Private launcher-to-manager exit receipt, not an ACP session notification.
pub const TERMINAL_EXIT_METHOD: &str = "_nexus/terminal_exit";
/// Emitted by the native runtime after opening its one engine session.
pub const TERMINAL_READY_METHOD: &str = "_nexus/terminal_ready";
pub const TERMINAL_STATE_METHOD: &str = "_nexus/terminal_state";

/// A one-use terminal launch offer passed through an authenticated service call.
/// This is a control-channel capability, never an OS identity or credential.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchOffer {
    endpoint: SocketAddr,
    token: String,
}

impl LaunchOffer {
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
            return Err("invalid local terminal launch capability");
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

impl std::fmt::Debug for LaunchOffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchOffer")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// A live native CLI selected a different durable transcript.
pub const TERMINAL_SESSION_METHOD: &str = "_nexus/terminal_session";
