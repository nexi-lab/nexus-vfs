//! Peer addressing — hostname parsing and node ID derivation.

use super::error::{Result, TransportError};

/// Derive a deterministic node ID from a hostname.  Witness-only.
///
/// SHA-256 of hostname, first 8 bytes as little-endian u64.
/// Maps 0 to 1 (raft-rs reserves 0 as "no node").
///
/// Used by the standalone witness binary, which lives at a
/// well-known address and so binds raft node identity to hostname.
/// Data-plane node identity is opaque random — see
/// `read_or_mint_node_id` in `distributed_coordinator.rs` and
/// `docs/adr/adr-raft-node-id-opaque.md`.
#[doc = "Witness-only"]
pub fn hostname_to_node_id(hostname: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    let hash = hasher.finalize();
    let mut first_eight = [0u8; 8];
    first_eight.copy_from_slice(&hash[..8]);
    let value = u64::from_le_bytes(first_eight);
    if value == 0 {
        1
    } else {
        value
    }
}

fn format_host_port(hostname: &str, port: u16) -> String {
    let needs_brackets =
        hostname.contains(':') && !hostname.starts_with('[') && !hostname.ends_with(']');
    if needs_brackets {
        format!("[{}]:{}", hostname, port)
    } else {
        format!("{}:{}", hostname, port)
    }
}

#[allow(clippy::result_large_err)]
fn parse_host_port(addr: &str, original: &str) -> Result<(String, u16)> {
    let (hostname, port_str) = if let Some(rest) = addr.strip_prefix('[') {
        let Some(close_idx) = rest.find(']') else {
            return Err(TransportError::InvalidAddress(format!(
                "missing closing ']' in '{}'",
                original
            )));
        };
        let hostname = &rest[..close_idx];
        let remainder = &rest[close_idx + 1..];
        let Some(port_str) = remainder.strip_prefix(':') else {
            return Err(TransportError::InvalidAddress(format!(
                "expected ':port' after host in '{}'",
                original
            )));
        };
        (hostname, port_str)
    } else {
        let Some((hostname, port_str)) = addr.rsplit_once(':') else {
            return Err(TransportError::InvalidAddress(format!(
                "expected 'host:port', got '{}'",
                original
            )));
        };

        // Require bracketed IPv6 to avoid ambiguous host/port parsing.
        if hostname.contains(':') {
            return Err(TransportError::InvalidAddress(format!(
                "IPv6 addresses must be bracketed: '{}'",
                original
            )));
        }
        (hostname, port_str)
    };

    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err(TransportError::InvalidAddress(format!(
            "host cannot be empty: '{}'",
            original
        )));
    }

    let port: u16 = port_str.parse().map_err(|_| {
        TransportError::InvalidAddress(format!("invalid port in '{}': '{}'", original, port_str))
    })?;
    if port == 0 {
        return Err(TransportError::InvalidAddress(format!(
            "port must be 1-65535 in '{}'",
            original
        )));
    }

    Ok((hostname.to_string(), port))
}

/// Infallible companion to [`parse_host_port`] used by
/// [`PeerAddress::new`] when the caller supplies an already-canonical
/// endpoint (e.g. from raft `ConfChange` context).  Returns
/// `(String::new(), 0)` on shapes that don't fit `host:port`, so the
/// hostname + port fields degrade to defaults while the caller's
/// authoritative `endpoint` string still drives transport dispatch.
fn split_host_port(hostport: &str) -> (String, u16) {
    let Some((host, port_str)) = hostport.rsplit_once(':') else {
        return (String::new(), 0);
    };
    if host.contains(':') {
        return (String::new(), 0);
    }
    let host = host.trim();
    let Ok(port) = port_str.parse::<u16>() else {
        return (host.to_string(), 0);
    };
    (host.to_string(), port)
}

/// Address of a network peer (Raft node, gRPC endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerAddress {
    /// Peer hostname (e.g., "nexus-1").
    pub hostname: String,
    /// Peer port (e.g., 2126).
    pub port: u16,
    /// Node ID (derived from hostname via SHA-256).
    pub id: u64,
    /// gRPC endpoint (e.g., "http://nexus-1:2126").
    pub endpoint: String,
}

impl PeerAddress {
    /// Create a new PeerAddress with an authoritative id + endpoint —
    /// used by raft-internal call sites (`node_address_from_conf_context`)
    /// where the id comes from a `ConfChange` struct and the endpoint
    /// from its `context` bytes.  Both authoritative inputs are in
    /// hand, so we bypass [`Self::parse`] (which is CLI-facing and
    /// hard-rejects any `id@host:port` shape).
    ///
    /// Populates `hostname` + `port` by scanning the endpoint's
    /// `host:port` tail (after any `http[s]://` prefix).  Malformed
    /// endpoints (missing `:`, unparseable port) leave those fields
    /// zeroed; transport dispatch consults `endpoint` directly so a
    /// zero-hostname NodeAddress is still routable.
    pub fn new(id: u64, endpoint: impl Into<String>) -> Self {
        let endpoint = endpoint.into();
        let stripped = endpoint
            .strip_prefix("http://")
            .or_else(|| endpoint.strip_prefix("https://"))
            .unwrap_or(&endpoint);
        let (hostname, port) = split_host_port(stripped);
        Self {
            hostname,
            port,
            id,
            endpoint,
        }
    }

    /// Parse a peer address — raft-internal path.
    ///
    /// Accepts both `host:port` (id derived via
    /// [`hostname_to_node_id`]) and the legacy `id@host:port` shape
    /// (id preserved verbatim).  The dual acceptance is required
    /// by raft-internal round-trips through
    /// [`Self::to_raft_peer_str`] — founder self-registration,
    /// ConfChange context reconstruction, `ZoneManager::create_zone`
    /// address-book keying, and similar sites carry the
    /// authoritative `node_id` and encode it in the peer string so
    /// downstream parses recover it exactly.
    ///
    /// **CLI + env boundary code MUST NOT call this** — use
    /// [`Self::parse_operator_addr`] instead, which rejects the
    /// legacy form so operators are steered to the bare
    /// `host:port` shape.  Under the PR #3996 opaque-ID contract
    /// peer node_ids are random per boot, so carrying them across
    /// an operator-facing seam has no protocol purpose (the real
    /// id is learned from the first inbound raft message via
    /// `learn_peer_address` in `transport/server.rs`).
    #[allow(clippy::result_large_err)]
    pub fn parse(s: &str, use_tls: bool) -> Result<Self> {
        Self::parse_inner(s, use_tls, /* allow_id_prefix */ true)
    }

    /// Parse a peer address from `host:port` form only.
    ///
    /// The operator boundary contract: `NEXUS_PEERS`, `--peers`,
    /// `nexusd-cluster join <peer_addr>` all go through here.  A
    /// stray `<id>@host:port` gets a clear migration error naming
    /// the retired form, so operator scripts and runbooks migrate
    /// without silent semantic drift.
    #[allow(clippy::result_large_err)]
    pub fn parse_operator_addr(s: &str, use_tls: bool) -> Result<Self> {
        Self::parse_inner(s, use_tls, /* allow_id_prefix */ false)
    }

    #[allow(clippy::result_large_err)]
    fn parse_inner(s: &str, use_tls: bool, allow_id_prefix: bool) -> Result<Self> {
        let s = s.trim();
        let addr = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))
            .unwrap_or(s);

        let (explicit_id, addr) = match addr.find('@') {
            Some(pos) => {
                if !allow_id_prefix {
                    let prefix = &addr[..pos];
                    let remainder = &addr[pos + 1..];
                    return Err(TransportError::InvalidAddress(format!(
                        "peer address '{s}' uses the legacy 'id@host:port' form \
                         (id='{prefix}'); pass just 'host:port' (e.g. '{remainder}').  \
                         Peer node_id is opaque + random per boot — the transport \
                         layer learns it from the first inbound raft message via \
                         learn_peer_address; carrying an explicit id in the operator-\
                         facing address book had no protocol purpose."
                    )));
                }
                let id_str = &addr[..pos];
                let id = id_str.parse::<u64>().map_err(|_| {
                    TransportError::InvalidAddress(format!(
                        "invalid node id in '{}': '{}'",
                        s, id_str
                    ))
                })?;
                if id == 0 {
                    return Err(TransportError::InvalidAddress(format!(
                        "node id must be non-zero in '{}'",
                        s
                    )));
                }
                (Some(id), &addr[pos + 1..])
            }
            None => (None, addr),
        };

        let (hostname, port) = parse_host_port(addr, s)?;
        let id = explicit_id.unwrap_or_else(|| hostname_to_node_id(&hostname));

        let scheme = if use_tls { "https" } else { "http" };
        let endpoint = format!("{}://{}", scheme, format_host_port(&hostname, port));

        Ok(Self {
            hostname,
            port,
            id,
            endpoint,
        })
    }

    /// Parse a comma-separated list of "host:port" peers.
    #[allow(clippy::result_large_err)]
    pub fn parse_peer_list(s: &str, use_tls: bool) -> Result<Vec<Self>> {
        s.split(',')
            .filter(|p| !p.trim().is_empty())
            .map(|p| Self::parse(p.trim(), use_tls))
            .collect()
    }

    /// Operator-facing comma-separated list — same as
    /// [`Self::parse_peer_list`] but every entry goes through
    /// [`Self::parse_operator_addr`] so a stray `<id>@host:port`
    /// surfaces as a clear migration error at boot time rather than
    /// being silently accepted.  Used by CLI (`--peers`, `NEXUS_PEERS`)
    /// + `identity.json` load.
    #[allow(clippy::result_large_err)]
    pub fn parse_peer_list_operator(s: &str, use_tls: bool) -> Result<Vec<Self>> {
        s.split(',')
            .filter(|p| !p.trim().is_empty())
            .map(|p| Self::parse_operator_addr(p.trim(), use_tls))
            .collect()
    }

    /// Return "host:port" for gRPC connection target.
    pub fn grpc_target(&self) -> String {
        if self.hostname.is_empty() {
            self.endpoint
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .to_string()
        } else {
            format_host_port(&self.hostname, self.port)
        }
    }

    /// Return "id@host:port" for raft-internal peer-list serialization.
    ///
    /// Used by round-trip sites inside the raft crate
    /// (`ZoneManager::create_zone` address-book keying, founder
    /// self-registration, ConfChange context) where the caller has an
    /// authoritative `id` in hand and needs downstream parses to
    /// recover it exactly.  Operator-facing round-trips
    /// (identity.json peer entries) that must survive a subsequent
    /// [`Self::parse_operator_addr`] load should use
    /// [`Self::to_operator_str`] instead.
    pub fn to_raft_peer_str(&self) -> String {
        format!("{}@{}", self.id, self.grpc_target())
    }

    /// Return "host:port" for operator-facing round-trip.
    ///
    /// Symmetric with [`Self::parse_operator_addr`] — the strict CLI
    /// contract that rejects `@`.  Used by `identity.json` peer
    /// persistence so a later cold-boot loads the file without
    /// tripping the id-prefix rejection.
    pub fn to_operator_str(&self) -> String {
        self.grpc_target()
    }
}

/// Backward-compatible type alias.
pub type NodeAddress = PeerAddress;

impl std::fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.id, self.endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_to_node_id_golden_values() {
        assert_eq!(hostname_to_node_id("nexus-1"), 14044926161142285152);
        assert_eq!(hostname_to_node_id("nexus-2"), 768242927742468745);
        assert_eq!(hostname_to_node_id("witness"), 10099512703796518074);
    }

    #[test]
    fn test_parse_honors_explicit_node_id_internal_form() {
        // Raft-internal `parse` accepts `id@host:port` — round-trip
        // sites (`ZoneManager::create_zone` address book, founder
        // self-registration) carry the authoritative id in the string
        // so parses recover it exactly.
        let addr = PeerAddress::parse("42@nexus-2:2126", false).unwrap();
        assert_eq!(addr.id, 42);
        assert_eq!(addr.hostname, "nexus-2");
        assert_eq!(addr.port, 2126);
        assert_eq!(addr.endpoint, "http://nexus-2:2126");
    }

    #[test]
    fn test_parse_operator_addr_rejects_id_prefix() {
        // Operator-facing parse rejects `id@host:port` with a
        // migration message.  `NEXUS_PEERS`, `--peers`,
        // `nexusd-cluster join <peer_addr>`, `identity.json` load
        // all go through this variant so a stray id-prefixed entry
        // surfaces at boot rather than as silent semantic drift.
        let err = PeerAddress::parse_operator_addr("42@nexus-2:2126", false)
            .expect_err("must reject legacy form on operator boundary");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy 'id@host:port' form"),
            "error must name the retired form: {msg}"
        );
        assert!(
            msg.contains("nexus-2:2126"),
            "error must suggest the bare form: {msg}"
        );
    }

    #[test]
    fn test_parse_operator_addr_accepts_bare_host_port() {
        // Positive contract: bare `host:port` parses cleanly through
        // the operator surface — the shape operators are steered to.
        let addr =
            PeerAddress::parse_operator_addr("nexus-2:2126", false).expect("bare form parses");
        assert_eq!(addr.hostname, "nexus-2");
        assert_eq!(addr.port, 2126);
        assert_eq!(addr.id, hostname_to_node_id("nexus-2"));
    }

    #[test]
    fn test_to_raft_peer_str_round_trips_explicit_node_id() {
        // Raft-internal round-trip via `to_raft_peer_str` + `parse`
        // preserves the authoritative id.
        let original = PeerAddress {
            hostname: "nexus-2".to_string(),
            port: 2126,
            id: 12345,
            endpoint: "http://nexus-2:2126".to_string(),
        };

        let parsed = PeerAddress::parse(&original.to_raft_peer_str(), false).unwrap();
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.hostname, original.hostname);
        assert_eq!(parsed.port, original.port);
    }

    #[test]
    fn test_to_operator_str_round_trips_via_operator_parse() {
        // Operator-facing round-trip via `to_operator_str` +
        // `parse_operator_addr` yields the same struct because
        // `hostname_to_node_id` is deterministic.
        let original =
            PeerAddress::parse_operator_addr("nexus-2:2126", false).expect("bare form parses");
        let serialized = original.to_operator_str();
        assert_eq!(serialized, "nexus-2:2126");
        let parsed = PeerAddress::parse_operator_addr(&serialized, false).unwrap();
        assert_eq!(parsed.id, original.id);
    }

    #[test]
    fn test_parse_rejects_zero_explicit_node_id() {
        assert!(matches!(
            PeerAddress::parse("0@nexus-2:2126", false),
            Err(TransportError::InvalidAddress(_))
        ));
    }

    #[test]
    fn test_peer_address_parse() {
        let addr = PeerAddress::parse("nexus-1:2126", false).unwrap();
        assert_eq!(addr.hostname, "nexus-1");
        assert_eq!(addr.port, 2126);
        assert_eq!(addr.id, hostname_to_node_id("nexus-1"));
        assert_eq!(addr.endpoint, "http://nexus-1:2126");
    }

    #[test]
    fn test_peer_address_parse_tls() {
        let addr = PeerAddress::parse("nexus-2:2126", true).unwrap();
        assert_eq!(addr.endpoint, "https://nexus-2:2126");
    }

    #[test]
    fn test_peer_address_parse_ipv6() {
        let addr = PeerAddress::parse("[::1]:2126", false).unwrap();
        assert_eq!(addr.hostname, "::1");
        assert_eq!(addr.port, 2126);
        assert_eq!(addr.endpoint, "http://[::1]:2126");
        assert_eq!(addr.grpc_target(), "[::1]:2126");
    }

    #[test]
    fn test_peer_address_parse_rejects_invalid_host_port() {
        assert!(matches!(
            PeerAddress::parse("2001:db8::1:2126", false),
            Err(TransportError::InvalidAddress(_))
        ));
        assert!(matches!(
            PeerAddress::parse(":2126", false),
            Err(TransportError::InvalidAddress(_))
        ));
        assert!(matches!(
            PeerAddress::parse("nexus-1:0", false),
            Err(TransportError::InvalidAddress(_))
        ));
    }
}
