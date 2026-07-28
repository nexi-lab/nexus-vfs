//! Agent identity URI SAN — the `nexus://agent/{name}` that `certgen` pins into
//! an agent cert and `peer_identity` / `authorship` read back. Pure string
//! helpers (implementation), depending on nothing. The OID and `AgentGrants`
//! *data* live in `contracts`; these *functions* live here per the tier split
//! (contracts = types/constants, lib = implementations).

/// Scheme + authority of the agent identity URI SAN. An agent cert states which
/// *agent* it is, parallel to a node cert's `nexus://zone/{z}/node/{n}`.
/// Zone-free by design; disjoint from the node prefix, so a node URI never
/// parses as an agent and vice versa.
const AGENT_IDENTITY_URI_PREFIX: &str = "nexus://agent/";

/// Build the identity URI SAN pinned into an agent certificate:
/// `nexus://agent/{name}`.
pub fn agent_identity_uri(name: &str) -> String {
    format!("{AGENT_IDENTITY_URI_PREFIX}{name}")
}

/// Inverse of [`agent_identity_uri`] — `None` for any URI that is not an agent
/// identity or is malformed (a foreign SAN must never resolve to an agent).
pub fn parse_agent_identity_uri(uri: &str) -> Option<String> {
    let name = uri.strip_prefix(AGENT_IDENTITY_URI_PREFIX)?;
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_foreign_or_empty() {
        assert_eq!(
            parse_agent_identity_uri(&agent_identity_uri("win-ai")),
            Some("win-ai".to_string())
        );
        // A node URI is not an agent, and an empty name is malformed.
        assert_eq!(parse_agent_identity_uri("nexus://zone/root/node/7"), None);
        assert_eq!(parse_agent_identity_uri("nexus://agent/"), None);
    }
}
