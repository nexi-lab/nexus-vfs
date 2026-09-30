//! Agent identity URI SAN — the `nexus://agent/{name}` that `certgen` pins into
//! an agent cert and `peer_identity` / `authorship` read back. The cert is a
//! pure identity (a DID); this SAN is all it carries. Pure string helpers
//! (implementation), depending on nothing — they live here per the tier split
//! (contracts = types/constants, lib = implementations).
//!
//! ## Why the name is flat — and the cross-org headroom that keeps
//!
//! The name is flat and zone-free because there is exactly one cluster CA: a
//! `nexus://agent/{name}` is implicitly scoped to *this* CA's namespace, and
//! within-CA uniqueness is enforced at mint (`auth::mint`). This is the SPIFFE
//! shape — `nexus://` + a typed authority segment (`zone/…` for nodes,
//! `agent/…` here) — and it is deliberately *additively* extensible: a future
//! cross-org / multi-trust-domain identity (an agent under a foreign trust
//! root, brokered by the platform as an isolation intermediary) slots in as a
//! NEW prefix + parse fn, leaving the node and agent parsers untouched.
//!
//! So do NOT treat "agent names are globally flat" as a permanent invariant
//! (e.g. a global flat unique index a qualified name would break): the
//! org / trust-domain qualifier co-arrives with the multi-CA verification
//! change — both touch `certgen::generate_agent_cert` and the verifier's single
//! `client_ca_root` at once — not before. Deferred until a real cross-org
//! scenario pins the brokering contract; today there is one CA and one trust
//! root. The human legal signature (the shareone accountability plane) rides ON
//! TOP of this DID — one key both authenticates the agent and signs its `from`
//! — so accountability builds on this identity rather than a second signature
//! mechanism.

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

/// Scheme + authority of the OWNER SAN: who a session agent acts for.
///
/// The new prefix this module's header anticipated. Disjoint from
/// `nexus://agent/` and `nexus://zone/`, so the existing parsers are untouched
/// and an owner URI can never resolve as an agent or a node.
///
/// It rides in the certificate rather than a store because that is what makes
/// it resolve identically on every node the CA reaches — the same property that
/// lets an agent cert authenticate with no store lookup. A session's owner is
/// then a fact about the credential, established when the CA signs it, not a
/// row someone has to keep in sync.
const OWNER_URI_PREFIX: &str = "nexus://owner/";

/// Build the owner SAN pinned into a session agent certificate:
/// `nexus://owner/{owner_id}`.
pub fn owner_uri(owner_id: &str) -> String {
    format!("{OWNER_URI_PREFIX}{owner_id}")
}

/// Inverse of [`owner_uri`] — `None` for any URI that is not an owner SAN or is
/// malformed.
pub fn parse_owner_uri(uri: &str) -> Option<String> {
    let owner = uri.strip_prefix(OWNER_URI_PREFIX)?;
    if owner.is_empty() {
        return None;
    }
    Some(owner.to_string())
}

/// The agent name for a fresh session identity: `session-{uuid}`.
///
/// One session, one name, never reused — so a leaked session credential
/// authorises exactly the session it was issued for, and revoking it cannot
/// affect another. The `session-` stem is for operators reading a log; nothing
/// parses it, and no code should start to. What makes a credential a session
/// credential is its owner SAN and its short validity, both of which are
/// checkable, rather than a naming convention, which is not.
pub fn session_agent_name(session_uuid: &str) -> String {
    format!("session-{session_uuid}")
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

    #[test]
    fn owner_round_trips_and_rejects_foreign_or_empty() {
        assert_eq!(
            parse_owner_uri(&owner_uri("alice")),
            Some("alice".to_string())
        );
        assert_eq!(parse_owner_uri("nexus://owner/"), None);
        assert_eq!(parse_owner_uri("nexus://zone/root/node/7"), None);
    }

    /// The three SAN namespaces must stay mutually unreadable: one parser
    /// accepting another's URI is how a cert gets read as the wrong kind of
    /// principal.
    #[test]
    fn the_san_namespaces_are_disjoint() {
        let agent = agent_identity_uri("win-ai");
        let owner = owner_uri("alice");
        assert_eq!(parse_owner_uri(&agent), None);
        assert_eq!(parse_agent_identity_uri(&owner), None);
        // And a session agent is an ordinary agent URI — that is what makes it
        // resolve through the existing agent path with no parser change.
        let session = agent_identity_uri(&session_agent_name("3f2a"));
        assert_eq!(
            parse_agent_identity_uri(&session),
            Some("session-3f2a".to_string())
        );
        assert_eq!(parse_owner_uri(&session), None);
    }
}
