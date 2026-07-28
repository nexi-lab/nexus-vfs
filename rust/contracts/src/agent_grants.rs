//! `AgentGrants` — the authorization an agent identity cert carries as a
//! capability, so any node verifies **both** an agent's identity and its
//! grants from the cert via the cluster CA, with **no per-node credential
//! store lookup**.
//!
//! Why in the cert, not a record: the credential store lives in the root zone,
//! and root is per-node SOLO (never federated). An agent cert is signed by the
//! founder (the CA holder), so a record written at mint lives only on the
//! founder — an agent connecting to any *other* node would find no record and
//! fail. Putting the grants in the CA-signed cert makes them verifiable
//! anywhere the CA is (every node, via enrollment), which is exactly the
//! cross-trust-domain property the signed-`from` design rests on. The cert is
//! the single source of an agent's identity *and* authorization.
//!
//! Encoding is a compact, human-readable, dependency-free string embedded in a
//! private X.509 extension ([`AGENT_GRANTS_OID`]).

/// Private OID for the agent-grants X.509 extension, under the IANA private
/// enterprise arc (`1.3.6.1.4.1`). SSOT for both the minting side
/// (`certgen::generate_agent_cert`) and the reading side
/// (`transport::peer_identity`).
pub const AGENT_GRANTS_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 58530, 1, 1];

/// What an agent cert is allowed to reach — the same two authorization inputs
/// an [`crate::OperationContext`] carries (`zone_perms` + `is_admin`), lifted
/// into the cert so authorization travels with identity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentGrants {
    /// Global admin — the only principal allowed to hold no zone grants at all.
    pub is_admin: bool,
    /// Per-zone grants as `(zone_id, permission_chars)`, the same shape
    /// `OperationContext::zone_perms` carries into the permission gate.
    pub zone_perms: Vec<(String, String)>,
}

impl AgentGrants {
    /// Encode for the cert extension: `<admin>;<zone:perms,...>` where `<admin>`
    /// is `1` for a global admin else `0`, and zones are `id:perms`
    /// comma-separated. Examples: `1;` (admin, no zones), `0;sharedzone:rw`,
    /// `0;sharedzone:rw,other:r`.
    pub fn encode(&self) -> Vec<u8> {
        let admin = if self.is_admin { "1" } else { "0" };
        let zones: Vec<String> = self
            .zone_perms
            .iter()
            .map(|(z, p)| format!("{z}:{p}"))
            .collect();
        format!("{admin};{}", zones.join(",")).into_bytes()
    }

    /// Inverse of [`Self::encode`]. Malformed input yields empty grants
    /// (fail-closed: not admin, no zones), so a cert whose extension we cannot
    /// parse reaches nothing rather than everything.
    pub fn decode(bytes: &[u8]) -> Self {
        let Ok(s) = std::str::from_utf8(bytes) else {
            return Self::default();
        };
        let Some((admin, zones)) = s.split_once(';') else {
            return Self::default();
        };
        let zone_perms = zones
            .split(',')
            .filter(|z| !z.is_empty())
            .filter_map(|zp| zp.split_once(':').map(|(z, p)| (z.to_string(), p.to_string())))
            .collect();
        Self {
            is_admin: admin == "1",
            zone_perms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(g: &AgentGrants) {
        assert_eq!(&AgentGrants::decode(&g.encode()), g);
    }

    #[test]
    fn roundtrips_a_scoped_agent() {
        roundtrip(&AgentGrants {
            is_admin: false,
            zone_perms: vec![
                ("sharedzone".into(), "rw".into()),
                ("other".into(), "r".into()),
            ],
        });
    }

    #[test]
    fn roundtrips_a_zoneless_admin() {
        roundtrip(&AgentGrants {
            is_admin: true,
            zone_perms: vec![],
        });
    }

    #[test]
    fn roundtrips_the_empty_grant() {
        roundtrip(&AgentGrants::default());
    }

    #[test]
    fn malformed_input_is_the_empty_grant_not_a_wildcard() {
        // No separator, non-utf8, and an empty extension all fail closed.
        assert_eq!(AgentGrants::decode(b"garbage"), AgentGrants::default());
        assert_eq!(AgentGrants::decode(&[0xff, 0xfe]), AgentGrants::default());
        assert_eq!(AgentGrants::decode(b""), AgentGrants::default());
    }
}
