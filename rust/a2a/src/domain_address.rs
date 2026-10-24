//! Experimental cross-domain address values, not authentication capabilities.
//!
//! An address is public data. Parsing one does not authenticate its owner or
//! grant access. A later native authorizer must derive the caller from current
//! mTLS/managed context and enforce the enrolled collaboration-space policy.
//! No existing daemon route, stamp, mailbox or permission provider uses this
//! module. The legacy gate denies this family only for foreign callers;
//! domestic/unidentified callers on an old node have no such protection.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const PREFIX: &str = "/collaboration/v1/";
const MAX_SUBJECT_BYTES: usize = 128;
const MAX_AGENT_SEGMENT: usize = 218;
const MAX_PAIR_PATH: usize = PREFIX.len() + 32 + 7 + MAX_AGENT_SEGMENT * 3 + 1 + 9;

/// A public Agent address bound to SHA256 of its registered anchor's DER SPKI.
/// This is the authority key, not the complete certificate or a leaf issuer DN.
/// Subject bytes are exact UTF-8; no normalization or display-name fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentAddress {
    authority: [u8; 32],
    subject: String,
}

impl AgentAddress {
    /// Validate a public value. This constructor is deliberately not proof of
    /// authentication, ownership, grant membership or a valid certificate SAN.
    pub fn new(authority: [u8; 32], subject: String) -> Result<Self, &'static str> {
        if subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || subject.chars().any(char::is_control)
        {
            return Err("Agent subject must contain 1..128 UTF-8 bytes without controls");
        }
        Ok(Self { authority, subject })
    }

    #[must_use]
    pub fn authority(&self) -> &[u8; 32] {
        &self.authority
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Unambiguous ASCII rendering for permission review. Raw names can contain
    /// format characters; approvals must also show the full canonical segment.
    #[must_use]
    pub fn escaped_subject(&self) -> String {
        self.subject
            .chars()
            .flat_map(char::escape_default)
            .collect()
    }

    /// One reversible, path-safe segment, bounded to 218 ASCII bytes. Display
    /// aliases and the legacy `domain/agent/name` rendering are not this codec.
    #[must_use]
    pub fn segment(&self) -> String {
        format!(
            "a1.{}.{}",
            URL_SAFE_NO_PAD.encode(self.authority),
            URL_SAFE_NO_PAD.encode(self.subject.as_bytes())
        )
    }

    pub fn parse(segment: &str) -> Result<Self, &'static str> {
        if segment.len() > MAX_AGENT_SEGMENT {
            return Err("Agent address exceeds the canonical segment bound");
        }
        let parts: Vec<_> = segment.split('.').collect();
        let ["a1", authority, subject] = parts.as_slice() else {
            return Err("Unsupported or malformed Agent address");
        };
        let authority: [u8; 32] = URL_SAFE_NO_PAD
            .decode(authority)
            .map_err(|_| "Invalid issuer fingerprint encoding")?
            .try_into()
            .map_err(|_| "Issuer fingerprint must be 32 bytes")?;
        let subject = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(subject)
                .map_err(|_| "Invalid subject encoding")?,
        )
        .map_err(|_| "Subject must be UTF-8")?;
        let address = Self::new(authority, subject)?;
        if address.segment() != segment {
            return Err("Agent address is not canonical");
        }
        Ok(address)
    }
}

/// A pair address contains its participants, so checking participation need not
/// invent a second mutable CID-to-membership registry. Each participant remains
/// one bounded path segment. Space IDs are opaque 128-bit lowercase hex values,
/// not Raft Zone IDs, tenancy claims or an authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationAddress {
    space: String,
    first: AgentAddress,
    second: AgentAddress,
}

impl ConversationAddress {
    pub fn new(space: String, a: AgentAddress, b: AgentAddress) -> Result<Self, &'static str> {
        if space.len() != 32
            || !space
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Space ID must be exactly 32 lowercase hexadecimal characters");
        }
        let a_segment = a.segment();
        let b_segment = b.segment();
        if a_segment == b_segment {
            return Err("A conversation requires two distinct participants");
        }
        let (first, second) = if a_segment < b_segment {
            (a, b)
        } else {
            (b, a)
        };
        Ok(Self {
            space,
            first,
            second,
        })
    }

    #[must_use]
    pub fn contains(&self, address: &AgentAddress) -> bool {
        address == &self.first || address == &self.second
    }

    fn root(&self) -> String {
        format!(
            "{PREFIX}{}/pairs/{}/{}",
            self.space,
            self.first.segment(),
            self.second.segment()
        )
    }

    #[must_use]
    pub fn transcript(&self) -> String {
        format!("{}/transcript", self.root())
    }

    pub fn reader(&self, owner: &AgentAddress) -> Result<String, &'static str> {
        if !self.contains(owner) {
            return Err("Reader is not a participant in this conversation");
        }
        Ok(format!("{}/readers/{}", self.root(), owner.segment()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversationPath {
    Transcript(ConversationAddress),
    Reader {
        conversation: ConversationAddress,
        owner: AgentAddress,
    },
}

impl ConversationPath {
    /// Exact, anchored structural parsing. Stamping's intentionally broader
    /// path predicate must never be reused as an authorization allow-list.
    pub fn parse(path: &str) -> Result<Self, &'static str> {
        if path.len() > MAX_PAIR_PATH {
            return Err("Conversation path exceeds the canonical bound");
        }
        let relative = path
            .strip_prefix(PREFIX)
            .ok_or("Not a collaboration path")?;
        let parts: Vec<_> = relative.split('/').collect();
        let (space, first, second, reader) = match parts.as_slice() {
            [space, "pairs", first, second, "transcript"] => (*space, *first, *second, None),
            [space, "pairs", first, second, "readers", owner] => {
                (*space, *first, *second, Some(*owner))
            }
            _ => return Err("Not an exact conversation transcript or reader path"),
        };
        let conversation = ConversationAddress::new(
            space.to_string(),
            AgentAddress::parse(first)?,
            AgentAddress::parse(second)?,
        )?;
        if let Some(owner) = reader {
            let owner = AgentAddress::parse(owner)?;
            if conversation.reader(&owner)? != path {
                return Err("Conversation participants must be in canonical order");
            }
            Ok(Self::Reader {
                conversation,
                owner,
            })
        } else {
            if conversation.transcript() != path {
                return Err("Conversation participants must be in canonical order");
            }
            Ok(Self::Transcript(conversation))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: &str = "0123456789abcdef0123456789abcdef";

    fn agent(authority: u8, subject: &str) -> AgentAddress {
        AgentAddress::new([authority; 32], subject.to_string()).unwrap()
    }

    #[test]
    fn same_named_agents_in_different_domains_do_not_share_an_address() {
        let a = agent(1, "worker");
        let b = agent(2, "worker");
        assert_ne!(a.segment(), b.segment());
        assert_eq!(AgentAddress::parse(&a.segment()).unwrap(), a);
        assert_eq!(AgentAddress::parse(&b.segment()).unwrap(), b);
    }

    #[test]
    fn utf8_and_separators_are_exact_bounded_single_segments() {
        for name in ["研发 🧪", "a/b\\c.d", &"x".repeat(128)] {
            let address = agent(7, name);
            let segment = address.segment();
            assert!(segment.len() <= 218);
            assert!(!segment.contains('/') && !segment.contains('\\'));
            assert_eq!(AgentAddress::parse(&segment).unwrap().subject(), name);
        }
        assert!(AgentAddress::new([1; 32], "x".repeat(129)).is_err());
        assert!(AgentAddress::new([1; 32], "bad\0name".into()).is_err());
    }

    #[test]
    fn rejects_alias_encodings_and_unknown_versions() {
        let value = agent(4, "worker").segment();
        for invalid in [
            format!("{value}="),
            value.replacen("a1.", "a2.", 1),
            "a1.YQ.Yg".into(),
        ] {
            assert!(AgentAddress::parse(&invalid).is_err());
        }
    }

    #[test]
    fn review_rendering_exposes_invisible_and_directional_subject_bytes() {
        for (value, escaped) in [
            ("worker\u{200b}", "worker\\u{200b}"),
            ("worker\u{202e}", "worker\\u{202e}"),
            ("worker\u{feff}", "worker\\u{feff}"),
        ] {
            let address = agent(4, value);
            assert_eq!(address.escaped_subject(), escaped);
            assert_ne!(address.segment(), agent(4, "worker").segment());
        }
    }

    #[test]
    fn both_domains_derive_the_same_pair_and_only_their_own_reader() {
        let a = agent(1, "worker");
        let b = agent(2, "worker");
        let conversation = ConversationAddress::new(SPACE.into(), a.clone(), b.clone()).unwrap();
        let reverse = ConversationAddress::new(SPACE.into(), b.clone(), a.clone()).unwrap();
        assert_eq!(conversation, reverse);
        assert!(conversation.reader(&agent(3, "worker")).is_err());
        assert_eq!(
            ConversationPath::parse(&conversation.transcript()).unwrap(),
            ConversationPath::Transcript(conversation.clone())
        );
        assert_eq!(
            ConversationPath::parse(&conversation.reader(&a).unwrap()).unwrap(),
            ConversationPath::Reader {
                conversation,
                owner: a
            }
        );
    }

    #[test]
    fn authorization_paths_cannot_be_substring_matches_or_reordered_aliases() {
        let a = agent(1, "a");
        let b = agent(2, "b");
        let conversation = ConversationAddress::new(SPACE.into(), a, b).unwrap();
        let valid = conversation.transcript();
        for invalid in [
            format!("/workspace{valid}"),
            format!("{valid}/extra"),
            valid.replacen("/pairs/", "//pairs/", 1),
            format!("{valid}{}", "/extra".repeat(200)),
            format!(
                "{PREFIX}{SPACE}/pairs/{}/{}/transcript",
                conversation.second.segment(),
                conversation.first.segment()
            ),
        ] {
            assert!(ConversationPath::parse(&invalid).is_err());
        }
    }

    #[test]
    fn legacy_gate_denies_new_family_only_for_foreign_callers() {
        use kernel::kernel::OperationContext;
        use kernel::{Permission, PermissionProvider};
        let conversation =
            ConversationAddress::new(SPACE.into(), agent(1, "a"), agent(2, "b")).unwrap();
        let mut context = OperationContext::new("caller", "root", false, Some("worker"), false);
        context.trust_domain = Some("foreign".into());
        for permission in [Permission::Read, Permission::Write] {
            assert!(crate::ForeignAgentMailboxOnly
                .check(&conversation.transcript(), None, permission, &context)
                .is_err());
        }
        // Record the counterexample: a profile-wide boundary and zone-wide
        // version qualification are required before activating the new family.
        for actor in [Some("worker"), None] {
            let domestic = OperationContext::new("caller", "root", false, actor, false);
            for permission in [Permission::Read, Permission::Write] {
                for path in [
                    conversation.transcript(),
                    conversation.reader(&agent(1, "a")).unwrap(),
                ] {
                    assert!(crate::ForeignAgentMailboxOnly
                        .check(&path, None, permission, &domestic)
                        .is_ok());
                }
            }
        }
    }
}
