//! Experimental immutable space policy, separate from certificate trust.
//!
//! One space selects one hosting authority and replicated zone, and explicitly
//! grants its bounded member set pairwise collaboration. It never grants generic
//! filesystem/model/administrative access. Revoking a space is irreversible;
//! changing its host/membership requires another space rather than relabelling
//! existing transcripts. Native authenticated management and routing are still
//! required before any daemon may enable this protocol.

use crate::domain_address::{
    validate_space_id, AgentAddress, ConversationAddress, ConversationPath,
};
use serde::{Deserialize, Serialize};

/// Opaque, validated public policy data. Neither this value nor a decoded
/// AgentAddress authenticates a caller; the transport owns that proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpacePolicy {
    wire: SpaceWire,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpaceWire {
    version: u8,
    space: String,
    host_authority: [u8; 32],
    replicated_zone: String,
    members: Vec<String>,
    not_before_unix_ms: u64,
    expires_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollaborationOperation {
    ReadTranscript,
    AppendTranscript,
    ReadOwnReader,
    WriteOwnReader,
    LockOwnReader,
    UnlockOwnReader,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Invalid(String),
    NotYetValid,
    Expired,
    WrongHost,
    WrongZone,
    WrongSpace,
    NotMember,
    NotParticipant,
    WrongReader,
    WrongOperation,
    Revoked,
    NotFound,
    Conflict,
    Unknown(String),
    Unavailable(String),
}

impl SpacePolicy {
    pub fn new(
        space: String,
        host_authority: [u8; 32],
        replicated_zone: String,
        members: Vec<AgentAddress>,
        not_before_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<Self, PolicyError> {
        let mut members: Vec<_> = members.into_iter().map(|a| a.segment()).collect();
        members.sort();
        let policy = Self {
            wire: SpaceWire {
                version: 1,
                space,
                host_authority,
                replicated_zone,
                members,
                not_before_unix_ms,
                expires_unix_ms,
            },
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let w = &self.wire;
        validate_space_id(&w.space).map_err(|e| PolicyError::Invalid(e.into()))?;
        contracts::validate_zone_id_for(contracts::ZoneIdUse::TenantCreate, &w.replicated_zone)
            .map_err(|e| PolicyError::Invalid(e.to_string()))?;
        if w.version != 1
            || w.not_before_unix_ms >= w.expires_unix_ms
            || !(2..=64).contains(&w.members.len())
            || w.members.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(PolicyError::Invalid(
                "invalid version, interval or canonical unique member set".into(),
            ));
        }
        for member in &w.members {
            AgentAddress::parse(member).map_err(|e| PolicyError::Invalid(e.into()))?;
        }
        Ok(())
    }

    pub fn space(&self) -> &str {
        &self.wire.space
    }
    pub fn host_authority(&self) -> &[u8; 32] {
        &self.wire.host_authority
    }
    pub fn replicated_zone(&self) -> &str {
        &self.wire.replicated_zone
    }
    pub fn members(&self) -> &[String] {
        &self.wire.members
    }

    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        self.validate()?;
        serde_json::to_vec(&self.wire).map_err(|e| PolicyError::Invalid(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() > 32 * 1024 {
            return Err(PolicyError::Invalid("space record exceeds 32 KiB".into()));
        }
        let policy = Self {
            wire: serde_json::from_slice(bytes).map_err(|e| PolicyError::Invalid(e.to_string()))?,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Pure policy decision after native current authentication and a current,
    /// non-revoked control-store snapshot. Callers must supply the actual host
    /// and routed zone, not values copied out of the request or this record.
    /// No metadata or arbitrary-operation wildcard is implied by these verbs.
    pub fn authorize(
        &self,
        actor: &AgentAddress,
        path: &str,
        operation: CollaborationOperation,
        serving_authority: &[u8; 32],
        routed_zone: &str,
        now_unix_ms: u64,
    ) -> Result<ConversationPath, PolicyError> {
        if serving_authority != self.host_authority() {
            return Err(PolicyError::WrongHost);
        }
        if routed_zone != self.replicated_zone() {
            return Err(PolicyError::WrongZone);
        }
        if now_unix_ms < self.wire.not_before_unix_ms {
            return Err(PolicyError::NotYetValid);
        }
        if now_unix_ms >= self.wire.expires_unix_ms {
            return Err(PolicyError::Expired);
        }
        let parsed = ConversationPath::parse(path).map_err(|e| PolicyError::Invalid(e.into()))?;
        let conversation: &ConversationAddress = match &parsed {
            ConversationPath::Transcript(c) => c,
            ConversationPath::Reader { conversation, .. } => conversation,
        };
        if conversation.space() != self.space() {
            return Err(PolicyError::WrongSpace);
        }
        for member in [
            actor,
            conversation.participants().0,
            conversation.participants().1,
        ] {
            if self.wire.members.binary_search(&member.segment()).is_err() {
                return Err(PolicyError::NotMember);
            }
        }
        if !conversation.contains(actor) {
            return Err(PolicyError::NotParticipant);
        }
        match (&parsed, operation) {
            (
                ConversationPath::Transcript(_),
                CollaborationOperation::ReadTranscript | CollaborationOperation::AppendTranscript,
            ) => {}
            (
                ConversationPath::Reader { owner, .. },
                CollaborationOperation::ReadOwnReader
                | CollaborationOperation::WriteOwnReader
                | CollaborationOperation::LockOwnReader
                | CollaborationOperation::UnlockOwnReader,
            ) => {
                if owner != actor {
                    return Err(PolicyError::WrongReader);
                }
            }
            _ => return Err(PolicyError::WrongOperation),
        }
        Ok(parsed)
    }
}

/// Native storage boundary. A snapshot must observe the immutable policy and
/// its irreversible revocation at one consensus read point. Unsupported or
/// unavailable consensus is an error, never a missing grant/default allow.
pub trait SpacePolicyStore: Send + Sync {
    fn create(&self, policy: &SpacePolicy) -> Result<(), PolicyError>;
    fn current(&self, space: &str) -> Result<SpacePolicy, PolicyError>;
    fn revoke(&self, space: &str) -> Result<(), PolicyError>;
}

/// Shared key validation for storage adapters, without another address codec.
pub fn validated_space_key(space: &str) -> Result<String, PolicyError> {
    validate_space_id(space).map_err(|e| PolicyError::Invalid(e.into()))?;
    Ok(format!("space:{space}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SPACE: &str = "0123456789abcdef0123456789abcdef";
    fn actor(key: u8, name: &str) -> AgentAddress {
        AgentAddress::new([key; 32], name.into()).unwrap()
    }
    fn policy(members: Vec<AgentAddress>) -> SpacePolicy {
        SpacePolicy::new(
            SPACE.into(),
            [1; 32],
            "collab-one".into(),
            members,
            100,
            200,
        )
        .unwrap()
    }
    #[test]
    fn grant_is_pair_scoped_even_for_another_authorized_space_member() {
        let a = actor(1, "same");
        let b = actor(2, "same");
        let c = actor(3, "other");
        let p = policy(vec![a.clone(), b.clone(), c.clone()]);
        let pair = ConversationAddress::new(SPACE.into(), a.clone(), b.clone()).unwrap();
        let check = |who: &AgentAddress, path: &str, op| {
            p.authorize(who, path, op, &[1; 32], "collab-one", 150)
        };
        assert!(check(
            &a,
            &pair.transcript(),
            CollaborationOperation::AppendTranscript
        )
        .is_ok());
        assert!(check(
            &b,
            &pair.transcript(),
            CollaborationOperation::ReadTranscript
        )
        .is_ok());
        assert_eq!(
            check(
                &c,
                &pair.transcript(),
                CollaborationOperation::ReadTranscript
            ),
            Err(PolicyError::NotParticipant)
        );
        assert!(check(
            &a,
            &pair.reader(&a).unwrap(),
            CollaborationOperation::WriteOwnReader
        )
        .is_ok());
        assert_eq!(
            check(
                &a,
                &pair.reader(&b).unwrap(),
                CollaborationOperation::WriteOwnReader
            ),
            Err(PolicyError::WrongReader)
        );
        assert_eq!(
            check(
                &a,
                &pair.transcript(),
                CollaborationOperation::WriteOwnReader
            ),
            Err(PolicyError::WrongOperation)
        );
    }
    #[test]
    fn host_zone_time_and_ungranted_pair_cannot_fall_back_to_local_creation() {
        let a = actor(1, "a");
        let b = actor(2, "b");
        let c = actor(3, "c");
        let p = policy(vec![a.clone(), b.clone()]);
        let pair = ConversationAddress::new(SPACE.into(), a.clone(), b).unwrap();
        let op = CollaborationOperation::AppendTranscript;
        assert_eq!(
            p.authorize(&a, &pair.transcript(), op, &[2; 32], "collab-one", 150),
            Err(PolicyError::WrongHost)
        );
        assert_eq!(
            p.authorize(&a, &pair.transcript(), op, &[1; 32], "root", 150),
            Err(PolicyError::WrongZone)
        );
        assert_eq!(
            p.authorize(&a, &pair.transcript(), op, &[1; 32], "collab-one", 99),
            Err(PolicyError::NotYetValid)
        );
        assert_eq!(
            p.authorize(&a, &pair.transcript(), op, &[1; 32], "collab-one", 200),
            Err(PolicyError::Expired)
        );
        let outside = ConversationAddress::new(SPACE.into(), a.clone(), c).unwrap();
        assert_eq!(
            p.authorize(&a, &outside.transcript(), op, &[1; 32], "collab-one", 150),
            Err(PolicyError::NotMember)
        );
    }
    #[test]
    fn persisted_policy_rejects_schema_drift_duplicates_and_noncanonical_members() {
        let a = actor(1, "a");
        let b = actor(2, "b");
        assert!(SpacePolicy::new(
            SPACE.into(),
            [1; 32],
            "root".into(),
            vec![a.clone(), b.clone()],
            100,
            200
        )
        .is_err());
        assert!(SpacePolicy::new(
            SPACE.into(),
            [1; 32],
            "collab-one".into(),
            vec![a.clone(), a.clone()],
            100,
            200
        )
        .is_err());
        let p = policy(vec![a, b]);
        let bytes = p.encode().unwrap();
        assert_eq!(SpacePolicy::decode(&bytes).unwrap(), p);
        let mut wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        wire["members"].as_array_mut().unwrap().reverse();
        assert!(SpacePolicy::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
        wire = serde_json::from_slice(&bytes).unwrap();
        wire["grantAll"] = true.into();
        assert!(SpacePolicy::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
    }
}
