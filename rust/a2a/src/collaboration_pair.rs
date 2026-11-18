//! Pair preparation for an attachment behind the existing local Kernel.
//!
//! These are validated public values and pure policy composition, not a live
//! route, authenticated actor, provision receipt or grant. The transport must
//! supply the actual current actor/host/route and a current policy snapshot.
//! No profile enables these operations or advertises data-plane version 1 yet.

use crate::collaboration_policy::{CollaborationOperation, PolicyError, SpacePolicy};
use crate::domain_address::{validate_space_id, AgentAddress, ConversationAddress};
use serde::{Deserialize, Serialize};

pub const PAIR_CONTRACT_VERSION: u32 = 1;
const MAX_REQUEST_BYTES: usize = 1024;
const MAX_DESCRIPTION_BYTES: usize = 4096;

/// The adapter chooses the operation; the request never supplies a caller,
/// arbitrary filesystem path, host, routed zone or another reader's owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairIntent {
    Describe,
    /// Ensure the pair exists without overwriting any transcript, reader or
    /// operation record. This does not grant generic mkdir/link/write access.
    Provision,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairRequest {
    version: u32,
    space: String,
    peer: String,
}

impl PairRequest {
    pub fn new(space: String, peer: &AgentAddress) -> Result<Self, PolicyError> {
        validate_space_id(&space).map_err(invalid)?;
        Ok(Self {
            version: PAIR_CONTRACT_VERSION,
            space,
            peer: peer.segment(),
        })
    }

    pub fn decode(payload: &[u8]) -> Result<Self, PolicyError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            version: u32,
            space: String,
            peer: String,
        }
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(invalid("pair request exceeds 1024 bytes"));
        }
        let request: Wire = serde_json::from_slice(payload).map_err(invalid)?;
        if request.version != PAIR_CONTRACT_VERSION {
            return Err(invalid("unsupported pair request version"));
        }
        validate_space_id(&request.space).map_err(invalid)?;
        AgentAddress::parse(&request.peer).map_err(invalid)?;
        Ok(Self {
            version: request.version,
            space: request.space,
            peer: request.peer,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        serde_json::to_vec(self).map_err(invalid)
    }

    pub fn space(&self) -> &str {
        &self.space
    }

    pub fn conversation_for(
        &self,
        authenticated_actor: &AgentAddress,
    ) -> Result<ConversationAddress, PolicyError> {
        ConversationAddress::new(
            self.space.clone(),
            authenticated_actor.clone(),
            AgentAddress::parse(&self.peer).map_err(invalid)?,
        )
        .map_err(invalid)
    }
}

/// Actual native admission inputs. Public values alone are not authority.
pub struct PairContext<'a> {
    pub actor: &'a AgentAddress,
    pub serving_authority: &'a [u8; 32],
    pub routed_zone: &'a str,
    pub now_unix_ms: u64,
}

/// A canonical description for one authenticated caller's side of a pair.
/// No peer-controlled path is carried on the wire. The digest pins the complete
/// immutable policy image; a description must never replace a current read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairDescription {
    wire: PairWire,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairWire {
    version: u32,
    space: String,
    host_authority: [u8; 32],
    replicated_zone: String,
    participants: [String; 2],
    actor: String,
    policy_digest: [u8; 32],
}

impl PairDescription {
    /// Compose existing operation checks against ONE supplied current policy.
    /// Provision adds no authority to mutate the peer's existing reader. Its
    /// actual storage transaction and idempotent operation receipt are separate
    /// obligations of the native adapter, not implemented by this value.
    pub fn prepare(
        policy: &SpacePolicy,
        request: &PairRequest,
        intent: PairIntent,
        context: &PairContext<'_>,
    ) -> Result<Self, PolicyError> {
        let pair = request.conversation_for(context.actor)?;
        let own_reader = pair.reader(context.actor).map_err(invalid)?;
        let mut required = vec![
            (pair.transcript(), CollaborationOperation::ReadTranscript),
            (own_reader.clone(), CollaborationOperation::ReadOwnReader),
        ];
        if intent == PairIntent::Provision {
            required.extend([
                (pair.transcript(), CollaborationOperation::AppendTranscript),
                (own_reader, CollaborationOperation::WriteOwnReader),
            ]);
        }
        for (path, operation) in required {
            policy.authorize(
                context.actor,
                &path,
                operation,
                context.serving_authority,
                context.routed_zone,
                context.now_unix_ms,
            )?;
        }
        let (first, second) = pair.participants();
        Ok(Self {
            wire: PairWire {
                version: PAIR_CONTRACT_VERSION,
                space: pair.space().to_owned(),
                host_authority: *policy.host_authority(),
                replicated_zone: policy.replicated_zone().to_owned(),
                participants: [first.segment(), second.segment()],
                actor: context.actor.segment(),
                policy_digest: *blake3::hash(&policy.encode()?).as_bytes(),
            },
        })
    }

    /// Discover only this actor's possible pairs in one explicitly selected
    /// current space. No global agent/presence/directory enumeration is implied;
    /// these descriptions do not say that a transcript or live receiver exists.
    pub fn discover(
        policy: &SpacePolicy,
        context: &PairContext<'_>,
    ) -> Result<Vec<Self>, PolicyError> {
        let actor = context.actor.segment();
        if policy.members().binary_search(&actor).is_err() {
            return Err(PolicyError::NotMember);
        }
        policy
            .members()
            .iter()
            .filter(|peer| *peer != &actor)
            .map(|peer| {
                let request = PairRequest::new(
                    policy.space().to_owned(),
                    &AgentAddress::parse(peer).map_err(invalid)?,
                )?;
                Self::prepare(policy, &request, PairIntent::Describe, context)
            })
            .collect()
    }

    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        serde_json::to_vec(&self.wire).map_err(invalid)
    }

    /// Validate public syntax only. The caller must compare to its actual
    /// native attachment and retain the current admission for each operation.
    pub fn decode(payload: &[u8]) -> Result<Self, PolicyError> {
        if payload.len() > MAX_DESCRIPTION_BYTES {
            return Err(invalid("pair description exceeds 4096 bytes"));
        }
        let wire: PairWire = serde_json::from_slice(payload).map_err(invalid)?;
        if wire.version != PAIR_CONTRACT_VERSION {
            return Err(invalid("unsupported pair description version"));
        }
        contracts::validate_zone_id_for(contracts::ZoneIdUse::TenantCreate, &wire.replicated_zone)
            .map_err(invalid)?;
        let pair = ConversationAddress::new(
            wire.space.clone(),
            AgentAddress::parse(&wire.participants[0]).map_err(invalid)?,
            AgentAddress::parse(&wire.participants[1]).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let (first, second) = pair.participants();
        if [first.segment(), second.segment()] != wire.participants
            || !pair.contains(&AgentAddress::parse(&wire.actor).map_err(invalid)?)
        {
            return Err(invalid("noncanonical pair or unrelated actor"));
        }
        Ok(Self { wire })
    }

    /// Use an independently authenticated native expected binding, never a
    /// second copy of the same untrusted response. This is still not a grant.
    pub fn require_matches(&self, expected: &Self) -> Result<(), PolicyError> {
        if self != expected {
            return Err(PolicyError::Conflict);
        }
        Ok(())
    }

    pub fn conversation(&self) -> Result<ConversationAddress, PolicyError> {
        ConversationAddress::new(
            self.wire.space.clone(),
            AgentAddress::parse(&self.wire.participants[0]).map_err(invalid)?,
            AgentAddress::parse(&self.wire.participants[1]).map_err(invalid)?,
        )
        .map_err(invalid)
    }

    pub fn own_reader(&self) -> Result<String, PolicyError> {
        self.conversation()?
            .reader(&AgentAddress::parse(&self.wire.actor).map_err(invalid)?)
            .map_err(invalid)
    }
}

/// A future installed adapter must advertise both versions only after all
/// profile/storage/authority/consumer dependencies are enforced. This function
/// cannot authenticate a capability response or activate the current profile.
pub fn require_pair_capability(payload: &[u8]) -> Result<(), PolicyError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Capability {
        #[serde(default)]
        data_plane_version: u32,
        #[serde(default)]
        pair_contract_version: u32,
    }
    if payload.len() > MAX_DESCRIPTION_BYTES {
        return Err(invalid("capability exceeds 4096 bytes"));
    }
    let capability: Capability = serde_json::from_slice(payload).map_err(invalid)?;
    if capability.data_plane_version != 1
        || capability.pair_contract_version != PAIR_CONTRACT_VERSION
    {
        return Err(invalid("complete native pair capability is unavailable"));
    }
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> PolicyError {
    PolicyError::Invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const SPACE: &str = "0123456789abcdef0123456789abcdef";
    fn actor(ca: u8) -> AgentAddress {
        AgentAddress::new([ca; 32], "worker".to_owned()).unwrap()
    }
    fn policy(members: Vec<AgentAddress>) -> SpacePolicy {
        SpacePolicy::new(SPACE.into(), [9; 32], "collab-one".into(), members, 10, 100).unwrap()
    }
    fn context(actor: &AgentAddress) -> PairContext<'_> {
        PairContext {
            actor,
            serving_authority: &[9; 32],
            routed_zone: "collab-one",
            now_unix_ms: 50,
        }
    }

    #[test]
    fn caller_is_not_a_request_field_and_noncanonical_peers_refuse() {
        let peer = actor(2);
        let valid = PairRequest::new(SPACE.into(), &peer)
            .unwrap()
            .encode()
            .unwrap();
        assert!(PairRequest::decode(&valid).is_ok());
        for (field, value) in [
            ("actor", json!(actor(1).segment())),
            ("path", json!("/agents/other")),
            ("zone", json!("root")),
        ] {
            let mut request: Value = serde_json::from_slice(&valid).unwrap();
            request[field] = value;
            assert!(PairRequest::decode(&serde_json::to_vec(&request).unwrap()).is_err());
        }
        let mut request: Value = serde_json::from_slice(&valid).unwrap();
        request["peer"] = json!(peer.segment().to_uppercase());
        assert!(PairRequest::decode(&serde_json::to_vec(&request).unwrap()).is_err());
        request["peer"] = json!(peer.segment());
        request["version"] = json!(2);
        assert!(PairRequest::decode(&serde_json::to_vec(&request).unwrap()).is_err());
    }

    #[test]
    fn both_ends_share_transcript_but_keep_their_own_reader() {
        let (a, b) = (actor(1), actor(2));
        let policy = policy(vec![a.clone(), b.clone()]);
        let left = PairDescription::prepare(
            &policy,
            &PairRequest::new(SPACE.into(), &b).unwrap(),
            PairIntent::Provision,
            &context(&a),
        )
        .unwrap();
        let right = PairDescription::prepare(
            &policy,
            &PairRequest::new(SPACE.into(), &a).unwrap(),
            PairIntent::Provision,
            &context(&b),
        )
        .unwrap();
        assert_eq!(
            left.conversation().unwrap().transcript(),
            right.conversation().unwrap().transcript()
        );
        assert_ne!(left.own_reader().unwrap(), right.own_reader().unwrap());
        assert_eq!(
            PairDescription::decode(&left.encode().unwrap()).unwrap(),
            left
        );
        assert!(left.require_matches(&right).is_err());
    }

    #[test]
    fn known_space_discovery_excludes_unrelated_pairs_and_ungranted_actor() {
        let (a, b, c) = (actor(1), actor(2), actor(3));
        let policy = policy(vec![a.clone(), b.clone(), c.clone()]);
        let descriptions = PairDescription::discover(&policy, &context(&a)).unwrap();
        assert_eq!(descriptions.len(), 2);
        for description in descriptions {
            assert!(description.conversation().unwrap().contains(&a));
            assert_ne!(
                description.conversation().unwrap(),
                ConversationAddress::new(SPACE.into(), b.clone(), c.clone()).unwrap()
            );
        }
        assert_eq!(
            PairDescription::discover(&policy, &context(&actor(4))),
            Err(PolicyError::NotMember)
        );
    }

    #[test]
    fn preparation_checks_actual_host_zone_time_and_membership() {
        let (a, b) = (actor(1), actor(2));
        let policy = policy(vec![a.clone(), b.clone()]);
        let request = PairRequest::new(SPACE.into(), &b).unwrap();
        let mut ctx = context(&a);
        ctx.serving_authority = &[8; 32];
        assert_eq!(
            PairDescription::prepare(&policy, &request, PairIntent::Provision, &ctx),
            Err(PolicyError::WrongHost)
        );
        ctx.serving_authority = &[9; 32];
        ctx.routed_zone = "another";
        assert_eq!(
            PairDescription::prepare(&policy, &request, PairIntent::Provision, &ctx),
            Err(PolicyError::WrongZone)
        );
        ctx.routed_zone = "collab-one";
        ctx.now_unix_ms = 100;
        assert_eq!(
            PairDescription::prepare(&policy, &request, PairIntent::Provision, &ctx),
            Err(PolicyError::Expired)
        );
        assert_eq!(
            PairDescription::prepare(
                &policy,
                &request,
                PairIntent::Provision,
                &context(&actor(3))
            ),
            Err(PolicyError::NotMember)
        );
    }

    #[test]
    fn public_description_tampering_is_not_an_attachment() {
        let (a, b) = (actor(1), actor(2));
        let original = PairDescription::prepare(
            &policy(vec![a.clone(), b.clone()]),
            &PairRequest::new(SPACE.into(), &b).unwrap(),
            PairIntent::Describe,
            &context(&a),
        )
        .unwrap();
        let mut wire: Value = serde_json::from_slice(&original.encode().unwrap()).unwrap();
        wire["actor"] = json!(actor(3).segment());
        assert!(PairDescription::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
        wire["actor"] = json!(a.segment());
        wire["replicatedZone"] = json!("another");
        let changed = PairDescription::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
        assert_eq!(
            changed.require_matches(&original),
            Err(PolicyError::Conflict)
        );
        wire["replicatedZone"] = json!("collab-one");
        wire["transcript"] = json!("/agents/other");
        assert!(PairDescription::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
    }

    #[test]
    fn management_only_missing_and_future_capabilities_refuse() {
        for value in [
            json!({"managementVersion":1,"dataPlaneVersion":0}),
            json!({"dataPlaneVersion":1}),
            json!({"dataPlaneVersion":1,"pairContractVersion":2}),
            json!({"dataPlaneVersion":2,"pairContractVersion":1}),
        ] {
            assert!(require_pair_capability(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(
            require_pair_capability(br#"{"dataPlaneVersion":1,"pairContractVersion":1}"#).is_ok()
        );
    }
}
