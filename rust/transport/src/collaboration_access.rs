//! Compose actual TLS authentication with current native space authorization.
//! No daemon enables this admission boundary yet. Data routing, native operator
//! management, content gates and canonical sender stamping remain required.

use a2a::{
    collaboration_pair::{PairContext, PairDescription, PairIntent, PairRequest},
    collaboration_policy::{
        validated_space_key, CollaborationOperation, PolicyError, SpacePolicyStore,
    },
    domain_address::{AgentAddress, ConversationPath},
};
use lib::transport_primitives::FederatedClientCertVerifier;
use tonic::Request;

use crate::{
    collaboration_identity::{
        authenticate_request, AuthenticatedAgent, CurrentAgentAuthority, IdentityError,
    },
    grpc::AuthedRequest,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Identity(IdentityError),
    Policy(PolicyError),
    ClockUnavailable,
}

/// An admitted operation, not a cached grant or an append receipt. Constructors
/// are private; body fields never become its authenticated actor. Admission does
/// not establish quiescence or atomic revocation through data-plane completion.
#[derive(Debug)]
pub struct AdmittedOperation {
    actor: AuthenticatedAgent,
    path: ConversationPath,
}

impl AdmittedOperation {
    pub fn actor(&self) -> &AgentAddress {
        self.actor.address()
    }
    pub fn path(&self) -> &ConversationPath {
        &self.path
    }
}

/// Actual current TLS/policy admission for pair preparation. Not a storage
/// transaction, durable attachment, presence report or reusable grant. The
/// adapter must inspect the intent and retain its operation/completion fences.
#[derive(Debug)]
pub struct AdmittedPair {
    actor: AuthenticatedAgent,
    description: PairDescription,
    intent: PairIntent,
}

impl AdmittedPair {
    pub fn actor(&self) -> &AgentAddress {
        self.actor.address()
    }
    pub fn description(&self) -> &PairDescription {
        &self.description
    }
    pub fn intent(&self) -> PairIntent {
        self.intent
    }
}

/// Candidate pair descriptions within ONE current granted space. No global
/// listing, other party's reader write, active receiver or provision is implied.
#[derive(Debug)]
pub struct AdmittedPairDiscovery {
    actor: AuthenticatedAgent,
    descriptions: Vec<PairDescription>,
}

impl AdmittedPairDiscovery {
    pub fn actor(&self) -> &AgentAddress {
        self.actor.address()
    }
    pub fn descriptions(&self) -> &[PairDescription] {
        &self.descriptions
    }
}

fn now_ms() -> Result<u64, AdmissionError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AdmissionError::ClockUnavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| AdmissionError::ClockUnavailable)
}

/// Composition-root binding to this serving authority and its ACTUAL routed
/// zone. These values must come from native profile/mount state, not the RPC or
/// a decoded policy. Every call performs current identity and consensus reads.
pub struct SpaceAuthorizer<'a> {
    verifier: &'a FederatedClientCertVerifier,
    current: &'a dyn CurrentAgentAuthority,
    store: &'a dyn SpacePolicyStore,
    host: &'a [u8; 32],
    routed_zone: &'a str,
}

impl<'a> SpaceAuthorizer<'a> {
    pub fn new(
        verifier: &'a FederatedClientCertVerifier,
        current: &'a dyn CurrentAgentAuthority,
        store: &'a dyn SpacePolicyStore,
        host: &'a [u8; 32],
        routed_zone: &'a str,
    ) -> Self {
        Self {
            verifier,
            current,
            store,
            host,
            routed_zone,
        }
    }

    pub fn authorize<T: AuthedRequest>(
        &self,
        request: &Request<T>,
        path: &str,
        operation: CollaborationOperation,
    ) -> Result<AdmittedOperation, AdmissionError> {
        let actor = authenticate_request(request, self.verifier, self.current)
            .map_err(AdmissionError::Identity)?;
        let parsed = ConversationPath::parse(path)
            .map_err(|e| AdmissionError::Policy(PolicyError::Invalid(e.into())))?;
        let space = match &parsed {
            ConversationPath::Transcript(c) => c.space(),
            ConversationPath::Reader { conversation, .. } => conversation.space(),
        };
        let policy = self.store.current(space).map_err(AdmissionError::Policy)?;
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AdmissionError::ClockUnavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| AdmissionError::ClockUnavailable)?;
        let path = policy
            .authorize(
                actor.address(),
                path,
                operation,
                self.host,
                self.routed_zone,
                now_ms,
            )
            .map_err(AdmissionError::Policy)?;
        Ok(AdmittedOperation { actor, path })
    }

    /// A typed adapter supplies this operation, not a generic Write/mkdir RPC.
    /// The peer is request data; the original caller always comes from TLS.
    pub fn authorize_pair<T: AuthedRequest>(
        &self,
        request: &Request<T>,
        pair: &PairRequest,
        intent: PairIntent,
    ) -> Result<AdmittedPair, AdmissionError> {
        let actor = authenticate_request(request, self.verifier, self.current)
            .map_err(AdmissionError::Identity)?;
        let policy = self
            .store
            .current(pair.space())
            .map_err(AdmissionError::Policy)?;
        let description = PairDescription::prepare(
            &policy,
            pair,
            intent,
            &PairContext {
                actor: actor.address(),
                serving_authority: self.host,
                routed_zone: self.routed_zone,
                now_unix_ms: now_ms()?,
            },
        )
        .map_err(AdmissionError::Policy)?;
        Ok(AdmittedPair {
            actor,
            description,
            intent,
        })
    }

    pub fn discover_pairs<T: AuthedRequest>(
        &self,
        request: &Request<T>,
        space: &str,
    ) -> Result<AdmittedPairDiscovery, AdmissionError> {
        let actor = authenticate_request(request, self.verifier, self.current)
            .map_err(AdmissionError::Identity)?;
        validated_space_key(space).map_err(AdmissionError::Policy)?;
        let policy = self.store.current(space).map_err(AdmissionError::Policy)?;
        let descriptions = PairDescription::discover(
            &policy,
            &PairContext {
                actor: actor.address(),
                serving_authority: self.host,
                routed_zone: self.routed_zone,
                now_unix_ms: now_ms()?,
            },
        )
        .map_err(AdmissionError::Policy)?;
        Ok(AdmittedPairDiscovery {
            actor,
            descriptions,
        })
    }
}
