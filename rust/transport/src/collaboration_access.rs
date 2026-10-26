//! Compose actual TLS authentication with current native space authorization.
//! No daemon enables this admission boundary yet. Data routing, native operator
//! management, content gates and canonical sender stamping remain required.

use a2a::{
    collaboration_policy::{CollaborationOperation, PolicyError, SpacePolicyStore},
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
}
