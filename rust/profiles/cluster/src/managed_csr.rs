//! Versioned frontend for the existing I/F coordinator and CA holder. No key
//! generation, second issuer/store, legacy name adoption or automatic retry.
use super::FounderAgentMinter;
use auth::agent_issuance::{
    agent_intent_digest, commit_agent_intent, finalize_agent_issuance, query_agent_issuance,
    AgentIssuanceIntent, AgentIssuanceState, IssuanceAuthorizer, IssuanceBinding,
};
use nexus_raft::agent_minter::agent_csr_request_digest;
use nexus_raft::transport::proto::{
    AgentCsrCapabilitiesResponse, AgentCsrRequest, AgentCsrResponse, AgentCsrState,
};
use nexus_raft::transport::{
    current_local_node_certificate, prepare_agent_csr_intent, read_revoked_serials_checked,
    revoked_serials_path, sign_committed_agent_intent,
};
use sha2::{Digest, Sha256};

pub(super) fn failure(state: AgentCsrState, reason: impl ToString) -> AgentCsrResponse {
    AgentCsrResponse {
        state: state as i32,
        error: Some(reason.to_string()),
        ..Default::default()
    }
}

fn issuer_bytes(issuer: &FounderAgentMinter) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pem =
        std::fs::read(issuer.tls_dir.join("ca.pem")).map_err(|e| format!("read local CA: {e}"))?;
    let der = lib::transport_primitives::first_certificate_der(&pem, "local issuer CA")?;
    let verifier = issuer
        .peer_verifier
        .get()
        .ok_or("local issuer authority is unavailable")?;
    if verifier.cluster_ca_der() != der {
        return Err("issuer CA does not match current local TLS authority".into());
    }
    Ok((pem, der))
}

pub(super) fn capabilities(issuer: &FounderAgentMinter) -> AgentCsrCapabilitiesResponse {
    match issuer_bytes(issuer) {
        Ok((_, der)) => AgentCsrCapabilitiesResponse {
            version: 1,
            issuer_sha256: Sha256::digest(der).to_vec(),
        },
        Err(_) => AgentCsrCapabilitiesResponse::default(),
    }
}

struct CurrentNode<'a> {
    issuer: &'a FounderAgentMinter,
    caller: &'a [u8],
    expected: &'a IssuanceBinding,
}
impl IssuanceAuthorizer for CurrentNode<'_> {
    fn authorize(&self, binding: &IssuanceBinding) -> Result<(), String> {
        if binding != self.expected {
            return Err("issuance binding changed".into());
        }
        let (_, ca_der) = issuer_bytes(self.issuer)?;
        let node = current_local_node_certificate(self.caller, &ca_der)?;
        if binding.caller_id != format!("node:{}", node.node_id)
            || binding.issuer_sha256 != hex(&Sha256::digest(ca_der))
        {
            return Err("current Node or issuer differs from issuance binding".into());
        }
        let revoked = read_revoked_serials_checked(&revoked_serials_path(&self.issuer.data_dir))?;
        if revoked.contains(&node.serial) {
            return Err("revoked Node cannot issue or query Agent credentials".into());
        }
        // A local Node is already the native cluster control principal. It
        // vouches for the resolved managed descriptor/owner; a frontend Agent
        // cannot reach this policy or choose an owner on another Node's behalf.
        Ok(())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn observed_reply(
    state: AgentIssuanceState,
    binding: &IssuanceBinding,
    ca_pem: Vec<u8>,
) -> Result<AgentCsrResponse, String> {
    let mut reply = AgentCsrResponse {
        agent_name: binding.agent_name.clone(),
        owner_id: binding.owner_id.clone(),
        operation_id: binding.operation_id.clone(),
        request_sha256: binding.request_sha256.to_vec(),
        ca_pem,
        ..Default::default()
    };
    let (intent, finalized) = match state {
        AgentIssuanceState::NotObserved => {
            reply.state = AgentCsrState::NotObserved as i32;
            return Ok(reply);
        }
        AgentIssuanceState::IntentCommitted(intent) => (intent, None),
        AgentIssuanceState::Finalized {
            intent,
            certificate,
        } => (intent, Some(certificate)),
    };
    reply.intent_sha256 = agent_intent_digest(&intent)
        .map_err(|e| e.to_string())?
        .to_vec();
    reply.serial = intent.certificate.serial;
    reply.state = AgentCsrState::IntentCommitted as i32;
    if let Some(certificate) = finalized {
        reply.state = AgentCsrState::Finalized as i32;
        reply.certificate_der = certificate.certificate_der;
    }
    Ok(reply)
}

pub(super) fn execute(
    issuer: &FounderAgentMinter,
    caller: Option<Vec<u8>>,
    request: AgentCsrRequest,
    query_only: bool,
) -> AgentCsrResponse {
    let preflight = || -> Result<_, String> {
        let digest = agent_csr_request_digest(&request)?;
        let caller = caller
            .as_deref()
            .ok_or("Agent CSR issuance requires actual Node mTLS")?;
        let (ca_pem, ca_der) = issuer_bytes(issuer)?;
        if Sha256::digest(&ca_der).as_slice() != request.issuer_sha256 {
            return Err("expected issuer does not match current local CA".into());
        }
        let node = current_local_node_certificate(caller, &ca_der)?;
        let binding = IssuanceBinding {
            issuer_sha256: hex(&request.issuer_sha256),
            caller_id: format!("node:{}", node.node_id),
            owner_id: request.owner_id.clone(),
            agent_name: request.agent_name.clone(),
            operation_id: request.operation_id.clone(),
            request_sha256: digest,
        };
        CurrentNode {
            issuer,
            caller,
            expected: &binding,
        }
        .authorize(&binding)?;
        Ok((ca_pem, binding))
    };
    let (ca_pem, binding) = match preflight() {
        Ok(value) => value,
        Err(error) => return failure(AgentCsrState::NotSubmitted, error),
    };
    let authority = CurrentNode {
        issuer,
        caller: caller.as_deref().expect("preflight checked caller"),
        expected: &binding,
    };
    let observed = match query_agent_issuance(&issuer.store, &authority, &binding) {
        Ok(state) => state,
        Err(error) => return failure(AgentCsrState::Unknown, error),
    };
    if query_only || matches!(observed, AgentIssuanceState::Finalized { .. }) {
        return observed_reply(observed, &binding, ca_pem)
            .unwrap_or_else(|e| failure(AgentCsrState::Unknown, e));
    }
    if matches!(observed, AgentIssuanceState::NotObserved) {
        // This operation takes PUBLIC CA bytes only. No signing key is read
        // until the coordinator calls the signer for committed winning I.
        let certificate =
            match prepare_agent_csr_intent(&request.agent_name, &request.csr_pem, &ca_pem) {
                Ok(certificate) => certificate,
                Err(error) => return failure(AgentCsrState::NotSubmitted, error),
            };
        let record = auth::AuthKeyRecord {
            key_id: super::uuid_v4(),
            name: request.display_name,
            subject_type: auth::SubjectType::Agent,
            subject_id: binding.agent_name.clone(),
            is_admin: false,
            revoked: false,
            expires_at_ms: None,
            zone_perms: vec![],
        };
        let intent = AgentIssuanceIntent {
            schema_version: 2,
            binding: binding.clone(),
            certificate,
        };
        // From this point any error is conservatively Unknown. No automatic
        // mutation retry, remint, legacy adoption or new operation is attempted.
        if let Err(error) = commit_agent_intent(&issuer.store, &authority, record, intent) {
            return failure(AgentCsrState::Unknown, error);
        }
    }
    if let Err(error) = finalize_agent_issuance(&issuer.store, &authority, &binding, |intent| {
        let key = std::fs::read(issuer.tls_dir.join("ca-key.pem"))
            .map_err(|e| format!("read issuer key: {e}"))?;
        sign_committed_agent_intent(intent, &ca_pem, &key)
    }) {
        return failure(AgentCsrState::Unknown, error);
    }
    match query_agent_issuance(&issuer.store, &authority, &binding) {
        Ok(state) => observed_reply(state, &binding, ca_pem)
            .unwrap_or_else(|e| failure(AgentCsrState::Unknown, e)),
        Err(error) => failure(AgentCsrState::Unknown, error),
    }
}

#[cfg(test)]
pub(super) mod tests;
