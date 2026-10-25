//! Native host-to-issuer composition. The public request contains neither a
//! caller certificate nor an issuer URL: only the boot composition supplies
//! this daemon's selected TLS identity and the existing minter slot.

use super::*;
use nexus_raft::{
    agent_minter::{AgentMinter, AgentMinterSlot},
    transport::{current_local_node_certificate, proto::AgentCsrState, TlsConfig},
};

pub(crate) struct NativeIssuer {
    slot: AgentMinterSlot,
    node_der: Vec<u8>,
    issuer_der: Vec<u8>,
    runtime: tokio::runtime::Handle,
}

impl NativeIssuer {
    /// Only the trusted profile calls this with the SAME TLS configuration
    /// used by the daemon. This is an in-process native call, not a claim that
    /// a public DER supplied over Call proves possession or Node authority.
    pub(crate) fn from_tls(
        slot: AgentMinterSlot,
        tls: &TlsConfig,
        runtime: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let node_der =
            first_certificate_der(&tls.cert_pem, "native Node").map_err(anyhow::Error::msg)?;
        let issuer_der =
            first_certificate_der(&tls.ca_pem, "native issuer").map_err(anyhow::Error::msg)?;
        current_local_node_certificate(&node_der, &issuer_der).map_err(anyhow::Error::msg)?;
        Ok(Self {
            slot,
            node_der,
            issuer_der,
            runtime,
        })
    }

    pub(super) fn minter(&self, ca: &[u8]) -> Result<Arc<dyn AgentMinter>, String> {
        if first_certificate_der(ca, "prepared issuer")? != self.issuer_der {
            return Err("prepared issuer differs from the daemon's native TLS authority".into());
        }
        current_local_node_certificate(&self.node_der, &self.issuer_der)?;
        let minter = self
            .slot
            .read()
            .clone()
            .ok_or("native CA holder is not installed on this host")?;
        let capabilities = minter.csr_capabilities();
        if capabilities.version != 1
            || capabilities.issuer_sha256 != Sha256::digest(&self.issuer_der).to_vec()
        {
            return Err("native issuer does not support the exact prepared CSR authority".into());
        }
        Ok(minter)
    }
}

impl PreparationService {
    pub(super) fn issue(
        &self,
        verb: &str,
        target: Target,
        ctx: &OperationContext,
    ) -> Result<Value, RustCallError> {
        let registry = self.kernel.agent_registry();
        let managed = ManagedCredentialBinding::resolve(registry, ctx, &target.pid)?;
        let mut response = json!({"schemaVersion":1,"operationId":target.operation_id,
            "submissionAttempted":false,"issuanceOutcome":"unknown",
            "credentialPublished":false,"managedRuntimeActivated":false});
        let mut execute = || -> Result<(), String> {
            let issuer = self
                .issuer
                .as_ref()
                .ok_or("native managed CSR issuance is unsupported on this host")?;
            let minter = issuer.minter(&self.ca)?;
            let binding = AgentCsrBinding {
                agent_name: managed.agent(),
                owner_id: managed.owner(),
                display_name: managed.agent(),
                operation_id: &target.operation_id,
            };
            // Never implicitly prepare or replace a key on issue/query/publish.
            let pending = PendingAgentCsr::load(
                &self.pending_path(&managed, &target.operation_id),
                &binding,
                &self.ca,
            )?;
            managed
                .ensure_current(registry)
                .map_err(|e| e.to_string())?;
            response["requestSha256"] = json!(agent_csr_request_digest(pending.request())?);
            response["binding"] = json!({"pid":managed.pid(),"agentId":managed.agent(),"ownerId":managed.owner(),"zone":managed.zone()});
            response["submissionAttempted"] = json!(verb == "issue_v1");
            // The existing issuer rechecks the native Node, current CA and
            // revocation at every I/F stage. One invocation; no retry/fallback.
            let observed = lib::rt::block_on_via(
                &issuer.runtime,
                minter.agent_csr_v1(
                    Some(issuer.node_der.clone()),
                    pending.request().clone(),
                    verb != "issue_v1",
                ),
            );
            // Keep the attempted flag even when a later validation fails.
            let state = response_observation(&mut response, &pending, &observed)?;
            if let Err(error) = managed.ensure_current(registry) {
                response["issuanceOutcome"] = "unknown".into();
                response["error"] =
                    format!("managed binding changed after issuer work: {error}").into();
                return Ok(());
            }
            if verb == "publish_v1" && state == AgentCsrState::Finalized {
                let directory = self.root.join(format!(
                    "managed-agent-{}",
                    Self::operation_key(managed.agent(), managed.owner(), &target.operation_id)
                ));
                // This loader is shared with the explicit operator path. It
                // verifies stored F, caller key/profile and writes manifest last.
                pending.publish(&observed, &directory)?;
                managed
                    .ensure_current(registry)
                    .map_err(|e| e.to_string())?;
                response["credentialPublished"] = true.into();
                response["localCredentialId"] =
                    Self::operation_key(managed.agent(), managed.owner(), &target.operation_id)
                        .into();
            }
            Ok(())
        };
        if let Err(error) = execute() {
            // A prior operation or local publication may already exist.
            // Only explicit query of the SAME key/request can reconcile it.
            response["issuanceOutcome"] = "unknown".into();
            response["error"] = error.into();
        }
        Ok(response)
    }
}

fn response_observation(
    result: &mut Value,
    pending: &PendingAgentCsr,
    observed: &nexus_raft::transport::proto::AgentCsrResponse,
) -> Result<AgentCsrState, String> {
    let state = pending.observe(observed)?;
    result["issuerObservation"] = match state {
        AgentCsrState::Finalized => "finalized",
        AgentCsrState::IntentCommitted => "intent_committed",
        AgentCsrState::NotObserved => "not_observed",
        AgentCsrState::NotSubmitted => "not_submitted",
        AgentCsrState::Unknown => "unknown",
        AgentCsrState::Unspecified => return Err("unspecified CSR state".into()),
    }
    .into();
    // A refusal/not-observed reply to this invocation does not establish that
    // an earlier ambiguous submission was absent. Preserve Unknown unless F
    // has passed the shared exact-binding and certificate validation.
    if state == AgentCsrState::Finalized {
        result["issuanceOutcome"] = "finalized".into();
        result["certificateSha256"] =
            json!(<[u8; 32]>::from(Sha256::digest(&observed.certificate_der)));
    }
    if let Some(error) = &observed.error {
        result["error"] = error.clone().into();
    }
    Ok(state)
}

#[cfg(test)]
mod tests;
