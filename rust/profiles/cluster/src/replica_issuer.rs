//! Native coordinator over the existing replica receipts and CA signer.
//!
//! The trusted composition supplies the actual TLS leaf and its configured
//! local CA. Its allocation observer validates current storage ownership before
//! calling this service. The service creates no allocator or transport listener.

use std::path::Path;

pub use crate::replica_control::ReplicaControlError as ReplicaIssuerError;
use crate::replica_control::{
    after_submission as after_preparation, refused, unknown, with_current_controller,
    CurrentController, Result,
};
use contracts::replica_credential::{
    ReplicaCertificateIntent, ReplicaCredential, ReplicaIssuanceChange, ReplicaIssuanceOutcome,
    ReplicaIssuanceRequest,
};
use nexus_raft::{
    replica_binding_store::RaftReplicaBindingStore,
    transport::{
        current_local_node_certificate, sign_committed_replica_intent, verify_replica_csr_intent,
        verify_replica_renewal, ReplicaRenewalProof,
    },
};
use x509_parser::prelude::{FromDer, X509Certificate};

/// One caller-retained operation. Keep these exact fields across a lost reply.
/// The unsigned preparation has already been produced by the native CSR
/// serializer. Publication uses its own operation ID and the same credential.
pub struct ReplicaIssue<'a> {
    pub preparation: &'a ReplicaIssuanceRequest,
    pub publication_operation_id: &'a str,
    pub csr_pem: &'a [u8],
    pub renewal: Option<ReplicaRenewalProof<'a>>,
}

/// Borrowed per-request composition of the existing CA holder and control store.
/// Construct from the live issuer configuration; caller DER must come from the
/// authenticated connection, never from an Agent-supplied request field.
pub struct ReplicaIssuer<'a> {
    store: &'a RaftReplicaBindingStore,
    local_ca_der: &'a [u8],
    ca_pem: &'a [u8],
    ca_key_pem: &'a [u8],
    revocations: &'a Path,
}

impl<'a> ReplicaIssuer<'a> {
    pub fn new(
        store: &'a RaftReplicaBindingStore,
        local_ca_der: &'a [u8],
        ca_pem: &'a [u8],
        ca_key_pem: &'a [u8],
        revocations: &'a Path,
    ) -> Result<Self> {
        let ca = pem::parse(ca_pem).map_err(refused)?;
        if ca.contents() != local_ca_der {
            return Err(refused(
                "replica issuer differs from the configured local TLS CA",
            ));
        }
        Ok(Self {
            store,
            local_ca_der,
            ca_pem,
            ca_key_pem,
            revocations,
        })
    }

    /// Commit the exact retained preparation, sign only its current committed
    /// intent, then publish through the original Raft transition. A lost store
    /// result is returned as Unknown; this method performs no mutation retry.
    pub fn issue(&self, caller_der: &[u8], issue: &ReplicaIssue<'_>) -> Result<ReplicaCredential> {
        let (intent, renews) = preparation(issue.preparation)?;
        contracts::validate_operation_id(issue.publication_operation_id).map_err(refused)?;
        if issue.publication_operation_id == issue.preparation.operation_id {
            return Err(refused(
                "preparation and publication require distinct operation IDs",
            ));
        }
        current_local_node_certificate(caller_der, self.local_ca_der).map_err(refused)?;
        verify_replica_csr_intent(intent, issue.csr_pem, self.ca_pem).map_err(refused)?;
        let previous = renews
            .map(|id| self.store.credential(id))
            .transpose()?
            .flatten();
        if renews.is_some() != issue.renewal.is_some() || renews.is_some() && previous.is_none() {
            return Err(refused(
                "replica renewal requires the current predecessor and holder proof",
            ));
        }
        let mut serials = vec![intent.certificate.serial.as_slice()];
        if let Some(previous) = &previous {
            serials.push(previous.intent.certificate.serial.as_slice());
        }
        with_current_controller(
            caller_der,
            self.local_ca_der,
            self.revocations,
            &serials,
            |controller| self.issue_guarded(controller, issue, previous.as_ref()),
        )
    }

    fn issue_guarded(
        &self,
        controller: &CurrentController<'_>,
        issue: &ReplicaIssue<'_>,
        previous: Option<&ReplicaCredential>,
    ) -> Result<ReplicaCredential> {
        let (intent, renews) = preparation(issue.preparation)?;
        if let (Some(id), Some(previous), Some(proof)) = (renews, previous, issue.renewal.as_ref())
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(refused)?
                .as_millis();
            let now = u64::try_from(now).map_err(refused)?;
            verify_replica_renewal(
                issue.preparation,
                id,
                previous,
                controller.der,
                self.ca_pem,
                proof,
                now,
            )
            .map_err(refused)?;
        }
        if let Some(outcome) =
            controller.observe(|| Ok(self.store.reconcile_issuance(issue.preparation)?))?
        {
            require_prepared(outcome, intent, renews)?;
        } else {
            let outcome = controller.commit(|| Ok(self.store.issue(issue.preparation)?))?;
            require_prepared(outcome, intent, renews)?;
        }
        // Once preparation might have committed, an unavailable read/signing
        // result cannot promise that no original operation was stored.
        self.publish_guarded(controller, issue)
            .map_err(after_preparation)
    }

    fn publish_guarded(
        &self,
        controller: &CurrentController<'_>,
        issue: &ReplicaIssue<'_>,
    ) -> Result<ReplicaCredential> {
        let current = controller
            .observe(|| self.current(issue.preparation))?
            .ok_or_else(|| unknown("committed replica preparation is not observable"))?;
        if current.certificate_der.is_some() {
            return Ok(current);
        }
        let signed = controller.observe(|| {
            sign_committed_replica_intent(&current.intent, self.ca_pem, self.ca_key_pem)
                .map_err(refused)
        })?;
        let publication = ReplicaIssuanceRequest {
            operation_id: issue.publication_operation_id.into(),
            change: ReplicaIssuanceChange::Publish {
                credential_id: issue.preparation.operation_id.clone(),
                certificate: signed,
            },
        };
        match controller.commit(|| Ok(self.store.issue(&publication)?))? {
            ReplicaIssuanceOutcome::Published { .. } => {}
            // A competing invocation may have published the same original
            // intent with another randomized signature. Only the stored winner
            // is returned; the local candidate never escapes before publication.
            ReplicaIssuanceOutcome::OperationMismatch
            | ReplicaIssuanceOutcome::Rejected(
                contracts::replica_credential::ReplicaIssuanceRejection::AlreadyPublished,
            ) => {}
            other => return Err(refused(format!("replica publication refused: {other:?}"))),
        }
        let current = controller
            .observe(|| self.current(issue.preparation))?
            .ok_or_else(|| unknown("replica publication is not observable"))?;
        if current.certificate_der.is_none() {
            return Err(unknown("original replica publication remains unresolved"));
        }
        Ok(current)
    }

    /// Read back the exact original intent without preparing, signing or
    /// proposing again. None is unresolved, including when a proposal is still
    /// in flight. Historical success is checked against current authorization.
    pub fn query(
        &self,
        caller_der: &[u8],
        original: &ReplicaIssuanceRequest,
    ) -> Result<Option<ReplicaCredential>> {
        let (intent, _) = preparation(original)?;
        with_current_controller(
            caller_der,
            self.local_ca_der,
            self.revocations,
            &[intent.certificate.serial.as_slice()],
            |controller| controller.observe(|| self.current(original)),
        )
    }

    fn current(&self, original: &ReplicaIssuanceRequest) -> Result<Option<ReplicaCredential>> {
        let (intent, renews) = preparation(original)?;
        let Some(current) = self.store.credential(&original.operation_id)? else {
            return Ok(None);
        };
        if current.intent != *intent || current.renews.as_deref() != renews {
            return Err(refused(
                "replica operation differs from its original preparation",
            ));
        }
        if current.revoked || current.authority_denial.is_some() {
            return Err(refused(
                "replica credential no longer has current allocation/issuer authority",
            ));
        }
        if let Some(der) = &current.certificate_der {
            let (rest, cert) = X509Certificate::from_der(der).map_err(refused)?;
            let (_, ca) = X509Certificate::from_der(self.local_ca_der).map_err(refused)?;
            if !rest.is_empty()
                || !cert.validity().is_valid()
                || cert.tbs_certificate.as_ref() != intent.certificate.tbs_certificate_der
                || cert.raw_serial() != intent.certificate.serial
            {
                return Err(refused(
                    "published replica differs from its current committed intent",
                ));
            }
            cert.verify_signature(Some(ca.public_key()))
                .map_err(refused)?;
        }
        Ok(Some(current))
    }
}

fn preparation(
    request: &ReplicaIssuanceRequest,
) -> Result<(&ReplicaCertificateIntent, Option<&str>)> {
    request.validate().map_err(refused)?;
    match &request.change {
        ReplicaIssuanceChange::Prepare { intent, renews } => Ok((intent, renews.as_deref())),
        _ => Err(refused(
            "replica issuance requires an exact preparation request",
        )),
    }
}

fn require_prepared(
    outcome: ReplicaIssuanceOutcome,
    expected: &ReplicaCertificateIntent,
    expected_renews: Option<&str>,
) -> Result<()> {
    match outcome {
        ReplicaIssuanceOutcome::Prepared { intent, renews }
            if *intent == *expected && renews.as_deref() == expected_renews =>
        {
            Ok(())
        }
        other => Err(refused(format!("replica preparation refused: {other:?}"))),
    }
}

#[cfg(test)]
mod tests;
