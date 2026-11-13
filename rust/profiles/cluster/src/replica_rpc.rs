//! Authenticated transport adapter for the original native replica coordinator.

use std::{
    future::Future,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use contracts::replica_credential::{ReplicaIssuanceChange, ReplicaIssuanceRequest};
use nexus_raft::{
    replica_binding_store::{RaftReplicaBindingStore, ReplicaBindingError},
    transport::{
        current_local_node_certificate,
        proto::{ReplicaCsrRequest, ReplicaCsrResponse, ReplicaCsrState},
        revoked_serials_path, with_unrevoked_serial, ReplicaRenewalProof,
    },
};

use crate::replica_issuer::{ReplicaIssue, ReplicaIssuer, ReplicaIssuerError};
use crate::FounderCaIssuer;

#[cfg(test)]
mod tests;

pub(super) type StoreSlot = Arc<OnceLock<Arc<RaftReplicaBindingStore>>>;

pub(super) fn new_store_slot() -> StoreSlot {
    Arc::new(OnceLock::new())
}

/// The connection identity remains owned through the async worker result.
pub(super) struct ReplyAuthority {
    caller: Vec<u8>,
    ca: Vec<u8>,
    serial: Vec<u8>,
    revocations: PathBuf,
}

impl ReplyAuthority {
    pub(super) fn capture(
        founder: &FounderCaIssuer,
        caller: Option<&[u8]>,
    ) -> Result<Self, String> {
        let caller = caller.ok_or("replica issuer requires an mTLS Node")?;
        let verifier = founder
            .peer_verifier
            .get()
            .ok_or("current local TLS authority is unavailable")?;
        let ca = verifier.cluster_ca_der();
        let identity = current_local_node_certificate(caller, ca)?;
        Ok(Self {
            caller: caller.to_vec(),
            ca: ca.to_vec(),
            serial: identity.serial,
            revocations: revoked_serials_path(&founder.data_dir),
        })
    }

    pub(super) async fn complete<T>(self, pending: impl Future<Output = T>) -> Result<T, String> {
        let response = pending.await;
        // No suspension separates this post-lock current identity check from
        // returning the result to the transport adapter.
        with_unrevoked_serial(&self.revocations, &self.serial, || {
            current_local_node_certificate(&self.caller, &self.ca)?;
            Ok(response)
        })
    }

    async fn release(
        self,
        query_only: bool,
        pending: impl Future<Output = ReplicaCsrResponse>,
    ) -> ReplicaCsrResponse {
        self.complete(pending).await.unwrap_or_else(|error| {
            failure(
                if query_only {
                    ReplicaCsrState::Refused
                } else {
                    ReplicaCsrState::Unknown
                },
                error,
            )
        })
    }
}

pub(super) async fn respond(
    founder: FounderCaIssuer,
    caller: Option<Vec<u8>>,
    request: ReplicaCsrRequest,
    query_only: bool,
) -> ReplicaCsrResponse {
    let authority = match ReplyAuthority::capture(&founder, caller.as_deref()) {
        Ok(authority) => authority,
        Err(error) => return failure(ReplicaCsrState::Refused, error),
    };
    authority
        .release(query_only, async move {
            match tokio::task::spawn_blocking(move || {
                execute(&founder, caller, request, query_only)
            })
            .await
            {
                Ok(response) => response,
                Err(_) => failure(
                    ReplicaCsrState::Unknown,
                    "original replica issuer worker did not return",
                ),
            }
        })
        .await
}

pub(super) fn failure(state: ReplicaCsrState, reason: impl ToString) -> ReplicaCsrResponse {
    ReplicaCsrResponse {
        state: state as i32,
        error: Some(reason.to_string()),
        ..Default::default()
    }
}

fn parse(request: &ReplicaCsrRequest) -> Result<ReplicaIssuanceRequest, String> {
    // The existing intent includes bounded DER encoded as JSON byte arrays.
    if request.preparation_json.is_empty()
        || request.preparation_json.len() > 128 * 1024
        || request.csr_pem.len() > 16 * 1024
        || request.publication_operation_id.len() > 256
        || request
            .renewal
            .as_ref()
            .is_some_and(|proof| proof.signature.len() > 1024)
    {
        return Err("replica request exceeds its public intent/proof bounds".into());
    }
    let preparation: ReplicaIssuanceRequest =
        serde_json::from_slice(&request.preparation_json).map_err(|error| error.to_string())?;
    preparation.validate()?;
    if !matches!(preparation.change, ReplicaIssuanceChange::Prepare { .. }) {
        return Err("replica CSR requires the original Prepare request".into());
    }
    Ok(preparation)
}

pub(super) fn execute(
    founder: &FounderCaIssuer,
    caller: Option<Vec<u8>>,
    request: ReplicaCsrRequest,
    query_only: bool,
) -> ReplicaCsrResponse {
    let result = execute_inner(founder, caller, &request, query_only);
    match result {
        Ok(response) => response,
        Err(ReplicaIssuerError::Store(
            error @ (ReplicaBindingError::Unknown(_) | ReplicaBindingError::Unavailable(_)),
        )) => failure(ReplicaCsrState::Unknown, error),
        Err(error) => failure(ReplicaCsrState::Refused, error),
    }
}

fn execute_inner(
    founder: &FounderCaIssuer,
    caller: Option<Vec<u8>>,
    request: &ReplicaCsrRequest,
    query_only: bool,
) -> Result<ReplicaCsrResponse, ReplicaIssuerError> {
    let refuse = ReplicaIssuerError::Refused;
    let caller = caller.ok_or_else(|| refuse("replica issuer requires an mTLS Node".into()))?;
    let preparation = parse(request).map_err(refuse)?;
    let store = founder
        .replica_store
        .get()
        .ok_or_else(|| refuse("replica control store is not bound".into()))?;
    let verifier = founder
        .peer_verifier
        .get()
        .ok_or_else(|| refuse("current local TLS authority is unavailable".into()))?;
    let ca_pem = std::fs::read(founder.tls_dir.join("ca.pem"))
        .map_err(|error| refuse(format!("read issuer CA: {error}")))?;
    let ca_key_pem = if query_only {
        Vec::new()
    } else {
        std::fs::read(founder.tls_dir.join("ca-key.pem"))
            .map_err(|error| refuse(format!("read issuer key: {error}")))?
    };
    let revocations = revoked_serials_path(&founder.data_dir);
    let issuer = ReplicaIssuer::new(
        store,
        verifier.cluster_ca_der(),
        &ca_pem,
        &ca_key_pem,
        &revocations,
    )?;
    let current = if query_only {
        issuer.query(&caller, &preparation)?
    } else {
        Some(issuer.issue(
            &caller,
            &ReplicaIssue {
                preparation: &preparation,
                publication_operation_id: &request.publication_operation_id,
                csr_pem: &request.csr_pem,
                renewal: request.renewal.as_ref().map(|proof| ReplicaRenewalProof {
                    issued_at_unix_ms: proof.issued_at_unix_ms,
                    signature: &proof.signature,
                }),
            },
        )?)
    };
    let (state, certificate_der) = match current {
        None => (ReplicaCsrState::NotObserved, Vec::new()),
        Some(current) => match current.certificate_der {
            Some(certificate) => (ReplicaCsrState::Published, certificate),
            None => (ReplicaCsrState::Prepared, Vec::new()),
        },
    };
    Ok(ReplicaCsrResponse {
        state: state as i32,
        error: None,
        operation_id: preparation.operation_id,
        preparation_json: request.preparation_json.clone(),
        certificate_der,
        ca_pem,
    })
}
