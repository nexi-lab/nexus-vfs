//! Transport of original replica lifecycle commands and read-only observations.

use std::future::Future;

use nexus_raft::{
    replica_binding_store::ReplicaBindingError,
    transport::{
        proto::{
            replica_control_request::Operation, ReplicaControlRequest, ReplicaControlResponse,
            ReplicaControlState,
        },
        revoked_serials_path,
    },
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    replica_control::{ReplicaControlError, ReplicaController},
    replica_rpc::ReplyAuthority,
    FounderCaIssuer,
};

fn mutation(request: &ReplicaControlRequest) -> bool {
    matches!(
        request.operation,
        Some(Operation::ApplyBindingJson(_) | Operation::ApplyIssuerJson(_))
    )
}

fn failure(state: ReplicaControlState, reason: impl ToString) -> ReplicaControlResponse {
    ReplicaControlResponse {
        state: state as i32,
        error: Some(reason.to_string()),
        result_json: Vec::new(),
    }
}

pub(super) async fn release(
    authority: ReplyAuthority,
    mutation: bool,
    pending: impl Future<Output = ReplicaControlResponse>,
) -> ReplicaControlResponse {
    authority.complete(pending).await.unwrap_or_else(|error| {
        failure(
            if mutation {
                ReplicaControlState::Unknown
            } else {
                ReplicaControlState::Refused
            },
            error,
        )
    })
}

pub(super) async fn respond(
    founder: FounderCaIssuer,
    caller: Option<Vec<u8>>,
    request: ReplicaControlRequest,
) -> ReplicaControlResponse {
    let authority = match ReplyAuthority::capture(&founder, caller.as_deref()) {
        Ok(authority) => authority,
        Err(error) => return failure(ReplicaControlState::Refused, error),
    };
    release(authority, mutation(&request), async move {
        match tokio::task::spawn_blocking(move || execute(&founder, caller, request)).await {
            Ok(response) => response,
            Err(_) => failure(
                ReplicaControlState::Unknown,
                "original replica lifecycle worker did not return",
            ),
        }
    })
    .await
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ReplicaControlError> {
    if bytes.is_empty() || bytes.len() > 128 * 1024 {
        return Err(ReplicaControlError::Refused(
            "replica lifecycle request exceeds its bounds".into(),
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| ReplicaControlError::Refused(error.to_string()))
}

fn observed<T: Serialize>(
    result: Option<T>,
) -> Result<ReplicaControlResponse, ReplicaControlError> {
    let (state, result_json) = match result {
        Some(value) => (
            ReplicaControlState::Result,
            serde_json::to_vec(&value).map_err(|error| {
                ReplicaControlError::Store(ReplicaBindingError::Unknown(error.to_string()))
            })?,
        ),
        None => (ReplicaControlState::NotObserved, Vec::new()),
    };
    Ok(ReplicaControlResponse {
        state: state as i32,
        error: None,
        result_json,
    })
}

pub(super) fn execute(
    founder: &FounderCaIssuer,
    caller: Option<Vec<u8>>,
    request: ReplicaControlRequest,
) -> ReplicaControlResponse {
    match execute_inner(founder, caller, request) {
        Ok(response) => response,
        Err(ReplicaControlError::Store(
            error @ (ReplicaBindingError::Unavailable(_) | ReplicaBindingError::Unknown(_)),
        )) => failure(ReplicaControlState::Unknown, error),
        Err(error) => failure(ReplicaControlState::Refused, error),
    }
}

fn execute_inner(
    founder: &FounderCaIssuer,
    caller: Option<Vec<u8>>,
    request: ReplicaControlRequest,
) -> Result<ReplicaControlResponse, ReplicaControlError> {
    let refuse = ReplicaControlError::Refused;
    let caller = caller.ok_or_else(|| refuse("replica controller requires an mTLS Node".into()))?;
    let store = founder
        .replica_store
        .get()
        .ok_or_else(|| refuse("replica control store is not bound".into()))?;
    let verifier = founder
        .peer_verifier
        .get()
        .ok_or_else(|| refuse("current local TLS authority is unavailable".into()))?;
    let revocations = revoked_serials_path(&founder.data_dir);
    let controller = ReplicaController::new(store, verifier.cluster_ca_der(), &revocations);
    match request
        .operation
        .ok_or_else(|| refuse("replica lifecycle operation is missing".into()))?
    {
        Operation::ApplyBindingJson(bytes) => {
            observed(Some(controller.apply_binding(&caller, &parse(&bytes)?)?))
        }
        Operation::CurrentBindingJson(bytes) => {
            observed(controller.current_binding(&caller, &parse(&bytes)?)?)
        }
        Operation::ReconcileBindingJson(bytes) => {
            observed(controller.reconcile_binding(&caller, &parse(&bytes)?)?)
        }
        Operation::ApplyIssuerJson(bytes) => observed(Some(
            controller.apply_issuer_control(&caller, &parse(&bytes)?)?,
        )),
        Operation::CurrentIssuer(_) => observed(controller.current_issuer(&caller)?),
        Operation::ReconcileIssuerJson(bytes) => {
            observed(controller.reconcile_issuer_control(&caller, &parse(&bytes)?)?)
        }
    }
}
