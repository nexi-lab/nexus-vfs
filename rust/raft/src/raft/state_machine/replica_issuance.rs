//! Issuer admission, exact certificate publication and revocation are ordered
//! with allocation retirement in the same control-zone transaction.

use super::{
    control_key,
    replica_binding::{allocation_key, decode_binding, request_hash, storage_error, Receipt},
    storage_admission::StorageFormat,
    CommandResult, FullStateMachine, Result,
};
use contracts::{
    constants::CONTROL_NS_REPLICA as NAMESPACE,
    replica_credential::{
        ReplicaCertificateIntent, ReplicaCredential, ReplicaIssuanceChange, ReplicaIssuanceOutcome,
        ReplicaIssuanceRejection, ReplicaIssuanceRequest, ReplicaIssuerAuthority,
    },
};
use redb::ReadableTable;
use serde::de::DeserializeOwned;

type Read<'a> = dyn Fn(&[u8]) -> Result<Option<Vec<u8>>> + 'a;
type Writes = Vec<(Vec<u8>, Vec<u8>)>;

fn key(kind: &str, id: &str) -> Vec<u8> {
    control_key(NAMESPACE, &format!("{kind}:{id}"))
}

struct View<'a> {
    read: &'a Read<'a>,
}

impl View<'_> {
    fn decode<T: DeserializeOwned>(&self, key: &[u8]) -> Result<Option<T>> {
        (self.read)(key)?
            .map(|bytes| bincode::deserialize(&bytes).map_err(Into::into))
            .transpose()
    }

    fn authority(&self) -> Result<Option<ReplicaIssuerAuthority>> {
        let current: Option<ReplicaIssuerAuthority> = self.decode(&key("issuer", "current"))?;
        if current.as_ref().is_some_and(|value| value.revision == 0) {
            return Err(storage_error("invalid current replica issuer revision"));
        }
        Ok(current)
    }

    fn receipt(&self, operation: &str) -> Result<Option<Receipt<ReplicaIssuanceOutcome>>> {
        self.decode(&key("issuance-operation", operation))
    }

    fn credential(&self, id: &str) -> Result<Option<ReplicaCredential>> {
        let Some(Receipt {
            outcome: ReplicaIssuanceOutcome::Prepared { intent, renews },
            ..
        }) = self.receipt(id)?
        else {
            return Ok(None);
        };
        intent.validate_shape().map_err(storage_error)?;
        let certificate_der =
            if let Some(operation) = self.decode::<String>(&key("published", id))? {
                match self.receipt(&operation)? {
                    Some(Receipt {
                        outcome:
                            ReplicaIssuanceOutcome::Published {
                                credential_id,
                                certificate_der,
                            },
                        ..
                    }) if credential_id == id => Some(certificate_der),
                    _ => return Err(storage_error("invalid replica publication reference")),
                }
            } else {
                None
            };
        let revoked = if let Some(operation) = self.decode::<String>(&key("revoked", id))? {
            match self.receipt(&operation)? {
                Some(Receipt {
                    outcome: ReplicaIssuanceOutcome::Revoked { credential_id },
                    ..
                }) if credential_id == id => true,
                _ => return Err(storage_error("invalid replica revocation reference")),
            }
        } else {
            false
        };
        let authority_denial = self.admission(&intent)?;
        Ok(Some(ReplicaCredential {
            intent: *intent,
            renews,
            certificate_der,
            revoked,
            authority_denial,
        }))
    }

    fn admission(
        &self,
        intent: &ReplicaCertificateIntent,
    ) -> Result<Option<ReplicaIssuanceRejection>> {
        let authority = self.authority()?;
        if !authority.is_some_and(|value| {
            value.revision == intent.issuer_revision
                && value.issuer_sha256 == Some(intent.certificate.issuer_sha256)
        }) {
            return Ok(Some(ReplicaIssuanceRejection::AuthorityChanged));
        }
        let allocation = &intent.binding.allocation;
        let current = (self.read)(&control_key(NAMESPACE, &allocation_key(allocation)))?
            .map(|bytes| decode_binding(&bytes, allocation))
            .transpose()?;
        if current.as_ref() != Some(&intent.binding) {
            return Ok(Some(ReplicaIssuanceRejection::BindingChanged));
        }
        Ok(None)
    }

    fn transition(
        &self,
        request: &ReplicaIssuanceRequest,
    ) -> Result<(ReplicaIssuanceOutcome, Writes)> {
        use ReplicaIssuanceChange as Change;
        use ReplicaIssuanceOutcome as Outcome;
        use ReplicaIssuanceRejection as Reject;
        let refused = |reason| Ok((Outcome::Rejected(reason), vec![]));
        match &request.change {
            Change::Authority {
                expected_revision,
                issuer_sha256,
            } => {
                let current = self.authority()?;
                if current.as_ref().map(|value| value.revision) != *expected_revision {
                    return refused(Reject::AuthorityChanged);
                }
                let revision = expected_revision
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| storage_error("replica issuer revision exhausted"))?;
                let authority = ReplicaIssuerAuthority {
                    revision,
                    issuer_sha256: *issuer_sha256,
                };
                let write = (key("issuer", "current"), bincode::serialize(&authority)?);
                Ok((Outcome::AuthorityChanged(authority), vec![write]))
            }
            Change::Prepare { intent, renews } => {
                if let Some(reason) = self.admission(intent)? {
                    return refused(reason);
                }
                if let Some(previous) = renews {
                    let Some(previous) = self.credential(previous)? else {
                        return refused(Reject::MissingCredential);
                    };
                    if previous.revoked {
                        return refused(Reject::CredentialRevoked);
                    }
                    if previous.authority_denial.is_some()
                        || previous.certificate_der.is_none()
                        || previous.intent.binding != intent.binding
                        || previous.intent.subject_name != intent.subject_name
                        || previous.intent.issuer_revision != intent.issuer_revision
                        || previous.intent.certificate.issuer_sha256
                            != intent.certificate.issuer_sha256
                    {
                        return refused(Reject::RenewalMismatch);
                    }
                }
                Ok((
                    Outcome::Prepared {
                        intent: intent.clone(),
                        renews: renews.clone(),
                    },
                    vec![],
                ))
            }
            Change::Publish {
                credential_id,
                certificate,
            } => {
                let Some(credential) = self.credential(credential_id)? else {
                    return refused(Reject::MissingCredential);
                };
                if let Some(reason) = credential.authority_denial {
                    return refused(reason);
                }
                if credential.revoked {
                    return refused(Reject::CredentialRevoked);
                }
                if credential.certificate_der.is_some() {
                    return refused(Reject::AlreadyPublished);
                }
                if let Some(previous) = &credential.renews {
                    // A renewal prepared before the predecessor is revoked
                    // must still fail if publication follows that revocation.
                    if !self.credential(previous)?.is_some_and(|value| {
                        !value.revoked
                            && value.authority_denial.is_none()
                            && value.certificate_der.is_some()
                    }) {
                        return refused(Reject::CredentialRevoked);
                    }
                }
                let expected = &credential.intent.certificate;
                if certificate.tbs_certificate_der != expected.tbs_certificate_der
                    || certificate.serial != expected.serial
                {
                    return refused(Reject::CertificateMismatch);
                }
                let write = (
                    key("published", credential_id),
                    bincode::serialize(&request.operation_id)?,
                );
                Ok((
                    Outcome::Published {
                        credential_id: credential_id.clone(),
                        certificate_der: certificate.certificate_der.clone(),
                    },
                    vec![write],
                ))
            }
            Change::Revoke { credential_id } => {
                let Some(credential) = self.credential(credential_id)? else {
                    return refused(Reject::MissingCredential);
                };
                let writes = if credential.revoked {
                    vec![]
                } else {
                    vec![(
                        key("revoked", credential_id),
                        bincode::serialize(&request.operation_id)?,
                    )]
                };
                Ok((
                    Outcome::Revoked {
                        credential_id: credential_id.clone(),
                    },
                    writes,
                ))
            }
        }
    }
}

impl FullStateMachine {
    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn replica_issuer_authority(&self) -> Result<Option<ReplicaIssuerAuthority>> {
        View {
            read: &|key| self.control_state.get(key).map_err(Into::into),
        }
        .authority()
    }

    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn replica_credential(&self, id: &str) -> Result<Option<ReplicaCredential>> {
        View {
            read: &|key| self.control_state.get(key).map_err(Into::into),
        }
        .credential(id)
    }

    #[cfg(any(test, all(feature = "grpc", has_protos)))]
    pub(crate) fn replica_issuance_receipt(
        &self,
        request: &ReplicaIssuanceRequest,
    ) -> Result<Option<ReplicaIssuanceOutcome>> {
        let view = View {
            read: &|key| self.control_state.get(key).map_err(Into::into),
        };
        Ok(view.receipt(&request.operation_id)?.map(|receipt| {
            if receipt.request_hash == request_hash(request) {
                receipt.outcome
            } else {
                ReplicaIssuanceOutcome::OperationMismatch
            }
        }))
    }

    pub(super) fn apply_replica_issuance(
        &self,
        txn: &redb::WriteTransaction,
        request: &ReplicaIssuanceRequest,
    ) -> Result<CommandResult> {
        if let Err(error) = request.validate() {
            return Ok(CommandResult::Error(error));
        }
        self.require_storage_format_in_txn(txn, StorageFormat::ReplicaIssuance)?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let view = View {
            read: &|key| {
                table
                    .get(key)
                    .map(|value| value.map(|bytes| bytes.value().to_vec()))
                    .map_err(storage_error)
            },
        };
        let digest = request_hash(request);
        if let Some(receipt) = view.receipt(&request.operation_id)? {
            let outcome = if receipt.request_hash == digest {
                receipt.outcome
            } else {
                ReplicaIssuanceOutcome::OperationMismatch
            };
            return Ok(CommandResult::Value(bincode::serialize(&outcome)?));
        }
        let (outcome, writes) = view.transition(request)?;
        for (key, value) in writes {
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(storage_error)?;
        }
        let receipt = bincode::serialize(&Receipt {
            request_hash: digest,
            outcome: outcome.clone(),
        })?;
        table
            .insert(
                key("issuance-operation", &request.operation_id).as_slice(),
                receipt.as_slice(),
            )
            .map_err(storage_error)?;
        Ok(CommandResult::Value(bincode::serialize(&outcome)?))
    }
}

#[cfg(test)]
mod tests;
