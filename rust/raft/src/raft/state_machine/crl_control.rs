//! CRL authority, ordering, revocations and original receipts share Raft apply.

use super::{
    control_key, storage_admission::StorageFormat, CommandResult, FullStateMachine, Result,
};
#[cfg(all(feature = "grpc", has_protos))]
use contracts::crl_control::{CrlControlChange, CrlIssuerSelection};
use contracts::crl_control::{CrlControlOutcome, CrlControlRequest, LocalCrlIssuer};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

pub(super) const NAMESPACE: &str = "signed-crl-v1";

#[derive(Serialize, Deserialize)]
struct Receipt {
    request_hash: [u8; 32],
    outcome: CrlControlOutcome,
}

fn key(kind: &str, id: &str) -> Vec<u8> {
    control_key(NAMESPACE, &format!("{kind}:{id}"))
}

fn storage_error(error: impl std::fmt::Display) -> crate::raft::RaftError {
    crate::raft::RaftError::Storage(format!("signed CRL control: {error}"))
}

impl FullStateMachine {
    /// Read the durable local issuer, including explicit withdrawal. Trusted
    /// consumers combine this with their other admission records in one
    /// `ZoneConsensus::read_linearizable` closure; this local accessor alone
    /// neither supplies a consensus read barrier nor authorizes a TLS actor.
    pub fn local_crl_issuer(&self) -> Result<Option<LocalCrlIssuer>> {
        let issuer: Option<LocalCrlIssuer> = self
            .control_state
            .get(&key("issuer", "local"))?
            .map(|bytes| bincode::deserialize(&bytes))
            .transpose()?;
        if issuer.as_ref().is_some_and(|issuer| issuer.revision == 0) {
            return Err(storage_error("invalid stored local issuer revision"));
        }
        Ok(issuer)
    }

    /// Recover the exact original outcome after an uncertain submission.
    /// A historical success does not imply that the issuer is still current;
    /// absence does not prove that an outstanding request cannot still apply.
    pub fn crl_control_receipt(
        &self,
        request: &CrlControlRequest,
    ) -> Result<Option<CrlControlOutcome>> {
        request.validate().map_err(storage_error)?;
        let request_hash = *blake3::hash(&bincode::serialize(request)?).as_bytes();
        self.control_state
            .get(&key("operation", &request.operation_id))?
            .map(|bytes| {
                let receipt: Receipt = bincode::deserialize(&bytes)?;
                Ok(original_outcome(receipt, request_hash))
            })
            .transpose()
    }

    /// Once typed CRL storage is admitted, delayed generic commands cannot
    /// replace its existing snapshot or erase any irreversible revoke marker.
    pub(super) fn crl_owns_control_key_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        namespace: &str,
        record: &str,
    ) -> Result<bool> {
        if !crate::crl_records::is_crl_record(namespace, record) {
            return Ok(false);
        }
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let required = table
            .get(super::storage_admission::requirement_key().as_slice())
            .map_err(storage_error)?;
        Ok(
            StorageFormat::decode(required.as_ref().map(|value| value.value()))?
                .is_some_and(|format| format >= StorageFormat::SignedCrl),
        )
    }

    pub(super) fn apply_crl_control(
        &self,
        txn: &redb::WriteTransaction,
        request: &CrlControlRequest,
    ) -> Result<CommandResult> {
        if let Err(error) = request.validate() {
            return Ok(CommandResult::Error(error));
        }
        // Earlier readers reject this existing durable floor key even after
        // compaction. Replica-control activation does not activate this domain.
        self.require_storage_format_in_txn(txn, StorageFormat::SignedCrl)?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let request_hash = *blake3::hash(&bincode::serialize(request)?).as_bytes();
        let receipt_key = key("operation", &request.operation_id);
        let previous = table
            .get(receipt_key.as_slice())
            .map_err(storage_error)?
            .map(|value| bincode::deserialize::<Receipt>(value.value()))
            .transpose()?;
        if let Some(previous) = previous {
            let outcome = original_outcome(previous, request_hash);
            return Ok(CommandResult::Value(bincode::serialize(&outcome)?));
        }
        let read = |key: &[u8]| {
            table
                .get(key)
                .map(|value| value.map(|v| v.value().to_vec()))
                .map_err(storage_error)
        };
        let (outcome, writes) = transition(&read, request)?;
        for (key, value) in writes {
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(storage_error)?;
        }
        let receipt = bincode::serialize(&Receipt {
            request_hash,
            outcome: outcome.clone(),
        })?;
        table
            .insert(receipt_key.as_slice(), receipt.as_slice())
            .map_err(storage_error)?;
        Ok(CommandResult::Value(bincode::serialize(&outcome)?))
    }
}

fn original_outcome(receipt: Receipt, request_hash: [u8; 32]) -> CrlControlOutcome {
    if receipt.request_hash == request_hash {
        receipt.outcome
    } else {
        CrlControlOutcome::OperationMismatch
    }
}

type Writes = Vec<(Vec<u8>, Vec<u8>)>;
type ReadControl<'a> = dyn Fn(&[u8]) -> Result<Option<Vec<u8>>> + 'a;

// Without the native signature verifier this command cannot publish anything.
#[cfg(not(all(feature = "grpc", has_protos)))]
fn transition(_: &ReadControl<'_>, _: &CrlControlRequest) -> Result<(CrlControlOutcome, Writes)> {
    Ok((
        CrlControlOutcome::Refused("signed CRL verifier is unavailable".into()),
        vec![],
    ))
}

#[cfg(all(feature = "grpc", has_protos))]
fn transition(
    read: &ReadControl<'_>,
    request: &CrlControlRequest,
) -> Result<(CrlControlOutcome, Writes)> {
    use lib::transport_primitives::{
        ca_spki_sha256, canonical_certificate_serial, verify_signed_crl, ForeignCaAnchor,
        ForeignCaScope,
    };
    let refused = |message: &str| Ok((CrlControlOutcome::Refused(message.into()), vec![]));
    let local: Option<LocalCrlIssuer> = read(&key("issuer", "local"))?
        .map(|bytes| bincode::deserialize(&bytes))
        .transpose()?;
    if local.as_ref().is_some_and(|issuer| issuer.revision == 0) {
        return Err(storage_error("invalid stored local issuer revision"));
    }
    match &request.change {
        CrlControlChange::LocalIssuer {
            expected_revision,
            ca_pem,
        } => {
            if local.as_ref().map(|issuer| issuer.revision) != *expected_revision {
                return refused("local issuer revision changed");
            }
            if let Some(ca) = ca_pem {
                if let Err(error) = ca_spki_sha256(ca) {
                    return refused(&error);
                }
            }
            let revision = expected_revision
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| storage_error("local issuer revision exhausted"))?;
            let issuer = LocalCrlIssuer {
                revision,
                ca_pem: ca_pem.clone(),
            };
            let writes = vec![(key("issuer", "local"), bincode::serialize(&issuer)?)];
            Ok((CrlControlOutcome::LocalIssuerChanged(issuer), writes))
        }
        CrlControlChange::Install {
            issuer,
            crl_pem,
            observed_unix_s,
            maximum_age_secs,
        } => {
            let ca_pem = match issuer {
                CrlIssuerSelection::Local { revision } => {
                    let Some(current) = local.filter(|current| current.revision == *revision)
                    else {
                        return refused("local issuer revision changed");
                    };
                    let Some(ca) = current.ca_pem else {
                        return refused("local issuer is withdrawn");
                    };
                    ca
                }
                CrlIssuerSelection::Foreign { registration } => {
                    let anchor = match ForeignCaAnchor::decode(registration) {
                        Ok(anchor) => anchor,
                        Err(error) => return refused(&error.to_string()),
                    };
                    if anchor.scope != ForeignCaScope::CollaborationOnlyV1 {
                        return refused("foreign issuer purpose is not collaboration");
                    }
                    if read(&control_key(
                        contracts::CONTROL_NS_FOREIGN_CA,
                        &anchor.fingerprint_hex(),
                    ))?
                    .as_ref()
                        != Some(registration)
                    {
                        return refused("foreign issuer registration changed");
                    }
                    let ca =
                        pem::encode(&pem::Pem::new("CERTIFICATE", anchor.ca_cert_der.as_slice()))
                            .into_bytes();
                    if local
                        .as_ref()
                        .and_then(|current| current.ca_pem.as_ref())
                        .map(|local_ca| ca_spki_sha256(local_ca))
                        .transpose()
                        .map_err(storage_error)?
                        == Some(ca_spki_sha256(&ca).map_err(storage_error)?)
                    {
                        return refused("local authority cannot be foreign");
                    }
                    ca
                }
            };
            let verified = match verify_signed_crl(crl_pem, &ca_pem) {
                Ok(verified) => verified,
                Err(error) => return refused(&error),
            };
            if let Err(error) = verified.check_freshness(*observed_unix_s, *maximum_age_secs) {
                return refused(&error);
            }
            // Keep the deployed collaboration namespace and record encoding.
            // Earlier irreversible markers remain authoritative without copying
            // them into a second writable store or enumerating a whole domain.
            let snapshot_key = control_key(
                contracts::constants::CONTROL_NS_COLLABORATION,
                &crate::crl_records::snapshot_key(verified.authority()),
            );
            if let Some(previous) = read(&snapshot_key)? {
                let previous = verify_signed_crl(&previous, &ca_pem).map_err(storage_error)?;
                if let Err(error) = verified.check_successor(&previous) {
                    return refused(&error);
                }
            }
            let mut writes = vec![(snapshot_key, crl_pem.clone())];
            for serial in verified.revoked_serials() {
                let serial = canonical_certificate_serial(serial).map_err(storage_error)?;
                let revoked_key = control_key(
                    contracts::constants::CONTROL_NS_COLLABORATION,
                    &crate::crl_records::revoked_key(verified.authority(), serial),
                );
                match read(&revoked_key)? {
                    Some(value) if value != crate::crl_records::REVOKED => {
                        return Err(storage_error("invalid revocation marker"))
                    }
                    Some(_) => {}
                    None => writes.push((revoked_key, crate::crl_records::REVOKED.to_vec())),
                }
            }
            Ok((
                CrlControlOutcome::Installed {
                    authority: *verified.authority(),
                    signed_der_sha256: *verified.signed_der_sha256(),
                    number: verified.number().to_vec(),
                },
                writes,
            ))
        }
    }
}

#[cfg(all(test, feature = "grpc", has_protos))]
mod tests;
