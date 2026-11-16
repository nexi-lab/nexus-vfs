//! The committed protocol fact also identifies its original activation request.

use super::{
    control_key,
    storage_admission::{requirement_key, StorageFormat},
    CommandResult, FullStateMachine, Result,
};
use crate::raft::RaftError;
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

const NAMESPACE: &str = contracts::constants::CONTROL_NS_REPLICA;

/// A durable protocol activation, shared by the current fact and retry readback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaControlActivation {
    pub operation_id: String,
}

pub(crate) fn validate_operation(operation: &str) -> Result<()> {
    if operation.is_empty() || operation.len() > 256 || operation.chars().any(char::is_control) {
        return Err(storage_error("invalid activation operation ID"));
    }
    Ok(())
}

fn storage_error(error: impl std::fmt::Display) -> RaftError {
    RaftError::Storage(format!("replica protocol activation: {error}"))
}

pub(super) fn activation_key() -> Vec<u8> {
    control_key(NAMESPACE, "protocol:replica-control-v2")
}

pub(super) fn decode_activation(
    floor: Option<&[u8]>,
    record: Option<&[u8]>,
) -> Result<Option<ReplicaControlActivation>> {
    let floor = StorageFormat::decode(floor)?;
    match record {
        Some(record) => {
            if floor.is_none_or(|value| value < StorageFormat::ReplicaControlActive) {
                return Err(storage_error(
                    "activation is missing its reader requirement",
                ));
            }
            let fact: ReplicaControlActivation = bincode::deserialize(record)?;
            validate_operation(&fact.operation_id)?;
            Ok(Some(fact))
        }
        None if floor == Some(StorageFormat::ReplicaControlActive) => Err(storage_error(
            "reader requirement is missing its activation",
        )),
        None => Ok(None),
    }
}

impl FullStateMachine {
    pub(super) fn read_replica_control_activation(
        &self,
    ) -> Result<Option<ReplicaControlActivation>> {
        let txn = self
            .control_state
            .raw_db()
            .begin_read()
            .map_err(storage_error)?;
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let floor = table
            .get(requirement_key().as_slice())
            .map_err(storage_error)?;
        let fact = table
            .get(activation_key().as_slice())
            .map_err(storage_error)?;
        decode_activation(
            floor.as_ref().map(|v| v.value()),
            fact.as_ref().map(|v| v.value()),
        )
    }

    pub(super) fn activate_replica_control_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        operation_id: &str,
    ) -> Result<CommandResult> {
        if let Err(error) = validate_operation(operation_id) {
            return Ok(CommandResult::Error(error.to_string()));
        }
        let existing = {
            let table = txn
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                    self.control_state.name(),
                ))
                .map_err(storage_error)?;
            let floor = table
                .get(requirement_key().as_slice())
                .map_err(storage_error)?;
            let fact = table
                .get(activation_key().as_slice())
                .map_err(storage_error)?;
            decode_activation(
                floor.as_ref().map(|v| v.value()),
                fact.as_ref().map(|v| v.value()),
            )?
        };
        if let Some(original) = existing {
            // Every retry reads the original committed operation. A second
            // operation cannot replace it or infer success for its own ID.
            return Ok(CommandResult::Value(bincode::serialize(&original)?));
        }
        let fact = ReplicaControlActivation {
            operation_id: operation_id.to_owned(),
        };
        let bytes = bincode::serialize(&fact)?;
        self.require_storage_format_in_txn(txn, StorageFormat::ReplicaControlActive)?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        table
            .insert(activation_key().as_slice(), bytes.as_slice())
            .map_err(storage_error)?;
        Ok(CommandResult::Value(bytes))
    }
}

#[cfg(test)]
mod tests;
