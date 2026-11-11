//! The local reader floor is carried by the mandatory log-boundary record.

use super::*;

const VERSIONED_INDEX: &[u8; 8] = b"NXRIDX01";

#[derive(Clone, Copy)]
pub(super) struct LogBoundary {
    pub(super) index: u64,
    versioned: bool,
}

impl LogBoundary {
    pub(super) fn decode(bytes: Option<&[u8]>) -> Result<Self> {
        let Some(bytes) = bytes else {
            return Ok(Self {
                index: 1,
                versioned: false,
            });
        };
        let (index, versioned) = match bytes.len() {
            8 => (bytes, false),
            16 if bytes.starts_with(VERSIONED_INDEX) => (&bytes[8..], true),
            _ => {
                return Err(RaftError::Storage(
                    "unsupported Raft log-boundary format".into(),
                ))
            }
        };
        Ok(Self {
            index: u64::from_be_bytes(index.try_into().expect("validated index width")),
            versioned,
        })
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(if self.versioned { 16 } else { 8 });
        if self.versioned {
            bytes.extend_from_slice(VERSIONED_INDEX);
        }
        bytes.extend_from_slice(&self.index.to_be_bytes());
        bytes
    }
}

impl RaftStorage {
    /// Persist the reader format required before this node can qualify for
    /// replica-control activation. This upgrades the local storage format;
    /// the replicated activation and authenticated member checks are separate.
    /// Earlier readers reject the mandatory index record before starting Raft,
    /// including when the node uses a witness state machine.
    pub fn prepare_replica_control_reader(&self) -> Result<()> {
        self.update_log_boundary(None, true)
    }

    /// Inspect the durable local reader requirement without granting activation.
    pub fn replica_control_reader_required(&self) -> Result<bool> {
        Ok(LogBoundary::decode(self.state.get(KEY_FIRST_INDEX)?.as_deref())?.versioned)
    }

    pub(super) fn set_first_index(&self, index: u64) -> Result<()> {
        self.update_log_boundary(Some(index), false)
    }

    pub(super) fn update_log_boundary(&self, index: Option<u64>, upgrade: bool) -> Result<()> {
        let txn = self
            .state
            .raw_db()
            .begin_write()
            .map_err(to_storage_error)?;
        {
            let mut table = txn
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                    self.state.name(),
                ))
                .map_err(to_storage_error)?;
            let current = table.get(KEY_FIRST_INDEX).map_err(to_storage_error)?;
            let mut boundary = LogBoundary::decode(current.as_ref().map(|value| value.value()))?;
            drop(current);
            boundary.index = index.unwrap_or(boundary.index);
            boundary.versioned |= upgrade;
            table
                .insert(KEY_FIRST_INDEX, boundary.encode().as_slice())
                .map_err(to_storage_error)?;
        }
        txn.commit().map_err(to_storage_error)
    }

    pub(super) fn first_index_bytes(&self, current: Option<&[u8]>, index: u64) -> Result<Vec<u8>> {
        let mut boundary = LogBoundary::decode(current)?;
        boundary.index = index;
        Ok(boundary.encode())
    }
}

fn to_storage_error(error: impl std::fmt::Display) -> RaftError {
    RaftError::Storage(format!("Raft reader format: {error}"))
}

#[cfg(test)]
mod tests;
