//! The local reader floor is carried by the mandatory log-boundary record.

use super::*;

const NAMESPACE_INDEX: &[u8; 8] = b"NXRIDX03";
const VERSIONED_INDEX: &[u8; 8] = b"NXRIDX01";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReaderFormat {
    #[default]
    Legacy,
    ReplicaControl,
    AtomicNamespace,
}

#[derive(Clone, Copy)]
pub(super) struct LogBoundary {
    pub(super) index: u64,
    format: ReaderFormat,
}

impl LogBoundary {
    pub(super) fn decode(bytes: Option<&[u8]>) -> Result<Self> {
        let Some(bytes) = bytes else {
            return Ok(Self {
                index: 1,
                format: ReaderFormat::Legacy,
            });
        };
        let (index, format) = match bytes.len() {
            8 => (bytes, ReaderFormat::Legacy),
            16 if bytes.starts_with(VERSIONED_INDEX) => (&bytes[8..], ReaderFormat::ReplicaControl),
            16 if cfg!(all(feature = "grpc", has_protos)) && bytes.starts_with(NAMESPACE_INDEX) => {
                (&bytes[8..], ReaderFormat::AtomicNamespace)
            }
            _ => {
                return Err(RaftError::Storage(
                    "unsupported Raft log-boundary format".into(),
                ))
            }
        };
        Ok(Self {
            index: u64::from_be_bytes(index.try_into().expect("validated index width")),
            format,
        })
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = match self.format {
            ReaderFormat::Legacy => Vec::with_capacity(8),
            ReaderFormat::ReplicaControl => VERSIONED_INDEX.to_vec(),
            ReaderFormat::AtomicNamespace => NAMESPACE_INDEX.to_vec(),
        };
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
        self.update_log_boundary(None, ReaderFormat::ReplicaControl)
    }

    /// Inspect the durable local reader requirement without granting activation.
    pub fn replica_control_reader_required(&self) -> Result<bool> {
        Ok(self.reader_format()? >= ReaderFormat::ReplicaControl)
    }

    pub(crate) fn reader_format(&self) -> Result<ReaderFormat> {
        Ok(LogBoundary::decode(self.state.get(KEY_FIRST_INDEX)?.as_deref())?.format)
    }

    /// Commission an empty member of a new namespace-format zone before boot.
    /// Existing histories require a separate cluster-wide format transition.
    #[cfg(all(feature = "grpc", has_protos))]
    pub fn initialize_atomic_namespace(&mut self) -> Result<()> {
        self.update_log_boundary(None, ReaderFormat::AtomicNamespace)
    }

    pub(super) fn set_first_index(&self, index: u64) -> Result<()> {
        self.update_log_boundary(Some(index), ReaderFormat::Legacy)
    }

    pub(super) fn update_log_boundary(
        &self,
        index: Option<u64>,
        minimum: ReaderFormat,
    ) -> Result<()> {
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
            if minimum == ReaderFormat::AtomicNamespace && boundary.format != minimum {
                let entries = txn
                    .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                        self.entries.name(),
                    ))
                    .map_err(to_storage_error)?;
                let has_entries = entries
                    .iter()
                    .map_err(to_storage_error)?
                    .next()
                    .transpose()
                    .map_err(to_storage_error)?
                    .is_some();
                let mut has_history = has_entries || boundary.index != 1;
                for row in table.iter().map_err(to_storage_error)? {
                    let (key, _) = row.map_err(to_storage_error)?;
                    has_history |= key.value() != KEY_FIRST_INDEX;
                }
                if has_history {
                    return Err(RaftError::Config(
                        "atomic namespace requires empty Raft storage".into(),
                    ));
                }
            }
            boundary.index = index.unwrap_or(boundary.index);
            boundary.format = boundary.format.max(minimum);
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
