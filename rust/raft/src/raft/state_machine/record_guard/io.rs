//! Read admission in one snapshot; only explicit enrollment mutates consensus.

use super::*;

impl FullStateMachine {
    pub(crate) fn admit_record_io_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        owner: &str,
        expected: &[u8],
    ) -> Result<CommandResult> {
        if let Err(error) = kernel::kernel::validate_path_fast(owner) {
            return Ok(CommandResult::Error(error.to_string()));
        }
        if self
            .record_control_in_txn(txn, BINDING_PREFIX, owner)?
            .is_some()
            || !self.live_record_guard_in_txn(txn, owner, expected)?
        {
            return Ok(CommandResult::Error(
                "record owner handle is not live".into(),
            ));
        }
        self.mark_record_io_owner_in_txn(txn, owner)?;
        Ok(CommandResult::Success)
    }

    #[cfg(all(feature = "grpc", has_protos))]
    fn record_io_control_in_read(
        &self,
        txn: &redb::ReadTransaction,
        prefix: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(control_key(NAMESPACE, &format!("{prefix}{key}")).as_slice())
            .map_err(storage_error)?
            .map(|value| value.value().to_vec());
        Ok(value)
    }

    /// The native path is local storage identity, never replicated authority.
    /// The caller releases the state-machine lock before touching that path.
    #[cfg(all(feature = "grpc", has_protos))]
    pub(crate) fn live_record_io_domain(
        &self,
        record: &str,
        expected: &[u8],
    ) -> Result<(std::path::PathBuf, String)> {
        let txn = self.metadata.raw_db().begin_read().map_err(storage_error)?;
        let owner = match self.record_io_control_in_read(&txn, BINDING_PREFIX, record)? {
            Some(binding) => String::from_utf8(binding).map_err(storage_error)?,
            // The owning service retains this same lifetime while qualifying
            // a new child, before that child can have a permanent binding.
            // Only explicit I/O enrollment admits this owner spelling.
            None if self.is_record_io_owner_in_read(&txn, record)? => record.to_owned(),
            None => {
                return Err(super::super::super::RaftError::UnsupportedOperation(
                    "record has no owner binding",
                ));
            }
        };
        if !self.is_record_io_owner_in_read(&txn, &owner)? {
            return Err(super::super::super::RaftError::UnsupportedOperation(
                "record owner I/O is not enrolled",
            ));
        }
        let image = self.versioned_metadata_in_read(&txn, &owner)?;
        if image.version.as_deref() != Some(expected)
            || self
                .record_io_control_in_read(&txn, RETIRED_PREFIX, &owner)?
                .is_some()
        {
            return Err(super::super::super::RaftError::InvalidState(
                "record owner handle is not live".into(),
            ));
        }
        Ok((self.record_io_directory.clone(), owner))
    }

    #[cfg(all(feature = "grpc", has_protos))]
    pub(crate) fn retired_record_io_domain(
        &self,
        owner: &str,
        terminal_version: &[u8],
    ) -> Result<(std::path::PathBuf, String)> {
        let txn = self.metadata.raw_db().begin_read().map_err(storage_error)?;
        if !self.is_record_io_owner_in_read(&txn, owner)? {
            return Err(super::super::super::RaftError::UnsupportedOperation(
                "record owner I/O is not enrolled",
            ));
        }
        let image = self.versioned_metadata_in_read(&txn, owner)?;
        if image.version.as_deref() != Some(terminal_version)
            || self
                .record_io_control_in_read(&txn, RETIRED_PREFIX, owner)?
                .as_deref()
                != Some(terminal_version)
        {
            return Err(super::super::super::RaftError::InvalidState(
                "record owner is not retired at the expected revision".into(),
            ));
        }
        Ok((self.record_io_directory.clone(), owner.to_owned()))
    }
}
