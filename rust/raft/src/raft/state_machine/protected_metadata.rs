//! Conditional-only records retain their existing zone-relative metadata key.

use super::conditional_metadata::storage_error;
use super::storage_admission::StorageFormat;
use super::*;

const POLICY_PREFIX: &str = "protected:";
const CONDITIONAL_ONLY: &[u8] = b"conditional-only-v1";
const RECORD_OWNER: &[u8] = b"record-owner-v1";
const RECORD_IO_OWNER: &[u8] = b"record-owner-io-v1";
fn policy_key(path: &str) -> Vec<u8> {
    control_key(
        conditional_metadata::NAMESPACE,
        &format!("{POLICY_PREFIX}{path}"),
    )
}

fn decode_policy(value: Option<Vec<u8>>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value)
            if value == CONDITIONAL_ONLY || value == RECORD_OWNER || value == RECORD_IO_OWNER =>
        {
            Ok(true)
        }
        Some(_) => Err(super::super::RaftError::Storage(
            "invalid protected metadata policy".into(),
        )),
    }
}

impl FullStateMachine {
    pub(super) fn ordinary_metadata_refusal(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<Option<CommandResult>> {
        Ok(self.protected_in_txn(txn, path)?.then(|| {
            CommandResult::Error("protected metadata requires a conditional write".into())
        }))
    }

    /// Export reads the policy set once, rather than opening a transaction per
    /// metadata key in a potentially large anti-entropy image.
    pub(super) fn protected_metadata_paths(&self) -> Result<std::collections::HashSet<String>> {
        let prefix = policy_key("");
        self.control_state
            .scan_prefix(&prefix)
            .map(|item| {
                let (key, value) = item?;
                decode_policy(Some(value))?;
                String::from_utf8(key[prefix.len()..].to_vec()).map_err(storage_error)
            })
            .collect()
    }

    /// The policy is a durable fact in this zone's existing control store.
    pub fn is_protected_metadata(&self, path: &str) -> Result<bool> {
        decode_policy(self.control_state.get(&policy_key(path))?)
    }

    pub(super) fn protected_in_read(
        &self,
        txn: &redb::ReadTransaction,
        path: &str,
    ) -> Result<bool> {
        decode_policy(self.record_policy_in_read(txn, path)?)
    }

    fn record_policy_in_read(
        &self,
        txn: &redb::ReadTransaction,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(policy_key(path).as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        Ok(value)
    }

    #[cfg(all(feature = "grpc", has_protos))]
    pub(super) fn is_record_io_owner_in_read(
        &self,
        txn: &redb::ReadTransaction,
        path: &str,
    ) -> Result<bool> {
        Ok(self.record_policy_in_read(txn, path)?.as_deref() == Some(RECORD_IO_OWNER))
    }

    pub(super) fn protected_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<bool> {
        decode_policy(self.record_policy_in_txn(txn, path)?)
    }

    fn record_policy_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(policy_key(path).as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        Ok(value)
    }

    pub(super) fn is_record_owner_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<bool> {
        Ok(matches!(
            self.record_policy_in_txn(txn, path)?.as_deref(),
            Some(RECORD_OWNER | RECORD_IO_OWNER)
        ))
    }

    /// The existing policy is the role authority; no reverse binding index is
    /// needed to keep an owner from later becoming another owner's child.
    pub(super) fn mark_record_owner_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<()> {
        let policy = if self.record_policy_in_txn(txn, path)?.as_deref() == Some(RECORD_IO_OWNER) {
            RECORD_IO_OWNER
        } else {
            RECORD_OWNER
        };
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        table
            .insert(policy_key(path).as_slice(), policy)
            .map_err(storage_error)?;
        Ok(())
    }

    pub(super) fn mark_record_io_owner_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<()> {
        self.require_storage_format_in_txn(txn, StorageFormat::RecordIo)?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        table
            .insert(policy_key(path).as_slice(), RECORD_IO_OWNER)
            .map_err(storage_error)?;
        Ok(())
    }

    pub(super) fn adopt_protected_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
        expected_image: Option<&[u8]>,
        incarnation: [u8; 16],
    ) -> Result<CommandResult> {
        let value = self.metadata_in_txn(txn, key)?;
        if self.protected_in_txn(txn, key)? {
            return Ok(CommandResult::ProtectedMetadata { protected: true });
        }
        if value.as_deref() != expected_image {
            return Ok(CommandResult::ProtectedMetadata { protected: false });
        }
        if value.is_some() {
            self.allocate_revision(txn, key, Some(incarnation))?;
        }
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        table
            .insert(policy_key(key).as_slice(), CONDITIONAL_ONLY)
            .map_err(storage_error)?;
        drop(table);
        self.require_storage_format_in_txn(txn, StorageFormat::Conditional)?;
        Ok(CommandResult::ProtectedMetadata { protected: true })
    }

    pub(super) fn ordinary_write_is_protected(&self, command: &Command) -> Result<bool> {
        command
            .ordinary_metadata_key()
            .map_or(Ok(false), |path| self.is_protected_metadata(path))
    }
}
