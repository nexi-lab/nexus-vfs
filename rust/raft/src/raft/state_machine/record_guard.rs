//! A record's owner comparison and mutation share the Raft apply transaction.
//!
//! Owner revisions are storage handles, not process IDs or expiring leases.
//! Retirement survives reconnect, replay and snapshots. This module performs
//! no content I/O; physical reclamation must drain that I/O separately.

use super::conditional_metadata::{storage_error, NAMESPACE};
use super::*;

mod io;

const BINDING_PREFIX: &str = "guard:";
const RETIRED_PREFIX: &str = "retired-guard:";

/// Mutations supported by the storage owner fence. Apply shares the original
/// command arms, borrowing payloads without an extra record or blob copy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GuardedRecordMutation {
    ReplaceMetadata {
        key: String,
        value: Vec<u8>,
        expected: Option<Vec<u8>>,
        incarnation: [u8; 16],
    },
    Append {
        stream_prefix: String,
        data: Vec<u8>,
    },
    Seal {
        stream_prefix: String,
        base: u64,
        end: u64,
        content_id: String,
        origin: String,
        size: u64,
    },
    Trim {
        stream_prefix: String,
        up_to_seq: u64,
        trimmed: Vec<(String, String)>,
    },
}

impl GuardedRecordMutation {
    fn key(&self) -> Option<&str> {
        match self {
            Self::ReplaceMetadata { key, .. } => Some(key),
            Self::Append { stream_prefix, .. }
            | Self::Seal { stream_prefix, .. }
            | Self::Trim { stream_prefix, .. }
                if stream_prefix.ends_with('/') =>
            {
                kernel::core::stream::wal::watch_path_from_wal_stream_key(stream_prefix)
            }
            _ => None,
        }
    }
}

impl Command {
    fn record_stream_prefix(&self) -> Option<&str> {
        match self {
            Self::AppendStreamEntry { stream_prefix, .. }
            | Self::SealStreamSegment { stream_prefix, .. }
            | Self::TrimStreamSegment { stream_prefix, .. } => Some(stream_prefix),
            _ => None,
        }
    }

    /// Locate ordinary record mutations that require a bound owner handle.
    fn guarded_record_key(&self) -> Option<&str> {
        match self {
            Self::WriteVersionedMetadata { key, .. } => Some(key),
            _ => self
                .record_stream_prefix()
                .filter(|prefix| prefix.ends_with('/'))
                .and_then(|stream_prefix| {
                    kernel::core::stream::wal::watch_path_from_wal_stream_key(stream_prefix)
                }),
        }
    }
}

impl FullStateMachine {
    fn record_control_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        prefix: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(control_key(NAMESPACE, &format!("{prefix}{path}")).as_slice())
            .map_err(storage_error)?
            .map(|value| value.value().to_vec());
        Ok(value)
    }

    fn put_record_control_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        prefix: &str,
        path: &str,
        value: &[u8],
    ) -> Result<()> {
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        table
            .insert(
                control_key(NAMESPACE, &format!("{prefix}{path}")).as_slice(),
                value,
            )
            .map_err(storage_error)?;
        Ok(())
    }

    fn live_record_guard_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        guard_key: &str,
        expected: &[u8],
    ) -> Result<bool> {
        Ok(self.protected_in_txn(txn, guard_key)?
            && self
                .record_control_in_txn(txn, RETIRED_PREFIX, guard_key)?
                .is_none()
            && self.metadata_in_txn(txn, guard_key)?.is_some()
            && self.revision_in_txn(txn, guard_key)?.as_deref() == Some(expected))
    }

    pub(super) fn record_guard_refusal(
        &self,
        txn: &redb::WriteTransaction,
        command: &Command,
    ) -> Result<Option<CommandResult>> {
        if let Command::GuardedRecord {
            guard_version,
            mutation,
        } = command
        {
            return self.guarded_record_refusal(txn, guard_version, mutation);
        }
        // A missing delimiter can alias a parent's real entry: prefix
        // "<parent-prefix>1" plus seq 0 overwrites the parent's seq 10. Such a
        // malformed WAL identity must not escape the owner lookup below.
        if command.record_stream_prefix().is_some_and(|prefix| {
            prefix.starts_with(kernel::core::stream::wal::WAL_STREAM_KEY_PREFIX)
                && !prefix.ends_with('/')
        }) {
            return Ok(Some(CommandResult::Error(
                "invalid WAL stream prefix".into(),
            )));
        }
        // Ordinary metadata already checks the permanent conditional-only
        // policy. Only conditional replacements and WAL mutations need the
        // additional owner checks here.
        let key = command.guarded_record_key();
        let Some(key) = key else { return Ok(None) };
        if self
            .record_control_in_txn(txn, RETIRED_PREFIX, key)?
            .is_some()
        {
            return Ok(Some(CommandResult::Error(
                "record owner is permanently retired".into(),
            )));
        }
        if self
            .record_control_in_txn(txn, BINDING_PREFIX, key)?
            .is_some()
        {
            return Ok(Some(CommandResult::Error(
                "record mutation requires its owner handle".into(),
            )));
        }
        Ok(None)
    }

    pub(super) fn bind_record_guard_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
        expected_image: Option<&[u8]>,
        guard_key: &str,
        guard_version: &[u8],
        incarnation: [u8; 16],
    ) -> Result<CommandResult> {
        for path in [key, guard_key] {
            if let Err(error) = kernel::kernel::validate_path_fast(path) {
                return Ok(CommandResult::Error(error.to_string()));
            }
        }
        if key == guard_key
            || self
                .record_control_in_txn(txn, BINDING_PREFIX, guard_key)?
                .is_some()
            || !self.live_record_guard_in_txn(txn, guard_key, guard_version)?
        {
            return Ok(CommandResult::Error(
                "record owner handle is not live".into(),
            ));
        }
        if self.is_record_owner_in_txn(txn, key)?
            || self
                .record_control_in_txn(txn, RETIRED_PREFIX, key)?
                .is_some()
        {
            return Ok(CommandResult::Error(
                "record owner cannot become a guarded record".into(),
            ));
        }
        if let Some(binding) = self.record_control_in_txn(txn, BINDING_PREFIX, key)? {
            return Ok(if binding == guard_key.as_bytes() {
                CommandResult::Success
            } else {
                CommandResult::Error("record already belongs to a different owner".into())
            });
        }
        // Qualify outside apply; compare the same image before publishing either
        // policy. A racing ordinary mutation cannot be silently adopted.
        if self.metadata_in_txn(txn, key)?.as_deref() != expected_image {
            return Ok(CommandResult::Error(
                "record changed before owner admission".into(),
            ));
        }
        self.adopt_protected_in_txn(txn, key, expected_image, incarnation)?;
        self.mark_record_owner_in_txn(txn, guard_key)?;
        self.require_storage_format_in_txn(
            txn,
            super::storage_admission::StorageFormat::GuardedRecords,
        )?;
        self.put_record_control_in_txn(txn, BINDING_PREFIX, key, guard_key.as_bytes())?;
        Ok(CommandResult::Success)
    }

    fn guarded_record_refusal(
        &self,
        txn: &redb::WriteTransaction,
        guard_version: &[u8],
        mutation: &GuardedRecordMutation,
    ) -> Result<Option<CommandResult>> {
        let Some(key) = mutation.key() else {
            return Ok(Some(CommandResult::Error(
                "unsupported guarded record mutation".into(),
            )));
        };
        let Some(binding) = self.record_control_in_txn(txn, BINDING_PREFIX, key)? else {
            return Ok(Some(CommandResult::Error(
                "record has no admitted owner".into(),
            )));
        };
        let guard_key = std::str::from_utf8(&binding).map_err(storage_error)?;
        if !self.live_record_guard_in_txn(txn, guard_key, guard_version)? {
            return Ok(Some(CommandResult::Error(
                "record owner handle is not live".into(),
            )));
        }
        Ok(None)
    }

    pub(super) fn retire_record_guard_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
        expected: &[u8],
        terminal_image: &[u8],
        incarnation: [u8; 16],
    ) -> Result<CommandResult> {
        if self
            .record_control_in_txn(txn, BINDING_PREFIX, key)?
            .is_some()
            || !self.live_record_guard_in_txn(txn, key, expected)?
        {
            return Ok(CommandResult::Error(
                "record owner handle is not live".into(),
            ));
        }
        let result =
            self.write_versioned_in_txn(txn, key, terminal_image, Some(expected), incarnation)?;
        self.mark_record_owner_in_txn(txn, key)?;
        self.require_storage_format_in_txn(
            txn,
            super::storage_admission::StorageFormat::GuardedRecords,
        )?;
        match &result {
            CommandResult::ConditionalMetadata {
                committed: true,
                current,
            } => {
                let version = current
                    .version
                    .as_deref()
                    .ok_or_else(|| storage_error("retired owner has no revision"))?;
                self.put_record_control_in_txn(txn, RETIRED_PREFIX, key, version)?;
            }
            _ => return Err(storage_error("qualified retirement did not commit")),
        }
        Ok(result)
    }
}
