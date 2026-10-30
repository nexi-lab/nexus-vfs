//! Conditional-only records retain their existing zone-relative metadata key.

use super::conditional_metadata::storage_error;
use super::*;

const POLICY_PREFIX: &str = "protected:";
const CONDITIONAL_ONLY: &[u8] = b"conditional-only-v1";
const REQUIREMENT: &str = "requires:protected-records-v1";

fn requirement_key() -> Vec<u8> {
    control_key(conditional_metadata::NAMESPACE, REQUIREMENT)
}

fn validate_policy(required: bool, policy: super::super::MembershipPolicy) -> Result<()> {
    if required && policy != super::super::MembershipPolicy::FixedLocal {
        return Err(super::super::RaftError::Config(
            "protected records require qualified fixed-local storage".into(),
        ));
    }
    Ok(())
}

fn policy_key(path: &str) -> Vec<u8> {
    control_key(
        conditional_metadata::NAMESPACE,
        &format!("{POLICY_PREFIX}{path}"),
    )
}

fn decode_policy(value: Option<Vec<u8>>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == CONDITIONAL_ONLY => Ok(true),
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

    pub(super) fn validate_protected_storage_policy(
        &self,
        policy: super::super::MembershipPolicy,
    ) -> Result<()> {
        validate_policy(
            decode_policy(self.control_state.get(&requirement_key())?)?,
            policy,
        )
    }

    pub(super) fn validate_protected_snapshot_policy(
        snapshot: &Snapshot,
        policy: super::super::MembershipPolicy,
    ) -> Result<()> {
        let key = String::from_utf8(requirement_key()).map_err(storage_error)?;
        validate_policy(
            decode_policy(snapshot.control_state.get(&key).cloned())?,
            policy,
        )
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
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(policy_key(path).as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        decode_policy(value)
    }

    pub(super) fn protected_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        path: &str,
    ) -> Result<bool> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(policy_key(path).as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        decode_policy(value)
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
        table
            .insert(requirement_key().as_slice(), CONDITIONAL_ONLY)
            .map_err(storage_error)?;
        Ok(CommandResult::ProtectedMetadata { protected: true })
    }

    pub(super) fn ordinary_write_is_protected(&self, command: &Command) -> Result<bool> {
        command
            .ordinary_metadata_key()
            .map_or(Ok(false), |path| self.is_protected_metadata(path))
    }
}
