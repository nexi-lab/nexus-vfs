//! Durable storage formats and membership admission survive log compaction.

use super::{
    conditional_metadata::{self, storage_error},
    control_key, FullStateMachine, Result, Snapshot, OWNED_CONTROL_NAMESPACES,
};
use crate::raft::{MembershipPolicy, RaftError};
use redb::ReadableTable;

/// Minimum reader dialect. Declaration order is the monotonic format floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum StorageFormat {
    Conditional,
    GuardedRecords,
    RecordIo,
    ReplicaBinding,
    NodeIdentity,
    ReplicaIssuance,
    ReplicaControlActive,
}

impl StorageFormat {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Conditional => b"conditional-only-v1",
            Self::GuardedRecords => b"guarded-records-v1",
            Self::RecordIo => b"guarded-record-io-v1",
            Self::ReplicaBinding => b"replica-binding-v1",
            Self::NodeIdentity => b"node-identity-v1",
            Self::ReplicaIssuance => b"replica-issuance-v1",
            Self::ReplicaControlActive => b"managed-replica-control-v2",
        }
    }

    pub(super) fn decode(bytes: Option<&[u8]>) -> Result<Option<Self>> {
        match bytes {
            None => Ok(None),
            Some(b"conditional-only-v1") => Ok(Some(Self::Conditional)),
            Some(b"guarded-records-v1") => Ok(Some(Self::GuardedRecords)),
            Some(b"guarded-record-io-v1") => Ok(Some(Self::RecordIo)),
            Some(b"replica-binding-v1") => Ok(Some(Self::ReplicaBinding)),
            Some(b"node-identity-v1") => Ok(Some(Self::NodeIdentity)),
            Some(b"replica-issuance-v1") => Ok(Some(Self::ReplicaIssuance)),
            Some(b"managed-replica-control-v2") => Ok(Some(Self::ReplicaControlActive)),
            Some(_) => Err(storage_error("unsupported control storage format")),
        }
    }

    fn validate_policy(self, policy: MembershipPolicy, replica_reader: bool) -> Result<()> {
        if policy == MembershipPolicy::Managed
            && replica_reader
            && self == Self::ReplicaControlActive
        {
            return Ok(());
        }
        if policy != MembershipPolicy::FixedLocal {
            let records = match self {
                Self::ReplicaBinding
                | Self::NodeIdentity
                | Self::ReplicaIssuance
                | Self::ReplicaControlActive => "replica-binding records",
                _ => "protected records",
            };
            return Err(RaftError::Config(format!(
                "{records} require qualified fixed-local storage"
            )));
        }
        Ok(())
    }
}

pub(super) fn requirement_key() -> Vec<u8> {
    // Preserve the existing reader admission key. Earlier readers reject an
    // unknown value here before admitting storage or restoring a snapshot.
    control_key(
        conditional_metadata::NAMESPACE,
        "requires:protected-records-v1",
    )
}

fn validate_requirement(
    bytes: Option<&[u8]>,
    policy: MembershipPolicy,
    replica_reader: bool,
) -> Result<()> {
    if let Some(required) = StorageFormat::decode(bytes)? {
        required.validate_policy(policy, replica_reader)?;
    }
    Ok(())
}

fn validate_owned_namespaces(
    policy: MembershipPolicy,
    replica_active: bool,
    mut contains: impl FnMut(&[u8], Option<&[u8]>) -> Result<bool>,
) -> Result<()> {
    if policy == MembershipPolicy::FixedLocal {
        return Ok(());
    }
    let marker = requirement_key();
    for namespace in OWNED_CONTROL_NAMESPACES {
        if replica_active && *namespace == contracts::constants::CONTROL_NS_REPLICA {
            continue;
        }
        // The reader marker shares a namespace with protected records. Only
        // that exact key is exempt; the format ordinal never grants a domain.
        let except = (replica_active && *namespace == conditional_metadata::NAMESPACE)
            .then_some(marker.as_slice());
        if contains(&control_key(namespace, ""), except)? {
            return Err(RaftError::Config(format!(
                "{namespace} records require qualified fixed-local storage"
            )));
        }
    }
    Ok(())
}

impl FullStateMachine {
    pub(super) fn require_storage_format_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        required: StorageFormat,
    ) -> Result<()> {
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let key = requirement_key();
        let current = table.get(key.as_slice()).map_err(storage_error)?;
        let format = StorageFormat::decode(current.as_ref().map(|value| value.value()))?;
        drop(current);
        if format.is_none_or(|format| format < required) {
            table
                .insert(key.as_slice(), required.bytes())
                .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(super) fn validate_owned_storage_reader(
        &self,
        policy: MembershipPolicy,
        replica_reader: bool,
    ) -> Result<()> {
        let active = self.read_replica_control_activation()?.is_some();
        validate_requirement(
            self.control_state.get(&requirement_key())?.as_deref(),
            policy,
            replica_reader,
        )?;
        validate_owned_namespaces(policy, active && replica_reader, |prefix, except| {
            // At most one excluded marker plus one record per namespace.
            let mut found = false;
            self.control_state.for_each_prefix(prefix, |key, _| {
                if except == Some(key) {
                    return Ok(true);
                }
                found = true;
                Ok(false)
            })?;
            Ok(found)
        })
    }

    pub(super) fn validate_owned_storage_policy(&self, policy: MembershipPolicy) -> Result<()> {
        self.validate_owned_storage_reader(policy, false)
    }

    pub(super) fn validate_owned_snapshot_policy(
        &self,
        snapshot: &Snapshot,
        policy: MembershipPolicy,
    ) -> Result<()> {
        self.validate_owned_snapshot_reader(snapshot, policy, false)
    }

    pub(super) fn validate_owned_snapshot_reader(
        &self,
        snapshot: &Snapshot,
        policy: MembershipPolicy,
        replica_reader: bool,
    ) -> Result<()> {
        let incoming = snapshot_activation(snapshot)?;
        if self
            .read_replica_control_activation()?
            .is_some_and(|current| incoming.as_ref() != Some(&current))
        {
            return Err(RaftError::Config(
                "snapshot changes the committed replica activation".into(),
            ));
        }
        validate_snapshot_reader(snapshot, policy, replica_reader)
    }
}

fn snapshot_activation(snapshot: &Snapshot) -> Result<Option<super::ReplicaControlActivation>> {
    let key = String::from_utf8(requirement_key()).map_err(storage_error)?;
    let activation_key =
        String::from_utf8(super::replica_activation::activation_key()).map_err(storage_error)?;
    super::replica_activation::decode_activation(
        snapshot.control_state.get(&key).map(Vec::as_slice),
        snapshot
            .control_state
            .get(&activation_key)
            .map(Vec::as_slice),
    )
}

/// Full replicas and witnesses validate the same incoming reader requirements.
pub(super) fn validate_snapshot_reader(
    snapshot: &Snapshot,
    policy: MembershipPolicy,
    replica_reader: bool,
) -> Result<()> {
    let active = snapshot_activation(snapshot)?.is_some();
    let key = String::from_utf8(requirement_key()).map_err(storage_error)?;
    validate_requirement(
        snapshot.control_state.get(&key).map(Vec::as_slice),
        policy,
        replica_reader,
    )?;
    validate_owned_namespaces(policy, active && replica_reader, |prefix, except| {
        Ok(snapshot
            .control_state
            .keys()
            .any(|key| key.as_bytes().starts_with(prefix) && except != Some(key.as_bytes())))
    })
}

#[cfg(test)]
mod managed_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        raft::{Command, StateMachine},
        storage::RedbStore,
    };

    #[test]
    fn storage_format_is_monotonic_and_aborted_upgrades_leave_no_requirement() {
        let store = RedbStore::open_temporary().unwrap();
        let state = FullStateMachine::new(&store).unwrap();
        {
            let txn = state.control_state.raw_db().begin_write().unwrap();
            state
                .require_storage_format_in_txn(&txn, StorageFormat::ReplicaBinding)
                .unwrap();
            txn.abort().unwrap();
        }
        assert!(state
            .control_state
            .get(&requirement_key())
            .unwrap()
            .is_none());
        for floor in [
            StorageFormat::Conditional,
            StorageFormat::GuardedRecords,
            StorageFormat::RecordIo,
            StorageFormat::ReplicaBinding,
            StorageFormat::NodeIdentity,
            StorageFormat::ReplicaIssuance,
        ] {
            let txn = state.control_state.raw_db().begin_write().unwrap();
            state.require_storage_format_in_txn(&txn, floor).unwrap();
            txn.commit().unwrap();
            // Exercise the actual writers that could otherwise overwrite a
            // replica requirement with an older protected-record requirement.
            let txn = state.control_state.raw_db().begin_write().unwrap();
            state
                .adopt_protected_in_txn(&txn, "/later", None, [7; 16])
                .unwrap();
            state
                .require_storage_format_in_txn(&txn, StorageFormat::Conditional)
                .unwrap();
            if floor >= StorageFormat::RecordIo {
                state.mark_record_io_owner_in_txn(&txn, "/owner").unwrap();
            }
            txn.commit().unwrap();
            assert_eq!(
                state
                    .control_state
                    .get(&requirement_key())
                    .unwrap()
                    .as_deref(),
                Some(floor.bytes())
            );
        }
    }

    #[test]
    fn unknown_format_refuses_boot_snapshot_and_upgrade_even_when_fixed_local() {
        let store = RedbStore::open_temporary().unwrap();
        let state = FullStateMachine::new(&store).unwrap();
        state
            .control_state
            .set(&requirement_key(), b"future-reader-format")
            .unwrap();
        for policy in [MembershipPolicy::FixedLocal, MembershipPolicy::Managed] {
            assert!(state
                .validate_membership_policy(policy)
                .unwrap_err()
                .to_string()
                .contains("unsupported control storage format"));
            assert!(state
                .validate_snapshot_membership(&state.snapshot().unwrap(), policy)
                .unwrap_err()
                .to_string()
                .contains("unsupported control storage format"));
        }
        let txn = state.control_state.raw_db().begin_write().unwrap();
        assert!(state
            .require_storage_format_in_txn(&txn, StorageFormat::ReplicaBinding)
            .is_err());
        txn.abort().unwrap();
        assert_eq!(
            state
                .control_state
                .get(&requirement_key())
                .unwrap()
                .as_deref(),
            Some(b"future-reader-format".as_slice())
        );
    }

    #[test]
    fn ordinary_control_namespaces_and_similar_names_remain_managed() {
        let directory = tempfile::tempdir().unwrap();
        let store = RedbStore::open(directory.path().join("state")).unwrap();
        let mut state = FullStateMachine::new(&store).unwrap();
        for (index, namespace) in [
            contracts::CONTROL_NS_AUTH.to_owned(),
            format!("{}-other", OWNED_CONTROL_NAMESPACES[0]),
            format!("{}-other", OWNED_CONTROL_NAMESPACES[1]),
        ]
        .into_iter()
        .enumerate()
        {
            state
                .apply(
                    index as u64 + 1,
                    &Command::PutControlState {
                        namespace,
                        key: "ordinary".into(),
                        value: b"preserved".to_vec(),
                        if_absent: false,
                    },
                )
                .unwrap();
        }
        state
            .validate_membership_policy(MembershipPolicy::Managed)
            .unwrap();
        state
            .validate_snapshot_membership(&state.snapshot().unwrap(), MembershipPolicy::Managed)
            .unwrap();
    }
}
