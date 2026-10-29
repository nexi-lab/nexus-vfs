//! Revisions live beside metadata in the SAME existing zone database.
//!
//! This implements only the atomic metadata half of conditional content writes.
//! It is deliberately not advertised as a file-write capability: a path backend
//! that overwrites live bytes before proposing metadata is still unsupported.

use super::*;
pub(super) use contracts::is_managed_content_path as is_managed_key;

pub(super) const NAMESPACE: &str = "content-version-v1";
const ALLOCATOR: &str = "allocator";
const PATH_PREFIX: &str = "path:";
const TOKEN_LEN: usize = 24;

impl Command {
    /// Fixed on every replica, including one that has not applied a first SC
    /// create. EC must never publish either managed metadata or its allocator.
    pub(crate) fn requires_conditional_sc(&self) -> bool {
        match self {
            Self::SetMetadata { key, .. }
            | Self::DeleteMetadata { key }
            | Self::CasSetMetadata { key, .. }
            | Self::AdjustCounter { key, .. } => is_managed_key(key),
            Self::PutControlState { namespace, .. }
            | Self::DeleteControlState { namespace, .. } => namespace == NAMESPACE,
            Self::WriteVersionedMetadata { .. } => true,
            _ => false,
        }
    }
}

/// Both fields describe the same committed metadata image. Missing metadata
/// has no public revision, even though its internal tombstone is retained.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedMetadata {
    pub value: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
}

fn revision_key(path: &str) -> Vec<u8> {
    control_key(NAMESPACE, &format!("{PATH_PREFIX}{path}"))
}

fn storage_error(error: impl std::fmt::Display) -> super::super::RaftError {
    super::super::RaftError::Storage(format!("conditional metadata: {error}"))
}

impl FullStateMachine {
    /// Read metadata and revision in one redb snapshot. A present untracked
    /// legacy key is refused. Reading must NEVER enrol a replica-local image.
    /// Migration creates a verified image in a new managed namespace instead.
    pub fn get_versioned_metadata(&self, key: &str) -> Result<VersionedMetadata> {
        Self::require_managed_key(key)?;
        let txn = self.metadata.raw_db().begin_read().map_err(storage_error)?;
        let metadata = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(storage_error)?;
        let versions = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = metadata
            .get(key.as_bytes())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        let version = versions
            .get(revision_key(key).as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        Self::versioned_image(value, version)
    }

    fn versioned_image(
        value: Option<Vec<u8>>,
        version: Option<Vec<u8>>,
    ) -> Result<VersionedMetadata> {
        if value.is_none() {
            return Ok(VersionedMetadata::default());
        }
        if version.is_none() {
            return Err(super::super::RaftError::UnsupportedOperation(
                "metadata key has no committed content revision",
            ));
        }
        if version.as_ref().is_some_and(|v| v.len() != TOKEN_LEN) {
            return Err(storage_error("invalid committed content revision"));
        }
        Ok(VersionedMetadata { value, version })
    }

    fn require_managed_key(key: &str) -> Result<()> {
        if is_managed_key(key) {
            Ok(())
        } else {
            Err(super::super::RaftError::UnsupportedOperation(
                "conditional content outside the managed metadata subtree",
            ))
        }
    }

    fn metadata_in_txn(&self, txn: &redb::WriteTransaction, key: &str) -> Result<Option<Vec<u8>>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(key.as_bytes())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        Ok(value)
    }

    fn revision_in_txn(&self, txn: &redb::WriteTransaction, key: &str) -> Result<Option<Vec<u8>>> {
        let table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let value = table
            .get(revision_key(key).as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        Ok(value)
    }

    /// Allocate at apply, in the transaction that publishes the pointer. No
    /// wall clock, per-node counter, local creation marker or path hash enters
    /// the token. Every replica consumes the same committed incarnation.
    fn allocate_revision(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
        initial: Option<[u8; 16]>,
    ) -> Result<Vec<u8>> {
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.control_state.name(),
            ))
            .map_err(storage_error)?;
        let allocator_key = control_key(NAMESPACE, ALLOCATOR);
        let previous = table
            .get(allocator_key.as_slice())
            .map_err(storage_error)?
            .map(|v| v.value().to_vec());
        let mut token = match previous {
            Some(token) if token.len() == TOKEN_LEN => token,
            Some(_) => return Err(storage_error("invalid revision allocator")),
            None => {
                let incarnation = initial.ok_or_else(|| storage_error("missing allocator"))?;
                let mut token = incarnation.to_vec();
                token.extend_from_slice(&0_u64.to_be_bytes());
                token
            }
        };
        let counter = u64::from_be_bytes(token[16..].try_into().expect("validated token length"));
        let next = counter
            .checked_add(1)
            .ok_or_else(|| storage_error("content revision space exhausted"))?;
        token[16..].copy_from_slice(&next.to_be_bytes());
        table
            .insert(allocator_key.as_slice(), token.as_slice())
            .map_err(storage_error)?;
        table
            .insert(revision_key(key).as_slice(), token.as_slice())
            .map_err(storage_error)?;
        Ok(token)
    }

    /// Ordinary SC writes, including byte-identical replacements and deletes,
    /// invalidate a previously observed token. They do not opt unrelated keys
    /// into conditional semantics. This is called inside their apply txn.
    pub(super) fn refresh_tracked_version(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
    ) -> Result<()> {
        if !is_managed_key(key) {
            return Ok(());
        }
        if self.revision_in_txn(txn, key)?.is_some() {
            self.allocate_revision(txn, key, None)?;
        }
        Ok(())
    }

    pub(super) fn write_versioned_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        key: &str,
        value: &[u8],
        expected: Option<&[u8]>,
        incarnation: [u8; 16],
    ) -> Result<CommandResult> {
        if !is_managed_key(key) {
            return Ok(CommandResult::ConditionalMetadataUnsupported);
        }
        let current = self.metadata_in_txn(txn, key)?;
        let version = self.revision_in_txn(txn, key)?;
        // The first image MUST travel in the SC create command. An occupied
        // unversioned legacy key is not eligible for automatic admission.
        if current.is_some() && version.is_none() {
            return Ok(CommandResult::ConditionalMetadataUnsupported);
        }
        let current = Self::versioned_image(current, version)?;
        if current.version.as_deref() != expected {
            return Ok(CommandResult::ConditionalMetadata {
                committed: false,
                current,
            });
        }
        let version = self.allocate_revision(txn, key, Some(incarnation))?;
        let mut table = txn
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                self.metadata.name(),
            ))
            .map_err(storage_error)?;
        table.insert(key.as_bytes(), value).map_err(storage_error)?;
        Ok(CommandResult::ConditionalMetadata {
            committed: true,
            current: VersionedMetadata {
                value: Some(value.to_vec()),
                version: Some(version),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_corrupt_committed_revision_is_a_storage_failure() {
        assert!(matches!(
            FullStateMachine::versioned_image(
                Some(b"pointer".to_vec()),
                Some(vec![1; TOKEN_LEN - 1])
            ),
            Err(super::super::super::RaftError::Storage(_))
        ));
        assert!(matches!(
            FullStateMachine::versioned_image(Some(b"legacy".to_vec()), None),
            Err(super::super::super::RaftError::UnsupportedOperation(_))
        ));
    }

    fn machine(dir: &std::path::Path) -> (RedbStore, FullStateMachine) {
        let store = RedbStore::open(dir.join("state.redb")).unwrap();
        let sm = FullStateMachine::new(&store).unwrap();
        (store, sm)
    }

    fn write(key: &str, value: &[u8], expected: Option<Vec<u8>>) -> Command {
        Command::WriteVersionedMetadata {
            key: key.into(),
            value: value.into(),
            expected,
            incarnation: [7; 16],
        }
    }

    fn committed(result: CommandResult) -> VersionedMetadata {
        match result {
            CommandResult::ConditionalMetadata {
                committed: true,
                current,
            } => current,
            other => panic!("expected committed image, got {other:?}"),
        }
    }

    #[test]
    fn conflict_changes_neither_pointer_nor_revision() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        let a = committed(
            sm.apply(
                1,
                &write("/__managed_content_v1__/cursor", b"object-a", None),
            )
            .unwrap(),
        );
        let b = committed(
            sm.apply(
                2,
                &write(
                    "/__managed_content_v1__/cursor",
                    b"object-b",
                    a.version.clone(),
                ),
            )
            .unwrap(),
        );
        assert_ne!(a.version, b.version);
        let allocator = sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap();
        let result = sm
            .apply(
                3,
                &write("/__managed_content_v1__/cursor", b"stale-object", a.version),
            )
            .unwrap();
        assert!(
            matches!(result, CommandResult::ConditionalMetadata { committed: false, current } if current == b)
        );
        assert_eq!(
            sm.get_versioned_metadata("/__managed_content_v1__/cursor")
                .unwrap(),
            b
        );
        assert_eq!(
            sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap(),
            allocator
        );
    }

    #[test]
    fn ordinary_writes_and_delete_recreate_cannot_reuse_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        let first = committed(
            sm.apply(1, &write("/__managed_content_v1__/cursor", b"same", None))
                .unwrap(),
        );
        sm.apply(
            2,
            &Command::SetMetadata {
                key: "/__managed_content_v1__/cursor".into(),
                value: b"same".to_vec(),
            },
        )
        .unwrap();
        let replaced = sm
            .get_versioned_metadata("/__managed_content_v1__/cursor")
            .unwrap();
        assert_ne!(
            first.version, replaced.version,
            "even identical ordinary writes invalidate the token"
        );
        sm.apply(
            3,
            &Command::DeleteMetadata {
                key: "/__managed_content_v1__/cursor".into(),
            },
        )
        .unwrap();
        assert_eq!(
            sm.get_versioned_metadata("/__managed_content_v1__/cursor")
                .unwrap(),
            VersionedMetadata::default()
        );
        let recreated = committed(
            sm.apply(4, &write("/__managed_content_v1__/cursor", b"same", None))
                .unwrap(),
        );
        assert_ne!(first.version, recreated.version);
        assert_ne!(replaced.version, recreated.version);
        assert!(matches!(
            sm.apply(
                5,
                &write("/__managed_content_v1__/cursor", b"stale", first.version)
            )
            .unwrap(),
            CommandResult::ConditionalMetadata {
                committed: false,
                ..
            }
        ));
        assert_eq!(
            sm.get_versioned_metadata("/__managed_content_v1__/cursor")
                .unwrap(),
            recreated
        );
    }

    #[test]
    fn legacy_images_are_never_enrolled_by_reads() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        sm.apply(
            1,
            &Command::SetMetadata {
                key: "/__managed_content_v1__/legacy".into(),
                value: b"legacy-proto".to_vec(),
            },
        )
        .unwrap();
        assert!(sm
            .get_versioned_metadata("/__managed_content_v1__/legacy")
            .is_err());
        assert!(matches!(
            sm.apply(
                2,
                &write("/__managed_content_v1__/legacy", b"force-create", None)
            )
            .unwrap(),
            CommandResult::ConditionalMetadataUnsupported
        ));
        assert!(sm
            .get_versioned_metadata("/__managed_content_v1__/legacy")
            .is_err());
        assert_eq!(sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap(), None);
        assert_eq!(
            sm.get_metadata("/__managed_content_v1__/legacy").unwrap(),
            Some(b"legacy-proto".to_vec())
        );
    }

    #[test]
    fn snapshots_and_restarts_retain_incarnation_and_allocator() {
        let dir = tempfile::tempdir().unwrap();
        let first = {
            let (_store, mut sm) = machine(dir.path());
            let first = committed(
                sm.apply(1, &write("/__managed_content_v1__/one", b"one", None))
                    .unwrap(),
            );
            sm.apply(
                2,
                &Command::DeleteMetadata {
                    key: "/__managed_content_v1__/one".into(),
                },
            )
            .unwrap();
            let snapshot = sm.snapshot().unwrap();
            let replica_dir = tempfile::tempdir().unwrap();
            let (_replica_store, mut replica) = machine(replica_dir.path());
            replica.restore_snapshot(&snapshot).unwrap();
            let next = committed(
                replica
                    .apply(3, &write("/__managed_content_v1__/one", b"one", None))
                    .unwrap(),
            );
            assert_ne!(first.version, next.version);
            assert_eq!(
                &first.version.as_ref().unwrap()[..16],
                &next.version.as_ref().unwrap()[..16]
            );
            first
        };
        let (_store, mut restarted) = machine(dir.path());
        let next = committed(
            restarted
                .apply(3, &write("/__managed_content_v1__/one", b"one", None))
                .unwrap(),
        );
        assert_ne!(first.version, next.version);
        assert_eq!(&first.version.unwrap()[..16], &next.version.unwrap()[..16]);
    }

    #[test]
    fn ec_cannot_overwrite_or_resurrect_a_versioned_path() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        let first = committed(
            sm.apply(1, &write("/__managed_content_v1__/cursor", b"new", None))
                .unwrap(),
        );
        let same = Command::SetMetadata {
            key: "/__managed_content_v1__/cursor".into(),
            value: b"new".to_vec(),
        };
        assert!(sm.apply_local(&same).is_err());
        assert_eq!(
            sm.get_versioned_metadata("/__managed_content_v1__/cursor")
                .unwrap(),
            first
        );
        let stale = Command::SetMetadata {
            key: "/__managed_content_v1__/cursor".into(),
            value: b"old".to_vec(),
        };
        assert!(sm.apply_local(&stale).is_err());
        let delete = Command::DeleteMetadata {
            key: "/__managed_content_v1__/cursor".into(),
        };
        assert!(sm.apply_local(&delete).is_err());
        #[cfg(feature = "grpc")]
        assert!(matches!(
            sm.apply_ec_with_lww(&stale, u64::MAX).unwrap(),
            CommandResult::Success
        ));
        sm.apply(2, &delete).unwrap();
        assert!(sm.apply_local(&stale).is_err());
        let unrelated = Command::SetMetadata {
            key: "/unrelated".into(),
            value: b"ec".to_vec(),
        };
        assert!(matches!(
            sm.apply_local(&unrelated).unwrap(),
            CommandResult::Success
        ));
        assert_eq!(sm.get_metadata("/unrelated").unwrap(), Some(b"ec".to_vec()));
    }

    #[test]
    fn replicated_incarnation_and_replay_are_deterministic() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let (_a_store, mut a) = machine(a_dir.path());
        let (_b_store, mut b) = machine(b_dir.path());
        let first = write("/__managed_content_v1__/a", b"a", None);
        a.apply(1, &first).unwrap();
        b.apply(1, &first).unwrap();
        let second = Command::WriteVersionedMetadata {
            key: "/__managed_content_v1__/b".into(),
            value: b"b".to_vec(),
            expected: None,
            incarnation: [8; 16],
        };
        a.apply(2, &second).unwrap();
        b.apply(2, &second).unwrap();
        assert_eq!(
            a.get_versioned_metadata("/__managed_content_v1__/b")
                .unwrap(),
            b.get_versioned_metadata("/__managed_content_v1__/b")
                .unwrap()
        );
        assert_eq!(
            &a.get_versioned_metadata("/__managed_content_v1__/b")
                .unwrap()
                .version
                .unwrap()[..16],
            &[7; 16]
        );
        let before = a
            .get_versioned_metadata("/__managed_content_v1__/a")
            .unwrap();
        a.apply(1, &first).unwrap();
        assert_eq!(
            a.get_versioned_metadata("/__managed_content_v1__/a")
                .unwrap(),
            before
        );
        assert_eq!(
            a.get_control_state(NAMESPACE, ALLOCATOR).unwrap(),
            b.get_control_state(NAMESPACE, ALLOCATOR).unwrap()
        );
    }

    // Divergent legacy images remain unversioned on every replica.
    #[test]
    fn enrolment_cannot_certify_divergent_legacy_images_with_one_token() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let (_a_store, mut a) = machine(a_dir.path());
        let (_b_store, mut b) = machine(b_dir.path());
        let base = Command::SetMetadata {
            key: "/__managed_content_v1__/legacy".into(),
            value: b"sc-base".to_vec(),
        };
        a.apply(1, &base).unwrap();
        b.apply(1, &base).unwrap();
        // Simulate a pre-upgrade EC image already present on one replica.
        b.metadata
            .set(b"/__managed_content_v1__/legacy", b"ec-diverged")
            .unwrap();
        assert!(a
            .get_versioned_metadata("/__managed_content_v1__/legacy")
            .is_err());
        assert!(b
            .get_versioned_metadata("/__managed_content_v1__/legacy")
            .is_err());
        assert_eq!(a.get_control_state(NAMESPACE, ALLOCATOR).unwrap(), None);
        assert_eq!(b.get_control_state(NAMESPACE, ALLOCATOR).unwrap(), None);
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn a_lagging_replica_skips_future_ec_images_before_first_sc_create() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let (_a_store, mut a) = machine(a_dir.path());
        let (_b_store, mut b) = machine(b_dir.path());
        let create = write("/__managed_content_v1__/cursor", b"first", None);
        let first = committed(a.apply(1, &create).unwrap());
        committed(
            a.apply(
                2,
                &write(
                    "/__managed_content_v1__/cursor",
                    b"second",
                    first.version.clone(),
                ),
            )
            .unwrap(),
        );
        let future = Command::SetMetadata {
            key: "/__managed_content_v1__/cursor".into(),
            value: b"second".to_vec(),
        };
        assert!(matches!(
            b.apply_ec_with_lww(&future, u64::MAX).unwrap(),
            CommandResult::Success
        ));
        assert_eq!(
            b.get_versioned_metadata("/__managed_content_v1__/cursor")
                .unwrap(),
            VersionedMetadata::default()
        );
        assert_eq!(b.get_control_state(NAMESPACE, ALLOCATOR).unwrap(), None);
        assert_eq!(committed(b.apply(1, &create).unwrap()), first);
        assert!(!a
            .ec_state_snapshot()
            .iter()
            .any(Command::requires_conditional_sc));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn ec_cannot_change_the_conditional_control_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        let tamper = Command::PutControlState {
            namespace: NAMESPACE.into(),
            key: ALLOCATOR.into(),
            value: vec![0; TOKEN_LEN],
            if_absent: false,
        };
        assert!(sm.apply_local(&tamper).is_err());
        assert!(matches!(
            sm.apply_ec_with_lww(&tamper, u64::MAX).unwrap(),
            CommandResult::Success
        ));
        assert_eq!(sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap(), None);
    }

    #[test]
    fn unsupported_paths_and_generic_control_writes_leave_the_image_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        assert!(sm.get_versioned_metadata("/legacy").is_err());
        assert!(sm
            .get_versioned_metadata("/__managed_content_v1__other/file")
            .is_err());
        assert!(matches!(
            sm.apply(1, &write("/legacy", b"unexpected", None)).unwrap(),
            CommandResult::ConditionalMetadataUnsupported
        ));
        let key = "/__managed_content_v1__/cursor";
        let first = committed(
            sm.apply(2, &write(key, b"immutable-pointer", None))
                .unwrap(),
        );
        let allocator = sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap();
        for (index, command) in [
            Command::PutControlState {
                namespace: NAMESPACE.into(),
                key: ALLOCATOR.into(),
                value: vec![0; TOKEN_LEN],
                if_absent: false,
            },
            Command::DeleteControlState {
                namespace: NAMESPACE.into(),
                key: ALLOCATOR.into(),
            },
            Command::AdjustCounter {
                key: key.into(),
                delta: 1,
            },
        ]
        .iter()
        .enumerate()
        {
            assert!(matches!(
                sm.apply(3 + index as u64, command).unwrap(),
                CommandResult::Error(_)
            ));
        }
        assert_eq!(sm.get_versioned_metadata(key).unwrap(), first);
        assert_eq!(
            sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap(),
            allocator
        );
        assert_eq!(sm.get_metadata("/legacy").unwrap(), None);
    }

    #[test]
    fn legacy_metadata_cas_invalidates_only_on_a_successful_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, mut sm) = machine(dir.path());
        let key = "/__managed_content_v1__/cursor";
        // FileMetadata field 9 (version), encoded as a protobuf varint.
        let first = committed(sm.apply(1, &write(key, &[0x48, 7], None)).unwrap());
        let replace = Command::CasSetMetadata {
            key: key.into(),
            value: vec![0x48, 8],
            expected_version: 7,
        };
        assert!(matches!(
            sm.apply(2, &replace).unwrap(),
            CommandResult::CasResult { success: true, .. }
        ));
        let second = sm.get_versioned_metadata(key).unwrap();
        assert_ne!(first.version, second.version);
        let allocator = sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap();
        assert!(matches!(
            sm.apply(3, &replace).unwrap(),
            CommandResult::CasResult { success: false, .. }
        ));
        assert_eq!(sm.get_versioned_metadata(key).unwrap(), second);
        assert_eq!(
            sm.get_control_state(NAMESPACE, ALLOCATOR).unwrap(),
            allocator
        );
    }
}
