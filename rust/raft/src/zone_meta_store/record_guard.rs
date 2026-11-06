//! Qualified record controls. Metadata qualification remains the caller's job,
//! as for ConditionalMetadata; these operations do not stage or reclaim blobs.

use super::conditional::{decode_result, map_error};
use super::{bridge_block_on, kernel_to_proto, ZoneMetaStore};
use crate::raft::{Command, CommandResult, GuardedRecordMutation};
use kernel::meta_store::{
    ConditionalMetadataError, ConditionalMetadataResult, FileMetadata, MetaStoreError,
};

fn refused(message: String) -> ConditionalMetadataError {
    ConditionalMetadataError::Failed(MetaStoreError::IOError(message))
}

impl ZoneMetaStore {
    fn commit_record(&self, command: Command) -> Result<CommandResult, ConditionalMetadataError> {
        let node = self.conditional_node()?;
        bridge_block_on(&self.runtime, node.commit_record_storage(command)).map_err(map_error)
    }

    /// Bind an exact qualified metadata image to a protected owner. Repeating
    /// the same binding is safe; a record can never be assigned to another owner.
    /// Paths, including aliases, are projected into this store's owning zone.
    pub fn bind_record_guard(
        &self,
        path: &str,
        expected_image: Option<&FileMetadata>,
        guard_path: &str,
        guard_version: &[u8],
    ) -> Result<(), ConditionalMetadataError> {
        let key = self.to_zone_key(path);
        let expected_image = expected_image.map(|metadata| {
            let mut metadata = metadata.clone();
            metadata.path = key.clone();
            kernel_to_proto(&metadata)
        });
        match self.commit_record(Command::BindRecordGuard {
            key,
            expected_image,
            guard_key: self.to_zone_key(guard_path),
            guard_version: guard_version.to_vec(),
            incarnation: rand::random(),
        })? {
            CommandResult::Success => Ok(()),
            CommandResult::Error(message) => Err(refused(message)),
            _ => Err(ConditionalMetadataError::Unknown(
                "unexpected record admission result".into(),
            )),
        }
    }

    /// Publish immutable content metadata only while both the record revision
    /// and its admitted owner's handle still match at final apply.
    pub fn replace_guarded_record(
        &self,
        path: &str,
        mut metadata: FileMetadata,
        expected_version: Option<&[u8]>,
        guard_version: &[u8],
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError> {
        let key = self.to_zone_key(path);
        metadata.path = key.clone();
        decode_result(self.commit_record(Command::GuardedRecord {
            guard_version: guard_version.to_vec(),
            mutation: GuardedRecordMutation::ReplaceMetadata {
                key,
                value: kernel_to_proto(&metadata),
                expected: expected_version.map(<[u8]>::to_vec),
                incarnation: rand::random(),
            },
        })?)
    }

    /// Append through the same owner fence as files. The store, rather than
    /// the caller, assigns the committed sequence in the Raft apply transaction.
    pub fn append_guarded_record(
        &self,
        path: &str,
        data: &[u8],
        guard_version: &[u8],
    ) -> Result<u64, ConditionalMetadataError> {
        let prefix = kernel::core::stream::wal::wal_stream_prefix(&self.to_zone_key(path));
        match self.commit_record(Command::GuardedRecord {
            guard_version: guard_version.to_vec(),
            mutation: GuardedRecordMutation::Append {
                stream_prefix: prefix,
                data: data.to_vec(),
            },
        })? {
            CommandResult::Value(bytes) => <[u8; 8]>::try_from(bytes.as_slice())
                .map(u64::from_be_bytes)
                .map_err(|_| {
                    ConditionalMetadataError::Unknown("committed record has no sequence".into())
                }),
            CommandResult::Error(message) => Err(refused(message)),
            _ => Err(ConditionalMetadataError::Unknown(
                "unexpected record append result".into(),
            )),
        }
    }

    /// Publish a terminal owner image and irrevocably retire its handles in one
    /// commit. This retains cleanup intent; it does not reclaim physical data.
    pub fn retire_record_guard(
        &self,
        path: &str,
        mut terminal_image: FileMetadata,
        expected_version: &[u8],
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError> {
        let key = self.to_zone_key(path);
        terminal_image.path = key.clone();
        decode_result(self.commit_record(Command::RetireRecordGuard {
            key,
            expected_version: expected_version.to_vec(),
            value: kernel_to_proto(&terminal_image),
            incarnation: rand::random(),
        })?)
    }
}
