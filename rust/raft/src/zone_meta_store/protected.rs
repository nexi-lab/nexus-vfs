//! The storage control plane adopts a legacy image without changing its key.

use super::{bridge_block_on, proto_to_kernel, ZoneMetaStore};
use crate::raft::CommandResult;
use kernel::meta_store::{
    ConditionalMetadataError, FileMetadata, MetaStoreError, RecordProtection,
    RecordProtectionResult, DT_REG,
};

use super::conditional::map_error;

impl RecordProtection for ZoneMetaStore {
    fn protect_record(
        &self,
        path: &str,
        qualify: &dyn Fn(&FileMetadata) -> Result<(), MetaStoreError>,
    ) -> Result<RecordProtectionResult, ConditionalMetadataError> {
        let node = self.conditional_node()?;
        let key = self.to_zone_key(path);
        let image = self
            .read_metadata_image(path)
            .map_err(ConditionalMetadataError::Failed)?;
        if let Some(raw) = &image {
            let mut metadata = proto_to_kernel(raw).map_err(ConditionalMetadataError::Failed)?;
            if metadata.entry_type != DT_REG {
                return Err(ConditionalMetadataError::Unsupported);
            }
            metadata.path = self.to_global_path(&metadata.path);
            qualify(&metadata).map_err(ConditionalMetadataError::Failed)?;
        }
        let result = bridge_block_on(
            &self.runtime,
            node.adopt_protected_metadata(key, image, rand::random()),
        )
        .map_err(map_error)?;
        match result {
            CommandResult::ProtectedMetadata { protected: false } => {
                Ok(RecordProtectionResult::Conflict)
            }
            CommandResult::ProtectedMetadata { protected: true } => {
                Ok(RecordProtectionResult::Protected)
            }
            _ => Err(ConditionalMetadataError::Unknown(
                "unexpected protected-record adoption response".into(),
            )),
        }
    }
}
