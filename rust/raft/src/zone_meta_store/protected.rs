//! The storage control plane adopts a legacy image without changing its key.

use super::{bridge_block_on, proto_to_kernel, ZoneMetaStore};
use crate::raft::{CommandResult, FullStateMachine};
use kernel::meta_store::{ConditionalMetadataError, DT_REG};

use super::conditional::map_error;

/// A qualified record, or a concurrent legacy change requiring a new snapshot.
#[derive(Debug)]
pub enum ProtectedMetadataAdoption {
    Protected,
    Conflict,
}

impl ZoneMetaStore {
    /// Atomically protect the current metadata image at the existing path.
    /// Repeating adoption of an already protected path preserves its current
    /// image and revision. The owning service qualifies immutable content first.
    pub fn adopt_protected_record(
        &self,
        path: &str,
    ) -> Result<ProtectedMetadataAdoption, ConditionalMetadataError> {
        self.conditional_metadata()
            .ok_or(ConditionalMetadataError::Unsupported)?;
        let node = self.node().map_err(ConditionalMetadataError::Failed)?;
        let key = self.to_zone_key(path);
        let image = bridge_block_on(
            &self.runtime,
            node.with_state_machine(|state: &FullStateMachine| state.get_metadata(&key)),
        )
        .map_err(map_error)?;
        if let Some(raw) = &image {
            let metadata = proto_to_kernel(raw).map_err(ConditionalMetadataError::Failed)?;
            if metadata.entry_type != DT_REG {
                return Err(ConditionalMetadataError::Unsupported);
            }
        }
        let result = bridge_block_on(
            &self.runtime,
            node.adopt_protected_metadata(key, image, rand::random()),
        )
        .map_err(map_error)?;
        match result {
            CommandResult::ProtectedMetadata { protected: false } => {
                Ok(ProtectedMetadataAdoption::Conflict)
            }
            CommandResult::ProtectedMetadata { protected: true } => {
                Ok(ProtectedMetadataAdoption::Protected)
            }
            _ => Err(ConditionalMetadataError::Unknown(
                "unexpected protected-record adoption response".into(),
            )),
        }
    }
}
