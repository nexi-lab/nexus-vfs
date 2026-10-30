//! Conditional metadata reuses the zone's path projection and SC state machine.

use super::{bridge_block_on, kernel_to_proto, proto_to_kernel, ZoneBinding, ZoneMetaStore};
use crate::prelude::{FullStateMachine, ZoneConsensus};
use crate::raft::{CommandResult, RaftError};
use kernel::meta_store::{
    ConditionalMetadata, ConditionalMetadataError, ConditionalMetadataResult, FileMetadata,
    MetaStoreError, MetadataSnapshot,
};

pub(super) fn map_error(error: RaftError) -> ConditionalMetadataError {
    match error {
        RaftError::UnsupportedOperation(_) => ConditionalMetadataError::Unsupported,
        error if error.proposal_outcome_unknown() => {
            ConditionalMetadataError::Unknown(error.to_string())
        }
        error => ConditionalMetadataError::Failed(MetaStoreError::IOError(error.to_string())),
    }
}

impl ZoneMetaStore {
    pub(super) fn conditional_metadata(&self) -> Option<&dyn ConditionalMetadata> {
        let node = match &self.binding {
            ZoneBinding::Ready(node) => Some(node),
            ZoneBinding::Deferred { resolved, .. } => resolved.get(),
        };
        // Provider lookup stays lazy. The operation resolves and validates the
        // actual node before reading or submitting any conditional command.
        if node.is_none_or(|node| node.supports_conditional_metadata()) {
            Some(self)
        } else {
            None
        }
    }

    pub(super) fn conditional_node(
        &self,
    ) -> Result<&ZoneConsensus<FullStateMachine>, ConditionalMetadataError> {
        let node = self.node().map_err(ConditionalMetadataError::Failed)?;
        if node.supports_conditional_metadata() {
            Ok(node)
        } else {
            Err(ConditionalMetadataError::Unsupported)
        }
    }
}

impl ConditionalMetadata for ZoneMetaStore {
    fn read_versioned(
        &self,
        path: &str,
    ) -> Result<Option<MetadataSnapshot>, ConditionalMetadataError> {
        let node = self.conditional_node()?;
        let key = self.to_zone_key(path);
        let image = bridge_block_on(
            &self.runtime,
            node.with_state_machine(|state| state.get_versioned_metadata(&key)),
        )
        .map_err(map_error)?;
        match (image.value, image.version) {
            (None, None) => Ok(None),
            (Some(value), Some(version)) => {
                let mut metadata =
                    proto_to_kernel(&value).map_err(ConditionalMetadataError::Failed)?;
                metadata.path = self.to_global_path(&metadata.path);
                Ok(Some(MetadataSnapshot { metadata, version }))
            }
            _ => Err(ConditionalMetadataError::Failed(MetaStoreError::IOError(
                "conditional metadata image and revision disagree".into(),
            ))),
        }
    }

    fn replace_if_version(
        &self,
        path: &str,
        mut metadata: FileMetadata,
        expected_version: Option<&[u8]>,
    ) -> Result<ConditionalMetadataResult, ConditionalMetadataError> {
        let node = self.conditional_node()?;
        let key = self.to_zone_key(path);
        metadata.path = key.clone();
        let result = bridge_block_on(
            &self.runtime,
            node.replace_conditional_metadata(
                key,
                kernel_to_proto(&metadata),
                expected_version.map(<[u8]>::to_vec),
                rand::random(),
            ),
        )
        .map_err(map_error)?;
        match result {
            CommandResult::ConditionalMetadata { committed, current } => {
                if committed {
                    let version = current.version.ok_or_else(|| {
                        ConditionalMetadataError::Unknown(
                            "committed metadata response has no revision".into(),
                        )
                    })?;
                    Ok(ConditionalMetadataResult::Committed { version })
                } else {
                    Ok(ConditionalMetadataResult::Conflict {
                        current_version: current.version,
                    })
                }
            }
            CommandResult::ConditionalMetadataUnsupported => {
                Err(ConditionalMetadataError::Unsupported)
            }
            _ => Err(ConditionalMetadataError::Unknown(
                "conditional metadata response has an unexpected result".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submitted_failures_keep_their_unknown_outcome() {
        for error in [
            RaftError::ProposalOutcomeUnknown("apply reply lost".into()),
            RaftError::Transport("connection reset".into()),
            RaftError::Timeout(10),
            RaftError::ProposalDropped,
        ] {
            assert!(matches!(
                map_error(error),
                ConditionalMetadataError::Unknown(_)
            ));
        }
        assert!(matches!(
            map_error(RaftError::NotLeader { leader_hint: None }),
            ConditionalMetadataError::Failed(_)
        ));
        assert!(matches!(
            map_error(RaftError::UnsupportedOperation("managed membership")),
            ConditionalMetadataError::Unsupported
        ));
    }
}
