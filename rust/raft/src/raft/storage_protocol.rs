//! Typed submission domains, independent of Raft membership and reader format.

use super::Command;

/// The storage authority that owns a command's admission and SC submission.
/// Reader-format compatibility is checked separately when admitting storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StorageProtocol {
    ConditionalMetadata,
    RecordLifetime,
    ReplicaControl,
}

impl Command {
    #[cfg(feature = "consensus")]
    pub(crate) fn requires_activation_qualification(&self) -> bool {
        matches!(self, Self::ActivateReplicaControl { .. })
    }

    pub(crate) fn storage_protocol(&self) -> Option<StorageProtocol> {
        match self {
            Self::WriteVersionedMetadata { .. }
            | Self::AdoptProtectedMetadata { .. }
            | Self::RenameMetadata { .. } => Some(StorageProtocol::ConditionalMetadata),
            Self::BindRecordGuard { .. }
            | Self::GuardedRecord { .. }
            | Self::RetireRecordGuard { .. }
            | Self::AdmitRecordIoOwner { .. } => Some(StorageProtocol::RecordLifetime),
            Self::ApplyReplicaBinding(_)
            | Self::ReserveNodeIdentity(_)
            | Self::ApplyReplicaIssuance(_)
            | Self::ActivateReplicaControl { .. } => Some(StorageProtocol::ReplicaControl),
            _ => None,
        }
    }
}
