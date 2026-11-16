//! Native lifetime locks span actual I/O, Kernel instances and store reopen.
//! None of these filesystem operations run in the Raft apply transaction.

use super::*;
use kernel::extensions::guarded_records::RecordIoGuard;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

struct NativeRecordIoGuard {
    _file: File,
}
impl RecordIoGuard for NativeRecordIoGuard {}

fn io_error(error: std::io::Error) -> ConditionalMetadataError {
    refused(format!("record I/O lifetime: {error}"))
}

fn lock_path(domain: &(PathBuf, String)) -> PathBuf {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(64);
    for byte in Sha256::digest(domain.1.as_bytes()) {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 15)]));
    }
    domain.0.join(name)
}

fn open_lock(path: &Path) -> Result<File, ConditionalMetadataError> {
    std::fs::create_dir_all(path.parent().expect("record I/O domain")).map_err(io_error)?;
    // Keep the inode as part of the retirement identity. Replacing/unlinking a
    // lock file while an old handle exists could split the lifetime barrier.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error)
}

impl ZoneMetaStore {
    pub(super) fn record_io_owner_state(
        &self,
        storage_key: &str,
    ) -> Result<kernel::extensions::guarded_records::RecordOwnerState, ConditionalMetadataError>
    {
        let node = self.conditional_node()?;
        bridge_block_on(
            &self.runtime,
            node.with_state_machine(|state| state.record_io_owner_state(storage_key)),
        )
        .map_err(map_error)
    }

    pub(super) fn check_unscoped_record_io(
        &self,
        storage_key: &str,
    ) -> Result<(), ConditionalMetadataError> {
        // Deferred provider discovery cannot decide this until the real node
        // is resolved. Managed membership does not offer record ownership;
        // ordinary I/O must retain the same behavior before and after resolve.
        // Resolution failures still propagate, and scoped operations continue
        // to require conditional_node.
        let node = self.node().map_err(ConditionalMetadataError::Failed)?;
        if !node.supports_conditional_metadata() {
            return Ok(());
        }
        bridge_block_on(
            &self.runtime,
            node.with_state_machine(|state| state.check_unscoped_record_io(storage_key)),
        )
        .map_err(map_error)
    }

    pub fn admit_record_io_owner(
        &self,
        path: &str,
        expected_version: &[u8],
    ) -> Result<(), ConditionalMetadataError> {
        match self.commit_record(Command::AdmitRecordIoOwner {
            key: self.to_zone_key(path),
            expected_version: expected_version.to_vec(),
        })? {
            CommandResult::Success => Ok(()),
            CommandResult::Error(message) => Err(refused(message)),
            _ => Err(ConditionalMetadataError::Unknown(
                "unexpected record I/O admission result".into(),
            )),
        }
    }

    fn live_io_domain(
        &self,
        path: &str,
        version: &[u8],
    ) -> Result<(PathBuf, String), ConditionalMetadataError> {
        let key = self.to_zone_key(path);
        let node = self.conditional_node()?;
        bridge_block_on(
            &self.runtime,
            node.with_state_machine(|state| state.live_record_io_domain(&key, version)),
        )
        .map_err(map_error)
    }

    fn retired_io_domain(
        &self,
        path: &str,
        version: &[u8],
    ) -> Result<(PathBuf, String), ConditionalMetadataError> {
        let key = self.to_zone_key(path);
        let node = self.conditional_node()?;
        bridge_block_on(
            &self.runtime,
            node.with_state_machine(|state| state.retired_record_io_domain(&key, version)),
        )
        .map_err(map_error)
    }

    pub fn begin_record_io(
        &self,
        path: &str,
        guard_version: &[u8],
    ) -> Result<Box<dyn RecordIoGuard>, ConditionalMetadataError> {
        let domain = self.live_io_domain(path, guard_version)?;
        let file = open_lock(&lock_path(&domain))?;
        file.lock_shared().map_err(io_error)?;
        // Deletion may have committed while the request waited for this inode.
        // Admission is valid only if the SAME owning domain is still live.
        if self.live_io_domain(path, guard_version)? != domain {
            return Err(refused("record I/O owner changed during admission".into()));
        }
        Ok(Box::new(NativeRecordIoGuard { _file: file }))
    }

    pub(super) fn check_record_owner_binding(
        &self,
        path: &str,
        owner_path: &str,
        owner_version: &[u8],
    ) -> Result<(), ConditionalMetadataError> {
        let key = self.to_zone_key(path);
        let owner_key = self.to_zone_key(owner_path);
        let (_, actual_owner) = self.live_io_domain(path, owner_version)?;
        if key == owner_key || actual_owner != owner_key {
            return Err(refused(
                "record binding does not match its control owner".into(),
            ));
        }
        Ok(())
    }

    pub fn try_exclude_retired_record_io(
        &self,
        path: &str,
        terminal_version: &[u8],
    ) -> Result<Option<Box<dyn RecordIoGuard>>, ConditionalMetadataError> {
        let domain = self.retired_io_domain(path, terminal_version)?;
        let file = open_lock(&lock_path(&domain))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(io_error(error)),
        }
        if self.retired_io_domain(path, terminal_version)? != domain {
            return Err(refused("record I/O owner changed during exclusion".into()));
        }
        Ok(Some(Box::new(NativeRecordIoGuard { _file: file })))
    }
}
