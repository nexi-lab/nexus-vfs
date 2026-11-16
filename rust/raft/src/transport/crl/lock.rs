//! One OS lock for revocation reads that authorize issuance and all writers.

use std::fs::File;
use std::path::Path;

/// The file contains no process state. The OS releases exclusion with the
/// handle, including process termination. Keep its name across replacements
/// of the separate revoked-serial file so every participant locks one inode.
pub(super) struct RevocationGuard {
    _file: File,
}

impl RevocationGuard {
    pub(super) fn acquire(path: &Path) -> Result<Self, String> {
        let lock = path.with_extension("lock");
        if let Some(parent) = lock.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create revocation lock directory: {e}"))?;
        }
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)
            .map_err(|e| format!("open revocation lock: {e}"))?;
        file.lock()
            .map_err(|e| format!("acquire revocation lock: {e}"))?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests;
