//! File replacement and namespace barriers for application-controlled storage.
//!
//! These functions report OS synchronization errors. Storage qualification must
//! separately establish persistent backing and the platform's device-cache
//! guarantees. Callers synchronize file contents before publishing a name.

use std::io;
use std::path::Path;

mod replacement;
pub use replacement::replace_file;

/// Synchronize a directory's entries using the native filesystem barrier.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let directory = std::fs::File::open(path)?;
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "directory synchronization requires a directory",
            ));
        }
        directory.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory synchronization is unsupported on this platform",
        ))
    }
}

/// Synchronize a directory and its ancestors, from child to parent.
///
/// An optional ancestor is included in the barriers. Its own directory entry
/// must already be durable. Without an anchor the walk includes the filesystem
/// path's root. Paths resolve inside an application-controlled storage tree;
/// this helper is not a private-path authorization or symlink confinement API.
pub fn sync_directory_ancestors(path: &Path, durable_ancestor: Option<&Path>) -> io::Result<()> {
    let resolved = path.canonicalize()?;
    let anchor = durable_ancestor.map(Path::canonicalize).transpose()?;
    if anchor
        .as_ref()
        .is_some_and(|root| !resolved.starts_with(root))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "durability anchor is not an ancestor of the directory",
        ));
    }
    for directory in resolved.ancestors() {
        sync_directory(directory)?;
        if anchor.as_deref() == Some(directory) {
            break;
        }
    }
    Ok(())
}

/// A complete object is visible, but its requested durability is unconfirmed.
///
/// This error never grants permission to remove or overwrite that object.
#[derive(Debug)]
pub struct PublishedButNotDurable {
    source: io::Error,
}

impl PublishedButNotDurable {
    /// Preserve the OS error as the source of a publication-state error.
    pub fn into_io_error(source: io::Error) -> io::Error {
        io::Error::new(source.kind(), Self { source })
    }

    pub fn io_error(&self) -> &io::Error {
        &self.source
    }
}

impl std::fmt::Display for PublishedButNotDurable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "object is visible but durability is unconfirmed: {}",
            self.source
        )
    }
}

impl std::error::Error for PublishedButNotDurable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacements_cover_filename_boundaries_and_retain_open_snapshots() {
        use std::io::Read;

        let raw_parent = std::env::temp_dir();
        let root = tempfile::tempdir_in(&raw_parent).unwrap();
        // Preserve the host's raw path spelling, as Python tempfile and actual
        // service roots do, rather than relying on tempfile's normalization.
        let raw_root = raw_parent.join(root.path().file_name().unwrap());
        let staged = raw_root.join("candidate.tmp");
        #[cfg(windows)]
        let mut native_boundaries = std::collections::BTreeSet::new();
        for padding in 0..48 {
            let destination = raw_root.join(format!("节点-🦀-{}", "x".repeat(padding)));
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                use windows_sys::Win32::Storage::FileSystem::FILE_RENAME_INFO;
                let name_bytes = std::path::absolute(&destination)
                    .unwrap()
                    .as_os_str()
                    .encode_wide()
                    .count()
                    * std::mem::size_of::<u16>();
                native_boundaries.insert(
                    (std::mem::offset_of!(FILE_RENAME_INFO, FileName) + name_bytes)
                        % std::mem::size_of::<FILE_RENAME_INFO>(),
                );
            }
            let original = format!("before native replacement {padding}");
            let updated = format!("after native replacement {padding}");
            std::fs::write(&staged, original.as_bytes()).unwrap();
            replace_file(&staged, &destination).unwrap();
            assert!(!staged.exists());
            let mut reader = std::fs::File::open(&destination).unwrap();
            std::fs::write(&staged, updated.as_bytes()).unwrap();
            replace_file(&staged, &destination).unwrap();
            assert!(!staged.exists());
            assert_eq!(std::fs::read(&destination).unwrap(), updated.as_bytes());
            let mut retained = Vec::new();
            reader.read_to_end(&mut retained).unwrap();
            assert_eq!(retained, original.as_bytes());
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::FILE_RENAME_INFO;
            assert!(native_boundaries.contains(&0), "cover zero-padding buffers");
            assert_eq!(
                native_boundaries.len(),
                std::mem::size_of::<FILE_RENAME_INFO>() / std::mem::size_of::<u16>(),
                "exercise every native UTF-16 alignment boundary"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn barriers_cover_nested_directories_and_reject_files() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        sync_directory_ancestors(&nested, Some(root.path())).unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(
            sync_directory(&file).unwrap_err().kind(),
            io::ErrorKind::NotADirectory
        );
    }

    #[test]
    fn unrelated_anchors_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let unrelated = tempfile::tempdir().unwrap();
        assert_eq!(
            sync_directory_ancestors(root.path(), Some(unrelated.path()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn published_error_retains_the_original_os_error() {
        let error = PublishedButNotDurable::into_io_error(io::Error::from_raw_os_error(5));
        let state = error
            .get_ref()
            .unwrap()
            .downcast_ref::<PublishedButNotDurable>()
            .unwrap();
        assert_eq!(state.io_error().raw_os_error(), Some(5));
    }

    #[cfg(not(unix))]
    #[test]
    fn directory_barriers_are_explicitly_unsupported() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            sync_directory(root.path()).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
