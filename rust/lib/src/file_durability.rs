//! Filesystem namespace barriers for storage with an application-controlled root.
//!
//! These functions report OS synchronization errors. Storage qualification must
//! separately establish persistent backing and the platform's device-cache
//! guarantees. Callers synchronize file contents before publishing a name.

use std::io;
use std::path::Path;

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
