//! Owner-only persistence for private keys, API-key secrets and join tokens.
//!
//! Permissions are tightened before writing new bytes, including when replacing
//! an existing file: Unix uses `0600`; Windows installs a protected owner-only
//! DACL on the open file handle. Directory inheritance does not grant access to
//! a secret file. A permissions error prevents the new secret from being written.

use std::io::Write;
use std::path::Path;

/// Tighten an existing regular secret without truncating or replacing bytes.
/// Paths must be inside the caller's owner-controlled storage directory.
pub fn protect_secret(path: &Path) -> std::io::Result<()> {
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secret must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::File::open(path)?.set_permissions(std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        windows::protect_owner_only(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "owner-only protection is unsupported",
        ))
    }
}

/// Persist a new secret without replacing any existing file, including a
/// partially written one. Success syncs both the bytes and (on Unix) its
/// directory entry before a caller may submit an operation using this key.
/// A write/sync failure deliberately retains the file for explicit recovery.
pub fn create_secret(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(windows)]
    let mut file = windows::create_owner_only(path)?;
    #[cfg(not(any(unix, windows)))]
    return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "owner-only create is unsupported on this platform",
    ));
    #[cfg(any(unix, windows))]
    {
        file.write_all(contents)?;
        file.sync_all()?;
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    }
}

#[cfg(windows)]
mod windows;

/// Write `contents` to `path` readable and writable by the owner only.
///
/// Creates or replaces the file, enforcing permissions on every write.
pub fn write_secret(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // `mode` above only took effect if the file was just created. Tighten
        // unconditionally BEFORE the bytes land, so a pre-existing 0644 file
        // never holds the new secret.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(contents)?;
        f.flush()
    }
    #[cfg(windows)]
    {
        let mut f = windows::open_owner_only(path)?;
        f.write_all(contents)?;
        f.flush()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(contents)?;
        f.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_a_secret_never_replaces_existing_or_partial_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending");
        create_secret(&path, b"original key and request").unwrap();
        assert_eq!(
            create_secret(&path, b"replacement").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"original key and request");
        let partial = dir.path().join("partial");
        std::fs::write(&partial, b"{").unwrap();
        assert_eq!(
            create_secret(&partial, b"new operation")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(partial).unwrap(), b"{");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn protecting_a_secret_repairs_permissions_without_rewriting_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovered");
        std::fs::write(&path, b"original persisted key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        protect_secret(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original persisted key");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn writes_the_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_secret(&path, b"second, longer").unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"second, longer",
            "a rewrite replaces the bytes rather than appending to them"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_secret(&path, b"k").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    /// The case the old writers got wrong: a file that ALREADY existed with
    /// looser permissions. `OpenOptions::mode` alone leaves it at 0644, which is
    /// what an agent key written by the previous release looks like on disk.
    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_file_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_secret(&path, b"new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a pre-existing 0644 file must come out 0600, got {mode:o}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }
}
