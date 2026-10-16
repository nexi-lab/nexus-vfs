//! The one way this workspace writes secret material to disk.
//!
//! Private keys (CA, node, agent), the cluster API-key HMAC secret and join
//! tokens all land as files, and every one of them must be owner-only. That rule
//! used to be written out separately at each site — and the copies disagreed. A
//! cross-machine bring-up found an agent's private key sitting at `0644`,
//! readable by every local user, because the agent-bundle writer used a bare
//! `std::fs::write`; the cluster CA key and the join token were written the same
//! way, while the node key and API-key secret each had their own hand-rolled
//! `0600`. One function makes the rule impossible to skip by accident.
//!
//! **Unix:** `0o600`, and tightened on EVERY write, not only on create.
//! `OpenOptions::mode` applies when a file is CREATED; a file that already
//! existed keeps whatever mode it had. So a key first written world-readable
//! stays world-readable through every later rotation unless something resets it
//! — which is exactly the state a node upgraded from the old writer is in. The
//! order is: open (truncating, so the old bytes are gone), tighten, then write,
//! so the NEW secret is never present in a file anyone else can read.
//!
//! **Windows:** a plain write. Files inherit the ACL of their directory, and a
//! data directory under the user's profile is already owner-only; Windows has no
//! mode bits to set here, so there is nothing truthful to add.

use std::io::Write;
use std::path::Path;

/// Write `contents` to `path` readable and writable by the owner only.
///
/// Creates or replaces the file. On unix the permissions are forced to `0o600`
/// even when the file already existed with looser ones — see the module docs
/// for why "on create" is not enough.
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
    #[cfg(not(unix))]
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
