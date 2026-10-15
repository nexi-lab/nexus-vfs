//! FileDescriptorTable — kernel primitive for pre-opened file descriptors.
//!
//! Mirrors the PipeManager / StreamManager pattern: a `DashMap` registry
//! of runtime state keyed by VFS path. `sys_write` registers an fd after
//! a successful backend write (PAS backends only — CAS/remote return
//! `None` from `resolve_physical_path`). `sys_read` hits the FDT before
//! falling through to the full backend read path.
//!
//! Uses `libc::pread` / `libc::pwrite` — atomic, no seek state, thread-safe.
//! Each `FileHandle` owns its `RawFd` and closes it on Drop.

use std::path::Path;

// ── Non-Unix stub ─────────────────────────────────────────────────────
// FDT is Unix-only (libc::pread/pwrite). On Windows the struct is a
// no-op: all reads miss, writes are no-ops. Production targets Linux/macOS.

#[cfg(not(unix))]
pub(crate) struct FileDescriptorTable;

#[cfg(not(unix))]
impl FileDescriptorTable {
    pub(crate) fn new() -> Self {
        Self
    }
    pub(crate) fn register(&self, _vfs_path: &str, _physical_path: &Path) -> bool {
        false
    }
    pub(crate) fn pread(&self, _vfs_path: &str) -> Option<Vec<u8>> {
        None
    }
    pub(crate) fn remove(&self, _vfs_path: &str) {}
    pub(crate) fn rename(&self, _old_path: &str, _new_path: &str) {}
    #[allow(dead_code)]
    pub(crate) fn close_all(&self) {}
}

// ── Unix implementation ───────────────────────────────────────────────

#[cfg(unix)]
use dashmap::DashMap;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
/// Owns a raw file descriptor; closes on drop.
struct FileHandle {
    fd: RawFd,
    physical_path: std::path::PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileHandle {
    /// Open `path` with O_RDWR. Returns `None` if open fails.
    fn open(path: &Path) -> Option<Self> {
        use std::os::fd::IntoRawFd;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        let metadata = file.metadata().ok()?;
        Some(Self {
            fd: file.into_raw_fd(),
            physical_path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Atomic positioned read — no seek state mutation.
    fn pread(&self, buf: &mut [u8], offset: i64) -> isize {
        unsafe { libc::pread(self.fd, buf.as_mut_ptr().cast(), buf.len(), offset) }
    }

    /// Atomic positioned write — no seek state mutation.
    #[allow(dead_code)]
    fn pwrite(&self, buf: &[u8], offset: i64) -> isize {
        unsafe { libc::pwrite(self.fd, buf.as_ptr().cast(), buf.len(), offset) }
    }

    /// Only reuse a descriptor while its physical path still names that inode.
    fn current_size(&self) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata(&self.physical_path).ok()?;
        (metadata.dev() == self.device && metadata.ino() == self.inode).then_some(metadata.len())
    }
}

#[cfg(unix)]
impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

// SAFETY: RawFd is an integer; pread/pwrite are thread-safe (no shared seek cursor).
#[cfg(unix)]
unsafe impl Send for FileHandle {}
#[cfg(unix)]
unsafe impl Sync for FileHandle {}

#[cfg(unix)]
/// Kernel-internal file descriptor table — pre-opened fds for PAS backends.
///
/// Lifecycle:
/// - `register`: called by `sys_write` after a successful PAS write.
/// - `pread`: called by `sys_read` as a fast path (skip VFS lock + backend I/O).
/// - `remove`: called by `sys_unlink`.
/// - `rename`: called by `sys_rename`.
/// - `close_all`: called on kernel shutdown / metastore release.
pub(crate) struct FileDescriptorTable {
    fds: DashMap<String, Arc<FileHandle>>,
}

#[cfg(unix)]
impl FileDescriptorTable {
    pub(crate) fn new() -> Self {
        Self {
            fds: DashMap::new(),
        }
    }

    /// Register (or replace) an fd for `vfs_path`. Returns true if opened successfully.
    pub(crate) fn register(&self, vfs_path: &str, physical_path: &Path) -> bool {
        if let Some(handle) = FileHandle::open(physical_path) {
            self.fds.insert(vfs_path.to_string(), Arc::new(handle));
            true
        } else {
            false
        }
    }

    /// Read the entire file content via the pre-opened fd. Returns `None` on miss.
    pub(crate) fn pread(&self, vfs_path: &str) -> Option<Vec<u8>> {
        let handle = Arc::clone(self.fds.get(vfs_path)?.value());
        let Some(size) = handle.current_size() else {
            // The backend must resolve a replacement under its own policy.
            // Do not evict a newer registration installed during this read.
            self.fds
                .remove_if(vfs_path, |_, cached| Arc::ptr_eq(cached, &handle));
            return None;
        };
        let size = size as usize;
        if size == 0 {
            return Some(Vec::new());
        }
        let mut buf = vec![0u8; size];
        let n = handle.pread(&mut buf, 0);
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    /// Remove and close the fd for `vfs_path`.
    pub(crate) fn remove(&self, vfs_path: &str) {
        self.fds.remove(vfs_path);
    }

    /// Re-key an fd; reads still validate its original physical path.
    pub(crate) fn rename(&self, old_path: &str, new_path: &str) {
        if let Some((_, handle)) = self.fds.remove(old_path) {
            self.fds.insert(new_path.to_string(), handle);
        }
    }

    /// Close all fds (kernel shutdown).
    #[allow(dead_code)]
    pub(crate) fn close_all(&self) {
        self.fds.clear();
    }
}

// ── Tests ───────────────────────────────────────────────────────────
//
// Unix-only: every test exercises the real libc-backed FileHandle path
// (register / pread / rename). On Windows FileDescriptorTable is a
// no-op stub, so these assertions would all fail against it — gate the
// module to match the implementation it tests.

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn register_and_pread() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let fdt = FileDescriptorTable::new();
        assert!(fdt.pread("/test/hello.txt").is_none());

        assert!(fdt.register("/test/hello.txt", &file_path));
        let data = fdt.pread("/test/hello.txt").unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn miss_returns_none() {
        let fdt = FileDescriptorTable::new();
        assert!(fdt.pread("/nonexistent").is_none());
    }

    #[test]
    fn remove_closes_fd() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("rm.txt");
        std::fs::write(&file_path, b"data").unwrap();

        let fdt = FileDescriptorTable::new();
        fdt.register("/rm", &file_path);
        assert!(fdt.pread("/rm").is_some());

        fdt.remove("/rm");
        assert!(fdt.pread("/rm").is_none());
    }

    #[test]
    fn rename_preserves_fd() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("orig.txt");
        std::fs::write(&file_path, b"content").unwrap();

        let fdt = FileDescriptorTable::new();
        fdt.register("/old", &file_path);

        fdt.rename("/old", "/new");
        assert!(fdt.pread("/old").is_none());
        assert_eq!(fdt.pread("/new").unwrap(), b"content");
    }

    #[test]
    fn close_all_clears_table() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");
        std::fs::write(&f1, b"a").unwrap();
        std::fs::write(&f2, b"b").unwrap();

        let fdt = FileDescriptorTable::new();
        fdt.register("/a", &f1);
        fdt.register("/b", &f2);

        fdt.close_all();
        assert!(fdt.pread("/a").is_none());
        assert!(fdt.pread("/b").is_none());
    }

    #[test]
    fn pread_reflects_external_write() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("mut.txt");
        std::fs::write(&file_path, b"v1").unwrap();

        let fdt = FileDescriptorTable::new();
        fdt.register("/mut", &file_path);
        assert_eq!(fdt.pread("/mut").unwrap(), b"v1");

        // External write (simulates a subsequent sys_write that wrote new content)
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        f.write_all(b"v2-longer").unwrap();
        f.flush().unwrap();
        drop(f);

        // pread reflects the new content (fd stays valid after external truncate+write)
        let data = fdt.pread("/mut").unwrap();
        assert_eq!(data, b"v2-longer");
    }

    #[test]
    fn atomic_external_replace_invalidates_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("document.txt");
        let replacement = dir.path().join("replacement.txt");
        std::fs::write(&file, b"old contents").unwrap();

        let fdt = FileDescriptorTable::new();
        assert!(fdt.register("/document.txt", &file));
        assert_eq!(fdt.pread("/document.txt").unwrap(), b"old contents");
        std::fs::write(&replacement, b"new").unwrap();
        std::fs::rename(&replacement, &file).unwrap();

        assert!(fdt.pread("/document.txt").is_none());
        assert!(fdt.fds.is_empty());
        assert!(fdt.register("/document.txt", &file));
        assert_eq!(fdt.pread("/document.txt").unwrap(), b"new");
    }

    #[test]
    fn external_delete_invalidates_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("deleted.txt");
        std::fs::write(&file, b"deleted contents").unwrap();
        let fdt = FileDescriptorTable::new();
        assert!(fdt.register("/deleted.txt", &file));

        std::fs::remove_file(&file).unwrap();
        assert!(fdt.pread("/deleted.txt").is_none());
        assert!(fdt.fds.is_empty());
    }

    #[test]
    fn cached_descriptor_does_not_survive_exec() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("private.txt");
        std::fs::write(&file, b"private").unwrap();
        let fdt = FileDescriptorTable::new();
        assert!(fdt.register("/private.txt", &file));
        let handle = fdt.fds.get("/private.txt").unwrap();
        let flags = unsafe { libc::fcntl(handle.fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
