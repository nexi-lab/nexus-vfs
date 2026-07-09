//! `LocalConnectorBackend` — local-folder reference connector.
//!
//! Reference mode: mounts an external local folder into Nexus
//! without copying.  Files stay at their original location (Single
//! Source of Truth).  Optional symlink following with escape
//! detection (resolved path must stay within the mount root).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kernel::abc::object_store::{BackendStat, ObjectStore, StorageError, WriteResult};
use kernel::extensions::observer_backend::{
    ObservationError, ObservationHandle, ObservationSink, ObserverBackend,
};
use kernel::meta_store::{DT_DIR, DT_REG};

/// Reconcile cadence — the self-verifying backstop re-walks the backend
/// this often and re-proposes any entries the metastore is missing.
/// Additive-only (see `docs/observer-backend-contract.md` §3.3); a
/// watcher latency-optimization layer can be added later without
/// changing this correctness floor.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// Shutdown responsiveness — the reconcile loop sleeps in slices this
/// long so `ObservationHandle::drop` joins promptly instead of waiting
/// out a full `RECONCILE_INTERVAL`.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

///
/// Mounts an external local folder into Nexus. Files remain at original
/// location (Single Source of Truth). Supports symlink following with
/// escape detection (resolved path must stay within root).
#[derive(Clone)]
pub struct LocalConnectorBackend {
    root_path: PathBuf,
    follow_symlinks: bool,
    fsync: bool,
}

impl LocalConnectorBackend {
    pub fn new(root: &Path, follow_symlinks: bool, fsync: bool) -> io::Result<Self> {
        if !root.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("local_connector root does not exist: {}", root.display()),
            ));
        }
        Ok(Self {
            root_path: fs::canonicalize(root)?,
            follow_symlinks,
            fsync,
        })
    }

    /// Resolve virtual path to physical path with escape detection.
    pub(crate) fn resolve_path(&self, virtual_path: &str) -> Result<PathBuf, StorageError> {
        let clean = virtual_path.trim_start_matches('/');
        if clean.contains("..") {
            return Err(StorageError::IOError(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path traversal detected: {virtual_path}"),
            )));
        }
        let physical = self.root_path.join(clean);

        let resolved = if self.follow_symlinks {
            // Resolve symlinks, falling back to parent resolution if path doesn't exist yet
            match fs::canonicalize(&physical) {
                Ok(p) => p,
                Err(_) => {
                    // Path may not exist yet (write). Resolve parent + leaf.
                    if let Some(parent) = physical.parent() {
                        match fs::canonicalize(parent) {
                            Ok(p) => p.join(physical.file_name().unwrap_or_default()),
                            Err(_) => physical.clone(),
                        }
                    } else {
                        physical.clone()
                    }
                }
            }
        } else {
            physical.clone()
        };

        // Escape detection: resolved path must be under root
        if !resolved.starts_with(&self.root_path) {
            return Err(StorageError::IOError(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("path escapes mount root: {virtual_path}"),
            )));
        }

        Ok(resolved)
    }

    /// Enumerate every entry under the backend root, returning
    /// `(backend_relative_path, entry_type, size)` tuples for the
    /// ObserverBackend sync.  Reuses the existing `list_dir` / `stat`
    /// surface so the traversal honours the same symlink policy as
    /// normal reads.  Best-effort: an unreadable subdirectory is skipped
    /// rather than aborting the whole walk (the reconcile backstop
    /// re-attempts it next tick).
    ///
    /// `entry_type` is `DT_DIR` for directories (size `0`) and `DT_REG`
    /// for files (size from `stat`, which POSIX `read()` needs non-zero
    /// to serve bytes).
    fn collect_listing(&self) -> Vec<(String, u8, u64)> {
        let mut out = Vec::new();
        self.walk_dir("", &mut out);
        out
    }

    fn walk_dir(&self, rel: &str, out: &mut Vec<(String, u8, u64)>) {
        let names = match self.list_dir(rel) {
            Ok(n) => n,
            Err(_) => return,
        };
        for name in names {
            let is_dir = name.ends_with('/');
            let clean = name.trim_end_matches('/');
            if clean.is_empty() {
                continue;
            }
            let child_rel = if rel.is_empty() {
                clean.to_string()
            } else {
                format!("{rel}/{clean}")
            };
            if is_dir {
                out.push((child_rel.clone(), DT_DIR, 0));
                self.walk_dir(&child_rel, out);
            } else {
                let size = self.stat(&child_rel).map(|s| s.size).unwrap_or(0);
                out.push((child_rel, DT_REG, size));
            }
        }
    }

    /// Push one full backend listing through the sink.  Idempotent at
    /// the kernel layer (rows already in the metastore are left
    /// untouched), so the initial walk and every reconcile tick share
    /// this path.
    fn sync_once(entries: &[(String, u8, u64)], sink: &ObservationSink) {
        for (rel, etype, size) in entries {
            // DT_REG rows carry the backend-relative path as content_id
            // (what `read_content` resolves); DT_DIR rows carry none.
            let content_id = if *etype == DT_REG {
                Some(rel.clone())
            } else {
                None
            };
            sink.propose(rel, *etype, *size, content_id);
        }
    }
}

impl ObserverBackend for LocalConnectorBackend {
    fn install_observer(
        &self,
        sink: ObservationSink,
    ) -> Result<ObservationHandle, ObservationError> {
        // The root must be enumerable before the mount is declared
        // ready — a walk failure here is fatal (surfaces as a mount
        // error).  Nested per-directory failures inside `collect_listing`
        // stay best-effort (reconcile retries).
        self.list_dir("").map_err(|e| {
            ObservationError::Walk(io::Error::other(format!(
                "local_connector initial walk: {e:?}"
            )))
        })?;

        // Layer 1: initial walk — synchronous, seeds every pre-existing
        // entry before the mount serves reads.
        Self::sync_once(&self.collect_listing(), &sink);

        // Layer 3: periodic reconciler — the self-verifying backstop.
        // (Layer 2, the sub-second OS watcher, is a latency optimization
        // deferred per the design doc; correctness rests on this loop.)
        let (handle, shutdown) = ObservationHandle::new();
        let backend = self.clone();
        std::thread::Builder::new()
            .name("observer-reconcile".to_string())
            .spawn(move || {
                let slices =
                    (RECONCILE_INTERVAL.as_millis() / SHUTDOWN_POLL.as_millis()).max(1) as u64;
                loop {
                    for _ in 0..slices {
                        std::thread::sleep(SHUTDOWN_POLL);
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                    Self::sync_once(&backend.collect_listing(), &sink);
                }
            })
            .map_err(|e| {
                ObservationError::Watcher(format!("spawn observer-reconcile thread: {e}"))
            })?;

        Ok(handle)
    }
}

impl ObjectStore for LocalConnectorBackend {
    fn name(&self) -> &str {
        "local_connector"
    }

    /// LocalConnector references a host directory that content can reach
    /// out-of-band (CC writing task JSON directly, `rsync`, another
    /// process), so it owns the ObserverBackend contract: keep the
    /// metastore authoritative for its contents. `DriverLifecycleCoordinator`
    /// calls `install_observer` at mount time.
    fn as_observer(&self) -> Option<&dyn ObserverBackend> {
        Some(self)
    }

    fn write_content(
        &self,
        content: &[u8],
        content_id: &str,
        _ctx: &kernel::kernel::OperationContext,
        offset: u64,
    ) -> Result<WriteResult, StorageError> {
        if content_id.is_empty() {
            return Err(StorageError::IOError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LocalConnectorBackend requires content_id (backend_path)",
            )));
        }
        let file_path = self.resolve_path(content_id)?;

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(StorageError::IOError)?;
        }

        if offset == 0 {
            // Fast path: full overwrite, hash `content` directly.
            fs::write(&file_path, content).map_err(StorageError::IOError)?;
            if self.fsync {
                if let Ok(f) = fs::File::open(&file_path) {
                    let _ = f.sync_all();
                }
            }
            let hash = lib::hash::hash_content(content);
            return Ok(WriteResult {
                content_id: content_id.to_string(),
                version: hash,
                size: content.len() as u64,
            });
        }

        // pwrite slow path — see PathLocalBackend for rationale.
        use std::io::{Seek, SeekFrom, Write};
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&file_path)
            .map_err(StorageError::IOError)?;
        let cur_len = f.metadata().map_err(StorageError::IOError)?.len();
        let new_len = cur_len.max(offset + content.len() as u64);
        if new_len > cur_len {
            f.set_len(new_len).map_err(StorageError::IOError)?;
        }
        f.seek(SeekFrom::Start(offset))
            .map_err(StorageError::IOError)?;
        f.write_all(content).map_err(StorageError::IOError)?;

        if self.fsync {
            let _ = f.sync_all();
        }
        drop(f);

        let final_bytes = fs::read(&file_path).map_err(StorageError::IOError)?;
        let hash = lib::hash::hash_content(&final_bytes);
        Ok(WriteResult {
            content_id: content_id.to_string(),
            version: hash,
            size: final_bytes.len() as u64,
        })
    }

    fn read_content(
        &self,
        content_id: &str,
        _ctx: &kernel::kernel::OperationContext,
    ) -> Result<Vec<u8>, StorageError> {
        if content_id.is_empty() {
            return Err(StorageError::IOError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "LocalConnectorBackend requires content_id",
            )));
        }
        let file_path = self.resolve_path(content_id)?;
        fs::read(&file_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StorageError::NotFound(content_id.to_string())
            } else {
                StorageError::IOError(e)
            }
        })
    }

    fn delete_content(&self, _content_id: &str) -> Result<(), StorageError> {
        // For reference-mode connector, delete_content by hash is not meaningful.
        // Actual deletion happens via backend_path through kernel sys_unlink flow.
        Ok(())
    }

    fn mkdir(&self, path: &str, parents: bool, _exist_ok: bool) -> Result<(), StorageError> {
        let dir_path = self.resolve_path(path)?;
        if parents {
            fs::create_dir_all(&dir_path).map_err(StorageError::IOError)
        } else {
            fs::create_dir(&dir_path).map_err(StorageError::IOError)
        }
    }

    fn rmdir(&self, path: &str, recursive: bool) -> Result<(), StorageError> {
        let dir_path = self.resolve_path(path)?;
        if recursive {
            fs::remove_dir_all(&dir_path).map_err(StorageError::IOError)
        } else {
            fs::remove_dir(&dir_path).map_err(StorageError::IOError)
        }
    }

    fn delete_file(&self, path: &str) -> Result<(), StorageError> {
        let file_path = self.resolve_path(path)?;
        fs::remove_file(&file_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StorageError::NotFound(path.to_string())
            } else {
                StorageError::IOError(e)
            }
        })
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), StorageError> {
        let old = self.resolve_path(old_path)?;
        let new = self.resolve_path(new_path)?;
        if let Some(parent) = new.parent() {
            fs::create_dir_all(parent).map_err(StorageError::IOError)?;
        }
        fs::rename(&old, &new).map_err(StorageError::IOError)
    }

    fn copy_file(&self, src_path: &str, dst_path: &str) -> Result<WriteResult, StorageError> {
        let src = self.resolve_path(src_path)?;
        let dst = self.resolve_path(dst_path)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(StorageError::IOError)?;
        }
        let size = fs::copy(&src, &dst).map_err(StorageError::IOError)?;
        let content = fs::read(&dst).map_err(StorageError::IOError)?;
        let hash = lib::hash::hash_content(&content);
        Ok(WriteResult {
            content_id: dst_path.to_string(),
            version: hash,
            size,
        })
    }

    fn stat(&self, path: &str) -> Result<BackendStat, StorageError> {
        let target = if path.is_empty() {
            self.root_path.clone()
        } else {
            self.resolve_path(path)?
        };
        let md = fs::metadata(&target).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StorageError::NotFound(path.to_string())
            } else {
                StorageError::IOError(e)
            }
        })?;
        Ok(BackendStat {
            size: if md.is_dir() { 0 } else { md.len() },
            is_dir: md.is_dir(),
        })
    }

    fn list_dir(&self, path: &str) -> Result<Vec<String>, StorageError> {
        let dir_path = if path.is_empty() {
            self.root_path.clone()
        } else {
            self.resolve_path(path)?
        };
        let rd = fs::read_dir(&dir_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StorageError::NotFound(path.to_string())
            } else {
                StorageError::IOError(e)
            }
        })?;
        let mut entries = Vec::new();
        for entry in rd {
            let entry = entry.map_err(StorageError::IOError)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let ft = entry.file_type().map_err(StorageError::IOError)?;
            if ft.is_dir() {
                entries.push(format!("{name}/"));
            } else {
                entries.push(name);
            }
        }
        entries.sort();
        Ok(entries)
    }

    fn resolve_physical_path(&self, content_id: &str) -> Option<std::path::PathBuf> {
        self.resolve_path(content_id).ok()
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use std::collections::HashMap;

    fn backend(root: &Path) -> LocalConnectorBackend {
        LocalConnectorBackend::new(
            root, /* follow_symlinks */ false, /* fsync */ false,
        )
        .expect("backend")
    }

    /// `collect_listing` recurses the whole tree, tagging directories
    /// DT_DIR (size 0) and files DT_REG with their real byte size, and
    /// returns backend-relative paths. Real user problem: the initial
    /// walk must see every pre-existing entry so a peer sees them via
    /// metastore after a cold restart.
    #[test]
    fn collect_listing_recurses_and_tags_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Layout: a.json (file), sub/ (dir), sub/b.json (nested file).
        fs::write(root.join("a.json"), b"hello").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("b.json"), b"nested-body").unwrap();

        let listing = backend(root).collect_listing();
        let by_path: HashMap<&str, (u8, u64)> = listing
            .iter()
            .map(|(p, t, s)| (p.as_str(), (*t, *s)))
            .collect();

        assert_eq!(
            by_path.get("a.json"),
            Some(&(DT_REG, 5)),
            "file size from stat"
        );
        assert_eq!(
            by_path.get("sub"),
            Some(&(DT_DIR, 0)),
            "dir tagged DT_DIR size 0"
        );
        assert_eq!(
            by_path.get("sub/b.json"),
            Some(&(DT_REG, 11)),
            "nested file discovered with backend-relative path + real size"
        );
        assert_eq!(by_path.len(), 3, "exactly the three entries, no extras");
    }

    /// An empty backend yields an empty listing (initial walk on a fresh
    /// mount is a no-op, not an error).
    #[test]
    fn collect_listing_empty_backend() {
        let dir = tempfile::tempdir().unwrap();
        assert!(backend(dir.path()).collect_listing().is_empty());
    }

    /// `install_observer` on a readable root returns a handle whose Drop
    /// stops the reconcile thread. Real user problem: unmount must not
    /// leak the background reconciler. We assert the handle is returned
    /// (initial walk succeeded against a real dir) and that dropping it
    /// returns promptly (thread observes shutdown within a poll slice).
    #[test]
    fn install_observer_returns_handle_and_shuts_down() {
        use kernel::extensions::observer_backend::ObservationSink;
        use std::sync::Weak;

        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("x.json"), b"x").unwrap();

        // Kernel-less sink: propose no-ops (Weak upgrade fails), so this
        // exercises the walk + thread lifecycle without a live kernel.
        let sink = ObservationSink::new(Weak::new(), "root".to_string(), "/mnt".to_string());
        let handle = backend(dir.path())
            .install_observer(sink)
            .expect("install on readable root");

        // Drop joins the reconcile thread via the shutdown broadcast; if
        // the loop ignored the signal this test would hang the suite.
        drop(handle);
    }

    /// `install_observer` surfaces a fatal error when the root cannot be
    /// enumerated (mount readiness must not be declared over an
    /// unreadable backend).
    #[test]
    fn install_observer_errors_on_unreadable_root() {
        use kernel::extensions::observer_backend::{ObservationError, ObservationSink};
        use std::sync::Weak;

        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        // Construct a backend whose root vanished after construction by
        // building against the tempdir then removing it.
        let be = backend(dir.path());
        drop(std::fs::remove_dir_all(dir.path()));
        let _ = missing; // silence unused on platforms that keep the dir

        let sink = ObservationSink::new(Weak::new(), "root".to_string(), "/mnt".to_string());
        match be.install_observer(sink) {
            Err(ObservationError::Walk(_)) => {}
            Err(other) => panic!("expected Walk error on unreadable root, got: {other}"),
            Ok(_) => panic!("expected Walk error on unreadable root, got Ok(handle)"),
        }
    }
}
