//! Per-zone on-disk lifecycle with RAII-backed crash safety.
//!
//! Disk-dir existence is the authoritative answer to "does this node host
//! zone X?". The `ZoneRaftRegistry.zones` DashMap is a pure live-handle
//! index derived from disk + runtime state — it never claims independent
//! membership authority.
//!
//! Two failure modes this module makes unrepresentable:
//!
//! 1. **Partial create** — `setup_zone` opens redb, creates `ZoneConsensus`,
//!    spawns the transport loop, inserts into the DashMap. Any `?` return
//!    between "dir created" and "DashMap insert" used to leave the zone
//!    dir behind. `ZonePersistence` is armed on `create()` and disarmed on
//!    `commit()`; Drop rolls back the dir while armed.
//!
//! 2. **Incomplete remove** — the previous `remove_zone` only cleared the
//!    in-memory DashMap. The dir stayed on disk and `open_existing_zones_
//!    from_disk` resurrected it as a zombie zone on every restart. The
//!    tombstone (`.removed` marker) is the durable commit point: once it
//!    exists, startup MUST complete the teardown instead of opening.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const TOMBSTONE_NAME: &str = ".removed";
/// In-dir marker of when this zone's LOCAL replica was created — the
/// wall-clock the boot resurrection check compares the replicated
/// deletion epoch against ("deleted after this copy was made ⇒ stale
/// copy, do not materialize").
const CREATION_EPOCH_NAME: &str = ".creation-epoch";

/// Tombstone payload (R12). Historically the tombstone was a zero-byte
/// marker; a zero-byte or unparsable file is read back as `deletion_epoch
/// == 0` (legacy), which suppresses nothing extra — the file's mere
/// existence still triggers the existing tombstone cleanup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeletionRecord {
    pub version: u32,
    pub zone_id: String,
    /// Strictly increasing per zone; the boot check is
    /// `deletion_epoch > local creation epoch`.
    pub deletion_epoch: u64,
    pub deleted_at_ms: u64,
    pub initiated_by_node: u64,
}

/// Owns the on-disk dir for a single zone. See module doc.
#[derive(Debug)]
pub struct ZonePersistence {
    zone_path: PathBuf,
    tombstone_path: PathBuf,
    /// When `true`, `Drop` rolls back the zone dir via `remove_dir_all`.
    /// Set by `create()`, cleared by `commit()`.
    armed: bool,
}

impl ZonePersistence {
    /// Create a fresh zone dir. Returns an armed handle — if `Drop` runs
    /// before `commit()`, the dir is rolled back.
    ///
    /// Errors if the dir already exists: a caller trying to `create` an
    /// existing zone indicates a bug (the registry's `creating` guard +
    /// fast-path check should have caught it upstream).
    pub fn create(base: &Path, zone_id: &str) -> io::Result<Self> {
        let zone_path = base.join(zone_id);
        let tombstone_path = zone_path.join(TOMBSTONE_NAME);
        if zone_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Zone dir '{}' already exists — caller must use open()",
                    zone_path.display()
                ),
            ));
        }
        std::fs::create_dir_all(&zone_path)?;
        Ok(Self {
            zone_path,
            tombstone_path,
            armed: true,
        })
    }

    /// Open an existing zone dir. The returned handle is not armed — the
    /// dir is already persisted state, Drop must not remove it on
    /// transient errors in the rest of setup.
    pub fn open(base: &Path, zone_id: &str) -> io::Result<Self> {
        let zone_path = base.join(zone_id);
        let tombstone_path = zone_path.join(TOMBSTONE_NAME);
        if !zone_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Zone dir '{}' does not exist", zone_path.display()),
            ));
        }
        Ok(Self {
            zone_path,
            tombstone_path,
            armed: false,
        })
    }

    /// True iff `{zone_id}/.removed` exists. Startup sees this and runs
    /// `cleanup_tombstoned` instead of opening.
    pub fn has_tombstone(base: &Path, zone_id: &str) -> bool {
        base.join(zone_id).join(TOMBSTONE_NAME).exists()
    }

    pub fn raft_path(&self) -> PathBuf {
        self.zone_path.join("raft")
    }

    pub fn sm_path(&self) -> PathBuf {
        self.zone_path.join("sm")
    }

    pub fn zone_path(&self) -> &Path {
        &self.zone_path
    }

    /// Disarm rollback. Call after the zone is fully registered in the
    /// in-memory map. Any error thereafter is a runtime error, not a
    /// setup-rollback scenario.
    pub fn commit(&mut self) {
        self.armed = false;
    }

    /// Write the tombstone. Must be called before tearing down the raft
    /// group — it is the single observable commit point of "this zone is
    /// being removed". Any crash between `write_tombstone` and `destroy`
    /// leaves a tombstoned dir that startup deterministically cleans up.
    ///
    /// Written atomically via `fs::write` on a zero-byte file. A crash
    /// during the write leaves the file missing; caller re-tries from
    /// the beginning of `remove_zone`.
    pub fn write_tombstone(&self) -> io::Result<()> {
        std::fs::write(&self.tombstone_path, b"")?;
        Ok(())
    }

    /// Write the tombstone with a deletion epoch (R12) — the deprovision
    /// path. A replica that missed the peer fan-out compares this epoch
    /// against its own `.creation-epoch` at boot and destroys itself
    /// instead of resurrecting the deleted zone.
    pub fn write_tombstone_with_epoch(&self, record: &DeletionRecord) -> io::Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("deletion record encode: {e}"),
            )
        })?;
        std::fs::write(&self.tombstone_path, bytes)?;
        Ok(())
    }

    /// Read a zone's tombstone record, if a tombstone exists. Zero-byte
    /// (legacy) or unparsable files read back as `deletion_epoch == 0` —
    /// never an error: cleanup decisions key off the tombstone's
    /// EXISTENCE; the epoch only refines "was this replica stale?".
    pub fn read_tombstone(base: &Path, zone_id: &str) -> Option<DeletionRecord> {
        let path = base.join(zone_id).join(TOMBSTONE_NAME);
        let bytes = std::fs::read(path).ok()?;
        Some(serde_json::from_slice(&bytes).unwrap_or(DeletionRecord {
            version: 0,
            zone_id: zone_id.to_string(),
            deletion_epoch: 0,
            deleted_at_ms: 0,
            initiated_by_node: 0,
        }))
    }

    /// Record when this local replica was created (wall-clock ms) — the
    /// boot resurrection check's comparison point. Best-effort by design:
    /// an unreadable/missing epoch reads as 0, which makes the check
    /// conservative (a stale copy with epoch 0 is cleaned only by the
    /// tombstone/60s-window paths, never resurrected as authoritative).
    pub fn write_creation_epoch(&self, epoch_ms: u64) -> io::Result<()> {
        std::fs::write(
            self.zone_path.join(CREATION_EPOCH_NAME),
            epoch_ms.to_string(),
        )?;
        Ok(())
    }

    /// Read a zone dir's creation epoch, if present. `None` = no marker
    /// (pre-R12 dir or write failed) — callers treat it as epoch 0.
    pub fn read_creation_epoch(base: &Path, zone_id: &str) -> Option<u64> {
        std::fs::read_to_string(base.join(zone_id).join(CREATION_EPOCH_NAME))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Delete the zone dir. Caller MUST have released all handles to
    /// files inside (redb snapshots, raft storage, etc.) — consumes self
    /// so the type system prevents use-after-destroy.
    pub fn destroy(mut self) -> io::Result<()> {
        self.armed = false; // disarm before the explicit rmdir
        if self.zone_path.exists() {
            std::fs::remove_dir_all(&self.zone_path)?;
        }
        Ok(())
    }

    /// Best-effort cleanup of a zone dir that still has a tombstone after
    /// restart. Called from `open_existing_zones_from_disk`.
    pub fn cleanup_tombstoned(base: &Path, zone_id: &str) -> io::Result<()> {
        let zone_path = base.join(zone_id);
        if zone_path.exists() {
            std::fs::remove_dir_all(&zone_path)?;
        }
        Ok(())
    }
}

impl Drop for ZonePersistence {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.zone_path);
            tracing::warn!(
                zone_path = %self.zone_path.display(),
                "ZonePersistence dropped while armed — rolled back partial zone dir",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_then_commit_leaves_dir() {
        let tmp = TempDir::new().unwrap();
        {
            let mut p = ZonePersistence::create(tmp.path(), "z1").unwrap();
            p.commit();
        }
        assert!(tmp.path().join("z1").exists());
    }

    #[test]
    fn test_create_without_commit_rolls_back() {
        let tmp = TempDir::new().unwrap();
        {
            let _p = ZonePersistence::create(tmp.path(), "z1").unwrap();
            // drop without commit
        }
        assert!(!tmp.path().join("z1").exists());
    }

    #[test]
    fn test_create_existing_errors() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("z1")).unwrap();
        let err = ZonePersistence::create(tmp.path(), "z1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn test_open_nonexistent_errors() {
        let tmp = TempDir::new().unwrap();
        let err = ZonePersistence::open(tmp.path(), "z1").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_tombstone_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut p = ZonePersistence::create(tmp.path(), "z1").unwrap();
        p.commit();
        assert!(!ZonePersistence::has_tombstone(tmp.path(), "z1"));
        p.write_tombstone().unwrap();
        assert!(ZonePersistence::has_tombstone(tmp.path(), "z1"));
    }

    #[test]
    fn test_destroy_removes_dir() {
        let tmp = TempDir::new().unwrap();
        let mut p = ZonePersistence::create(tmp.path(), "z1").unwrap();
        p.commit();
        // Drop some content inside to exercise recursive remove.
        std::fs::write(tmp.path().join("z1").join("marker"), b"x").unwrap();
        p.destroy().unwrap();
        assert!(!tmp.path().join("z1").exists());
    }

    #[test]
    fn test_cleanup_tombstoned_removes_dir() {
        let tmp = TempDir::new().unwrap();
        let zone_path = tmp.path().join("z1");
        std::fs::create_dir_all(&zone_path).unwrap();
        std::fs::write(zone_path.join(TOMBSTONE_NAME), b"").unwrap();
        std::fs::write(zone_path.join("some-data"), b"x").unwrap();
        ZonePersistence::cleanup_tombstoned(tmp.path(), "z1").unwrap();
        assert!(!zone_path.exists());
    }

    #[test]
    fn test_epoch_tombstone_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut p = ZonePersistence::create(tmp.path(), "z1").unwrap();
        p.commit();
        p.write_creation_epoch(1_700_000_000_000).unwrap();
        assert_eq!(
            ZonePersistence::read_creation_epoch(tmp.path(), "z1"),
            Some(1_700_000_000_000)
        );
        let rec = DeletionRecord {
            version: 1,
            zone_id: "z1".into(),
            deletion_epoch: 1_700_000_000_001,
            deleted_at_ms: 1_700_000_000_001,
            initiated_by_node: 7,
        };
        p.write_tombstone_with_epoch(&rec).unwrap();
        assert_eq!(ZonePersistence::read_tombstone(tmp.path(), "z1"), Some(rec));
    }

    #[test]
    fn test_legacy_empty_tombstone_reads_as_epoch_zero() {
        let tmp = TempDir::new().unwrap();
        let mut p = ZonePersistence::create(tmp.path(), "z1").unwrap();
        p.commit();
        p.write_tombstone().unwrap(); // legacy zero-byte
        let rec = ZonePersistence::read_tombstone(tmp.path(), "z1").expect("tombstone exists");
        assert_eq!(rec.deletion_epoch, 0);
    }

    #[test]
    fn test_missing_tombstone_and_epoch_read_none() {
        let tmp = TempDir::new().unwrap();
        assert!(ZonePersistence::read_tombstone(tmp.path(), "z1").is_none());
        assert_eq!(ZonePersistence::read_creation_epoch(tmp.path(), "z1"), None);
    }

    #[test]
    fn test_open_does_not_rollback_on_drop() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("z1")).unwrap();
        {
            let _p = ZonePersistence::open(tmp.path(), "z1").unwrap();
            // drop — must NOT remove the dir (not armed).
        }
        assert!(tmp.path().join("z1").exists());
    }
}
