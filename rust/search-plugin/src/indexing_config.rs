//! Serialized transactions for durable directory and indexing-mode facts.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::index_manager::IndexManager;

const DIRECTORIES_FILE: &str = "indexed_dirs.json";
const MODES_FILE: &str = "zone_modes.json";

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct Version(u32);

impl Default for Version {
    fn default() -> Self {
        Self(1)
    }
}

impl Version {
    fn check(&self) -> Result<(), StoreError> {
        if self.0 == 1 {
            Ok(())
        } else {
            Err(StoreError::Version(self.0))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Directory {
    pub path: String,
    pub added_at_ms: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct DirectoryFile {
    #[serde(default)]
    version: Version,
    #[serde(default)]
    entries: Vec<Directory>,
}

#[derive(Default, Serialize, Deserialize)]
struct ModesFile {
    #[serde(default)]
    version: Version,
    #[serde(default)]
    modes: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("index configuration I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid index configuration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported index configuration version {0}")]
    Version(u32),
    #[error("invalid indexing mode {0:?}; must be on, off or sandbox")]
    InvalidMode(String),
}

/// One owner per Search service; its clones share the same transaction lock.
/// Each operation reads committed files. No configuration cache or request
/// state is persisted, and search queries never acquire this lock.
pub(crate) struct IndexingConfigStore {
    manager: Arc<IndexManager>,
    transactions: Mutex<()>,
}

impl IndexingConfigStore {
    pub fn new(manager: Arc<IndexManager>) -> Self {
        Self {
            manager,
            transactions: Mutex::new(()),
        }
    }

    fn read_directories(&self, zone: &str) -> Result<BTreeMap<String, Directory>, StoreError> {
        let stored: DirectoryFile =
            read_json(&self.manager.zone_root(zone).join(DIRECTORIES_FILE))?;
        stored.version.check()?;
        Ok(stored
            .entries
            .into_iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect())
    }

    fn write_directories(
        &self,
        zone: &str,
        entries: BTreeMap<String, Directory>,
    ) -> Result<(), StoreError> {
        write_json(
            &self.manager.zone_root(zone).join(DIRECTORIES_FILE),
            &DirectoryFile {
                version: Version::default(),
                entries: entries.into_values().collect(),
            },
        )
    }

    pub fn add_directory(&self, zone: &str, path: &str, now_ms: i64) -> Result<bool, StoreError> {
        let _transaction = self.transactions.lock();
        let mut entries = self.read_directories(zone)?;
        if entries.contains_key(path) {
            return Ok(false);
        }
        entries.insert(
            path.to_owned(),
            Directory {
                path: path.to_owned(),
                added_at_ms: now_ms,
            },
        );
        self.write_directories(zone, entries)?;
        Ok(true)
    }

    pub fn remove_directory(&self, zone: &str, path: &str) -> Result<bool, StoreError> {
        let _transaction = self.transactions.lock();
        let mut entries = self.read_directories(zone)?;
        if entries.remove(path).is_none() {
            return Ok(false);
        }
        self.write_directories(zone, entries)?;
        Ok(true)
    }

    pub fn list_directories(&self, zone: &str) -> Result<Vec<Directory>, StoreError> {
        let _transaction = self.transactions.lock();
        let mut entries: Vec<_> = self.read_directories(zone)?.into_values().collect();
        entries.sort_by(|left, right| {
            left.added_at_ms
                .cmp(&right.added_at_ms)
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok(entries)
    }

    fn read_modes(&self) -> Result<ModesFile, StoreError> {
        let stored: ModesFile = read_json(&self.manager.root().join(MODES_FILE))?;
        stored.version.check()?;
        for mode in stored.modes.values() {
            validate_mode(mode)?;
        }
        Ok(stored)
    }

    pub fn set_mode(&self, zone: &str, mode: &str) -> Result<(), StoreError> {
        let mode = if mode.is_empty() { "on" } else { mode };
        validate_mode(mode)?;
        let _transaction = self.transactions.lock();
        let mut stored = self.read_modes()?;
        if stored
            .modes
            .get(zone)
            .is_some_and(|existing| existing == mode)
        {
            return Ok(());
        }
        stored.modes.insert(zone.to_owned(), mode.to_owned());
        write_json(&self.manager.root().join(MODES_FILE), &stored)
    }

    pub fn list_modes(&self) -> Result<Vec<(String, String)>, StoreError> {
        let _transaction = self.transactions.lock();
        Ok(self.read_modes()?.modes.into_iter().collect())
    }
}

fn validate_mode(mode: &str) -> Result<(), StoreError> {
    if matches!(mode, "on" | "off" | "sandbox") {
        Ok(())
    } else {
        Err(StoreError::InvalidMode(mode.to_owned()))
    }
}

fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T, StoreError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error.into()),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let parent = path.parent().expect("configuration path has a parent");
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    let result = (|| -> Result<(), StoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn store(root: &Path) -> IndexingConfigStore {
        IndexingConfigStore::new(Arc::new(IndexManager::with_root(root.to_owned())))
    }

    #[test]
    fn reads_existing_v1_facts_and_keeps_idempotent_timestamps() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("team")).unwrap();
        std::fs::write(
            root.path().join("team/indexed_dirs.json"),
            r#"{"version":1,"entries":[{"path":"/docs","added_at_ms":7}]}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join(MODES_FILE),
            r#"{"version":1,"modes":{"team":"sandbox"}}"#,
        )
        .unwrap();
        let config = store(root.path());
        assert!(!config.add_directory("team", "/docs", 99).unwrap());
        assert_eq!(config.list_directories("team").unwrap()[0].added_at_ms, 7);
        assert_eq!(
            config.list_modes().unwrap(),
            [("team".into(), "sandbox".into())]
        );
        config.set_mode("team", "").unwrap();
        assert_eq!(
            store(root.path()).list_modes().unwrap(),
            [("team".into(), "on".into())]
        );
        assert!(config.remove_directory("team", "/docs").unwrap());
        assert!(!config.remove_directory("team", "/docs").unwrap());
        assert!(store(root.path())
            .list_directories("team")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn concurrent_updates_preserve_every_acknowledged_fact_after_reopen() {
        let root = tempfile::tempdir().unwrap();
        let config = Arc::new(store(root.path()));
        let barrier = Arc::new(Barrier::new(32));
        let threads: Vec<_> = (0..32)
            .map(|number| {
                let config = Arc::clone(&config);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    config.set_mode(&format!("zone-{number}"), "off").unwrap();
                    assert!(config
                        .add_directory("team", &format!("/docs/{number}"), number)
                        .unwrap());
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let reopened = store(root.path());
        let modes = reopened.list_modes().unwrap();
        let directories = reopened.list_directories("team").unwrap();
        assert_eq!(modes.len(), 32);
        assert_eq!(directories.len(), 32);
        for number in 0..32 {
            assert!(modes.contains(&(format!("zone-{number}"), "off".to_owned())));
            assert!(directories.contains(&Directory {
                path: format!("/docs/{number}"),
                added_at_ms: number,
            }));
        }
    }

    #[test]
    fn rejected_and_failed_writes_leave_committed_facts_visible() {
        let root = tempfile::tempdir().unwrap();
        let config = store(root.path());
        config.set_mode("team", "on").unwrap();
        assert!(config.set_mode("team", "invalid").is_err());
        std::fs::create_dir(root.path().join("zone_modes.json.tmp")).unwrap();
        assert!(config.set_mode("team", "off").is_err());
        assert_eq!(config.list_modes().unwrap(), [("team".into(), "on".into())]);
        assert_eq!(
            store(root.path()).list_modes().unwrap(),
            [("team".into(), "on".into())]
        );
    }

    #[test]
    fn corrupt_or_unknown_version_configuration_is_reported_without_overwriting() {
        let root = tempfile::tempdir().unwrap();
        let config = store(root.path());
        for bytes in [
            r#"{"version":9,"modes":{}}"#,
            r#"{"version":1,"modes":{"team":"invalid"}}"#,
            "invalid JSON",
        ] {
            std::fs::write(root.path().join(MODES_FILE), bytes).unwrap();
            assert!(config.list_modes().is_err());
            assert!(config.set_mode("team", "on").is_err());
            assert_eq!(
                std::fs::read_to_string(root.path().join(MODES_FILE)).unwrap(),
                bytes
            );
        }
    }
}
