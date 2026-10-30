//! Cache fills are conditional on no apply notification crossing their read.

use std::collections::HashMap;

use super::{KernelFileMetadata, MetaStoreError};

struct State {
    generation: Option<u64>,
    entries: HashMap<String, KernelFileMetadata>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            generation: Some(0),
            entries: HashMap::new(),
        }
    }
}

impl State {
    fn advance_generation(&mut self) -> bool {
        self.generation = self
            .generation
            .and_then(|generation| generation.checked_add(1));
        if self.generation.is_none() {
            self.entries.clear();
            false
        } else {
            true
        }
    }
}

#[derive(Default)]
pub(super) struct MetadataCache {
    state: parking_lot::RwLock<State>,
}

impl MetadataCache {
    pub(super) fn get_or_load(
        &self,
        path: &str,
        load: impl FnOnce() -> Result<Option<KernelFileMetadata>, MetaStoreError>,
    ) -> Result<Option<KernelFileMetadata>, MetaStoreError> {
        self.load(path, true, load)
    }

    pub(super) fn load_uncached(
        &self,
        path: &str,
        load: impl FnOnce() -> Result<Option<KernelFileMetadata>, MetaStoreError>,
    ) -> Result<Option<KernelFileMetadata>, MetaStoreError> {
        self.load(path, false, load)
    }

    fn load(
        &self,
        path: &str,
        use_cached: bool,
        load: impl FnOnce() -> Result<Option<KernelFileMetadata>, MetaStoreError>,
    ) -> Result<Option<KernelFileMetadata>, MetaStoreError> {
        let generation = {
            let state = self.state.read();
            if let Some(value) = state.entries.get(path).filter(|_| use_cached) {
                return Ok(Some(value.clone()));
            }
            state.generation
        };
        // Actor I/O runs outside the cache lock: apply notifications can keep
        // serving the actor while this read waits for its queued snapshot.
        let value = load()?;
        if let Some(value) = &value {
            let mut state = self.state.write();
            if generation.is_some() && state.generation == generation {
                state.entries.insert(path.into(), value.clone());
            }
        }
        Ok(value)
    }

    pub(super) fn invalidate(&self, path: &str) {
        let mut state = self.state.write();
        if state.advance_generation() {
            state.entries.remove(path);
        }
    }

    pub(super) fn invalidate_where(&self, affected: impl Fn(&str) -> bool) {
        let mut state = self.state.write();
        if state.advance_generation() {
            state.entries.retain(|path, _| !affected(path));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    #[test]
    fn dropped_mount_releases_its_cache_while_the_zone_actor_stays_live() {
        let directory = tempfile::tempdir().unwrap();
        let manager = crate::ZoneManager::isolated(directory.path().to_str().unwrap()).unwrap();
        let zone = manager.create_zone("root", vec![]).unwrap();
        let store = super::super::ZoneMetaStore::new(
            zone.consensus_node().clone(),
            manager.runtime_handle(),
            "/view".into(),
        );
        let cache = Arc::downgrade(&store.cache);
        drop(store);
        assert!(
            cache.upgrade().is_none(),
            "the live actor must release the retired mount's cache"
        );
        manager.shutdown();
    }

    #[test]
    fn late_reads_and_write_observations_cannot_refill_an_invalidated_image() {
        for (use_cached, subtree) in [(true, false), (true, true), (false, false), (false, true)] {
            let cache = Arc::new(MetadataCache::default());
            let image = |value: &str| KernelFileMetadata {
                content_id: Some(value.into()),
                ..Default::default()
            };
            cache
                .get_or_load("/neighbor", || Ok(Some(image("unaffected"))))
                .unwrap();
            let (observed_tx, observed_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let reading = Arc::clone(&cache);
            let old_read = std::thread::spawn(move || {
                reading
                    .load("/source", use_cached, || {
                        let old = image("old");
                        observed_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(Some(old))
                    })
                    .unwrap()
            });
            observed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if subtree {
                cache.invalidate_where(|path| path == "/source" || path.starts_with("/source/"));
            } else {
                cache.invalidate("/source");
            }
            cache
                .get_or_load("/source", || Ok(Some(image("new"))))
                .unwrap();
            resume_tx.send(()).unwrap();
            assert_eq!(
                old_read.join().unwrap().unwrap().content_id.as_deref(),
                Some("old")
            );
            let current = cache
                .get_or_load("/source", || panic!("new image must remain cached"))
                .unwrap()
                .unwrap();
            assert_eq!(current.content_id.as_deref(), Some("new"));
            let neighbor = cache
                .get_or_load("/neighbor", || {
                    panic!("unaffected image must remain cached")
                })
                .unwrap()
                .unwrap();
            assert_eq!(neighbor.content_id.as_deref(), Some("unaffected"));
        }
    }
}
