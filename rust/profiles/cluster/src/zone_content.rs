//! Compose zone-owned CAS content with the same zone's authoritative metadata.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use backends::storage::zone_cas_local::ZoneCasLocal;
use kernel::core::stream::wal::wal_stream_prefix;
use kernel::federation::ColdSegmentAddress;
use kernel::meta_store::{MetaStore, DT_REG, DT_STREAM};
use nexus_raft::blob_fetcher::BlobFetcher;
use nexus_raft::zone_meta_store::ZoneMetaStore;
use nexus_raft::ZoneHandle;

const UNAVAILABLE: &str = "zone content is unavailable";

struct ZoneContentBinding {
    objects: Arc<ZoneCasLocal>,
    metadata: Arc<ZoneMetaStore>,
}

impl ZoneContentBinding {
    fn check_unscoped_io(&self, path: &str) -> Result<(), &'static str> {
        if let Some(records) = self.metadata.as_guarded_records() {
            records
                .check_unscoped_io(&records.record_storage_key(path))
                .map_err(|_| UNAVAILABLE)?;
        }
        Ok(())
    }
}

/// The owning runtime binds each admitted zone's metadata and physical store.
/// The cluster-wide reader retains its existing administrator-only surface.
pub struct ZoneContentBlobFetcher {
    cluster: Arc<dyn BlobFetcher>,
    zones: RwLock<HashMap<String, Arc<ZoneContentBinding>>>,
}

impl ZoneContentBlobFetcher {
    pub fn new(cluster: Arc<dyn BlobFetcher>) -> Self {
        Self {
            cluster,
            zones: RwLock::new(HashMap::new()),
        }
    }

    /// Return the same metadata source for the runtime's VFS mount. The runtime
    /// installs both before publishing access to the zone. Rebinding after a
    /// zone restart replaces the old actor reference.
    pub fn bind(
        &self,
        zone: &ZoneHandle,
        objects: Arc<ZoneCasLocal>,
    ) -> Result<Arc<dyn MetaStore>, String> {
        if zone.zone_id() != objects.zone_id() {
            return Err("zone metadata and content namespace differ".into());
        }
        let metadata = Arc::new(ZoneMetaStore::new_with_subtree(
            zone.consensus_node(),
            zone.runtime_handle(),
            "/".into(),
            "/".into(),
        ));
        let binding = ZoneContentBinding {
            objects,
            metadata: Arc::clone(&metadata),
        };
        self.zones
            .write()
            .map_err(|_| UNAVAILABLE.to_string())?
            .insert(zone.zone_id().to_owned(), Arc::new(binding));
        Ok(metadata)
    }

    pub fn unbind(&self, zone_id: &str) -> Result<(), String> {
        self.zones
            .write()
            .map_err(|_| UNAVAILABLE.to_string())?
            .remove(zone_id);
        Ok(())
    }
}

#[tonic::async_trait]
impl BlobFetcher for ZoneContentBlobFetcher {
    async fn read(&self, content_id: &str) -> Result<Vec<u8>, String> {
        self.cluster.read(content_id).await
    }

    async fn read_in_zone(&self, zone_id: &str, content_id: &str) -> Result<Vec<u8>, String> {
        let binding = self
            .zones
            .read()
            .map_err(|_| UNAVAILABLE.to_string())?
            .get(zone_id)
            .cloned()
            .ok_or(UNAVAILABLE)?;
        let content_id = content_id.to_owned();
        let zone_id = zone_id.to_owned();
        tokio::task::spawn_blocking(move || {
            if let Some(read) =
                ColdSegmentAddress::parse_read(&zone_id, &content_id).map_err(|_| UNAVAILABLE)?
            {
                let segment = &read.address;
                binding.check_unscoped_io(segment.stream_path)?;
                binding
                    .metadata
                    .get(segment.stream_path)
                    .map_err(|_| UNAVAILABLE)?
                    .filter(|entry| entry.entry_type == DT_STREAM)
                    .ok_or(UNAVAILABLE)?;
                let entry = binding
                    .metadata
                    .find_stream_segment(&wal_stream_prefix(segment.stream_path), segment.base)
                    .map_err(|_| UNAVAILABLE)?
                    .filter(|entry| {
                        entry.base == segment.base && read.matches_content_id(&entry.content_id)
                    })
                    .ok_or(UNAVAILABLE)?;
                return binding
                    .objects
                    .read_file(&entry.content_id)
                    .map_err(|_| UNAVAILABLE);
            }
            if content_id.starts_with('/') {
                // Read the zone's own metadata; mount aliases and links cannot
                // redirect this request into another zone's private directory.
                binding.check_unscoped_io(&content_id)?;
                let metadata = binding
                    .metadata
                    .get(&content_id)
                    .map_err(|_| UNAVAILABLE)?
                    .filter(|metadata| metadata.entry_type == DT_REG)
                    .ok_or(UNAVAILABLE)?;
                let hash = metadata.content_id.ok_or(UNAVAILABLE)?;
                binding.objects.read_file(&hash).map_err(|_| UNAVAILABLE)
            } else {
                binding
                    .objects
                    .read_blob(&content_id)
                    .map_err(|_| UNAVAILABLE)
            }
        })
        .await
        .map_err(|_| UNAVAILABLE.to_string())?
        .map_err(str::to_owned)
    }
}
