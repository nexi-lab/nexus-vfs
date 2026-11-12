//! Local-only serving of content already admitted by the peer transport.

use crate::core::stream::wal::wal_stream_prefix;
use crate::federation::ColdSegmentAddress;
use crate::meta_store::{DT_REG, DT_STREAM};

use super::{Kernel, OperationContext, StreamAddress};

const UNAVAILABLE: &str = "zone content is unavailable";

impl Kernel {
    /// Serve one zone's logical file or indexed cold segment from a captured
    /// metadata/backend pair. This never fans out, follows a link, contacts a
    /// peer, or discovers an object by a cluster-wide hash. Transport admission
    /// must establish the requesting node's data-zone authority first.
    pub fn read_local_zone_content(&self, zone: &str, content: &str) -> Result<Vec<u8>, String> {
        contracts::validate_zone_id_for(contracts::ZoneIdUse::ExistingRef, zone)
            .map_err(|_| UNAVAILABLE)?;
        let segment_read = ColdSegmentAddress::parse_read(zone, content)?;
        let segment = segment_read.as_ref().map(|read| &read.address);
        let path = segment.map_or(content, |address| address.stream_path);
        contracts::validate_zone_path(path).map_err(|_| UNAVAILABLE)?;

        let mut projections = self.vfs_router.project_zone_path(zone, path);
        projections.sort();
        for (lookup_zone, visible) in projections {
            let Some(route) = self.vfs_router.route(&visible, &lookup_zone) else {
                continue;
            };
            let address = StreamAddress::from_route(&visible, &lookup_zone, Some(&route));
            if address.zone != zone || address.path != path {
                continue;
            }
            // A different zone cannot borrow the root's global metadata slot.
            if route.metastore.is_none() && zone != contracts::ROOT_ZONE_ID {
                return Err(UNAVAILABLE.into());
            }
            let route = self.capture_metastore_route(route);
            self.check_unscoped_content_io(&visible, &route)
                .map_err(|error| error.to_string())?;
            let store = route.metastore.as_ref().ok_or(UNAVAILABLE)?;
            let metadata = store.get(&visible).map_err(|_| UNAVAILABLE)?;
            let ctx = OperationContext::new("system", zone, true, None, true);

            let mut local_origin = metadata
                .as_ref()
                .and_then(|entry| entry.last_writer_address.clone());
            let object = if let Some(segment) = segment {
                if metadata
                    .as_ref()
                    .is_none_or(|entry| entry.entry_type != DT_STREAM)
                {
                    return Err(UNAVAILABLE.into());
                }
                let entry = store
                    .find_stream_segment(&wal_stream_prefix(path), segment.base)
                    .map_err(|_| UNAVAILABLE)?
                    .filter(|entry| {
                        entry.base == segment.base
                            && segment_read
                                .as_ref()
                                .is_some_and(|read| read.matches_content_id(&entry.content_id))
                    })
                    .ok_or(UNAVAILABLE)?;
                local_origin = Some(entry.origin);
                entry.content_id
            } else {
                match metadata.as_ref() {
                    Some(entry) if entry.entry_type == DT_REG => entry
                        .content_id
                        .clone()
                        .filter(|id| !id.is_empty())
                        .ok_or(UNAVAILABLE)?,
                    Some(_) => return Err(UNAVAILABLE.into()),
                    // PAS discovery uses only this captured backend. CAS never
                    // interprets a file path as permission to read a raw hash.
                    None if !route.is_cas => route.backend_path.clone(),
                    None => return Err(UNAVAILABLE.into()),
                }
            };
            let backend = route
                .backend
                .clone()
                .or_else(|| {
                    route.target_zone_id.as_ref()?;
                    // The placeholder's local writer uses the federation cache;
                    // another writer's cache is never a local content authority.
                    let writer = local_origin.as_deref()?;
                    let own = self.self_address.read();
                    (own.as_deref() == Some(writer))
                        .then(|| self.federation_cache_arc())
                        .flatten()
                })
                .ok_or(UNAVAILABLE)?;
            let bytes = backend
                .read_content(&object, &ctx)
                .map_err(|_| UNAVAILABLE)?;
            if segment.is_none() && metadata.is_none() {
                let mut observed = ctx;
                observed.propagates_cross_node = true;
                self.observe_backend_content_in_store(
                    &visible,
                    bytes.len() as u64,
                    Some(object),
                    zone,
                    &observed,
                    store.as_ref(),
                );
            }
            return Ok(bytes);
        }
        Err(UNAVAILABLE.into())
    }
}
