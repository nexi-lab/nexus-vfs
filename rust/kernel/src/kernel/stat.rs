//! Metadata observation for point and grouped Stat calls.
use super::syscall_impl::{has_local_content_origin, reference_file_metadata};
use super::{validate_path_fast, Kernel, KernelError, StatResult};
use crate::abc::meta_store::{
    FileMetadata, MetaStore, MetaStoreError, StatLookup, DT_DIR, DT_MOUNT, DT_REG, DT_STREAM,
};
use crate::abc::object_store::StorageError;
use crate::vfs_router::RouteResult;
use std::io;

fn observe_io<T>(observation: io::Result<T>) -> Result<Option<T>, KernelError> {
    match observation {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            Err(KernelError::PermissionDenied(e.to_string()))
        }
        Err(e) => Err(KernelError::BackendError(e.to_string())),
    }
}
fn store_error(e: MetaStoreError) -> KernelError {
    KernelError::from_metastore(&e, e.to_string())
}

fn apply_reference_metadata(
    stat: &mut StatResult,
    metadata: crate::abc::object_store::ReferenceMetadata,
) {
    stat.size = metadata.size;
    stat.mode = metadata.mode;
    stat.is_directory = metadata.is_dir;
    stat.entry_type = if metadata.is_dir { DT_DIR } else { DT_REG };
    if metadata.is_dir {
        stat.mime_type = "inode/directory".to_string();
    }
    stat.modified_at_ms = metadata.modified_at_ms;
}

impl Kernel {
    /// Compatibility view for callers that can only represent an optional observation.
    pub fn sys_stat(&self, path: &str, zone: &str) -> Option<StatResult> {
        self.try_stat(path, zone).ok().flatten()
    }

    fn stat_target(&self, path: &str, zone: &str) -> Result<StatTarget, KernelError> {
        validate_path_fast(path)?;
        if self.trie.lookup(path).is_some() {
            return Ok(StatTarget::Observed(None));
        }
        if let Some(stat) = self.zones_view_stat(path) {
            return Ok(StatTarget::Observed(Some(stat)));
        }
        let Some(route) = self.vfs_router.route(path, zone) else {
            return self.unmounted_stat(path).map(StatTarget::Observed);
        };
        let route = self.capture_metastore_route(route);
        if route.backend_path.is_empty() {
            return Ok(StatTarget::Observed(Some(directory(
                path, &route, DT_MOUNT,
            ))));
        }
        Ok(StatTarget::Mount(route))
    }

    pub fn try_stat(&self, path: &str, zone: &str) -> Result<Option<StatResult>, KernelError> {
        self.observe_stat(path, zone, true)
    }

    /// A peer probe observes this host without forwarding to another peer.
    pub fn stat_for_peer(&self, path: &str, zone: &str) -> Result<Option<StatResult>, KernelError> {
        self.observe_stat(path, zone, false)
    }

    fn observe_stat(
        &self,
        path: &str,
        zone: &str,
        fan_out: bool,
    ) -> Result<Option<StatResult>, KernelError> {
        let route = match self.stat_target(path, zone)? {
            StatTarget::Observed(result) => return Ok(result),
            StatTarget::Mount(route) => route,
        };
        let lookup = if let Some(store) = route.metastore.as_ref() {
            if let Some(entry) = store.get(path).map_err(store_error)? {
                return self.stat_from_metadata(path, zone, route, entry);
            }
            resolve_miss(store.as_ref(), path)?
        } else {
            StatLookup::Missing
        };
        self.finish_stat(path, zone, route, lookup, fan_out)
    }

    pub fn try_stat_batch(
        &self,
        paths: &[String],
        zone: &str,
    ) -> Result<Vec<Option<StatResult>>, KernelError> {
        use std::borrow::Cow;
        use std::collections::BTreeMap;
        let mut results: Vec<_> = (0..paths.len()).map(|_| None).collect();
        let mut groups = BTreeMap::new();
        for (index, path) in paths.iter().enumerate() {
            match self.stat_target(path, zone)? {
                StatTarget::Observed(result) => results[index] = result,
                StatTarget::Mount(route) => {
                    let Some(store) = route.metastore.clone() else {
                        results[index] =
                            self.finish_stat(path, zone, route, StatLookup::Missing, true)?;
                        continue;
                    };
                    let group = groups
                        .entry(std::sync::Arc::as_ptr(&store) as *const () as usize)
                        .or_insert_with(|| (store, Vec::new()));
                    group.1.push((index, route));
                }
            }
        }
        for (_, (store, group)) in groups {
            let keys = if group.len() == paths.len() {
                Cow::Borrowed(paths)
            } else {
                Cow::Owned(group.iter().map(|(i, _)| paths[*i].clone()).collect())
            };
            let rows = store.get_batch(&keys).map_err(store_error)?;
            if rows.len() != group.len() {
                return Err(incomplete());
            }
            let mut misses = Vec::new();
            for ((i, route), row) in group.into_iter().zip(rows) {
                match row {
                    Some(entry) => {
                        results[i] = self.stat_from_metadata(&paths[i], zone, route, entry)?
                    }
                    None => misses.push((i, route)),
                }
            }
            if misses.is_empty() {
                continue;
            }
            let keys: Vec<_> = misses.iter().map(|(i, _)| paths[*i].as_str()).collect();
            let observations = store.resolve_stat_misses(&keys).map_err(store_error)?;
            if observations.len() != misses.len() {
                return Err(incomplete());
            }
            for ((i, route), lookup) in misses.into_iter().zip(observations) {
                results[i] = self.finish_stat(&paths[i], zone, route, lookup, true)?;
            }
        }
        Ok(results)
    }

    fn unmounted_stat(&self, path: &str) -> Result<Option<StatResult>, KernelError> {
        let store = self.metastore.read().clone();
        let Some(store) = store else { return Ok(None) };
        if let Some(entry) = store.get(path).map_err(store_error)? {
            return Ok(Some(entry.into()));
        }
        Ok(match resolve_miss(store.as_ref(), path)? {
            StatLookup::Entry(entry) => Some((*entry).into()),
            // Outside the mount table only explicit global records are addressable.
            StatLookup::Directory | StatLookup::Missing => None,
        })
    }

    fn finish_stat(
        &self,
        path: &str,
        zone: &str,
        route: RouteResult,
        lookup: StatLookup,
        fan_out: bool,
    ) -> Result<Option<StatResult>, KernelError> {
        if let StatLookup::Entry(entry) = lookup {
            return self.stat_from_metadata(path, zone, route, *entry);
        }
        if let Some(result) = route
            .backend
            .as_ref()
            .and_then(|b| b.reference_metadata(&route.backend_path))
        {
            if let Some(attrs) = observe_io(result)? {
                let mut stat = StatResult::from(FileMetadata {
                    path: path.into(),
                    zone_id: Some(route.zone_id.clone()),
                    ..Default::default()
                });
                apply_reference_metadata(&mut stat, attrs);
                return Ok(Some(stat));
            }
        }
        if matches!(lookup, StatLookup::Directory) {
            return Ok(Some(directory(path, &route, DT_DIR)));
        }
        let local = match route.backend.as_ref().map(|b| b.stat(&route.backend_path)) {
            Some(Ok(attrs)) => Some(attrs),
            Some(Err(StorageError::IOError(e))) => observe_io(Err(e))?,
            Some(Err(StorageError::NotFound(_) | StorageError::NotSupported(_))) | None => None,
        };
        let attrs = match local {
            Some(v) => Some(v),
            None if fan_out => route.via_federation_stat(self, path)?,
            None => None,
        };
        Ok(attrs.map(|attrs| {
            StatResult::from(FileMetadata {
                path: path.into(),
                zone_id: Some(route.zone_id),
                size: if attrs.is_dir { 4096 } else { attrs.size },
                entry_type: if attrs.is_dir { DT_DIR } else { DT_REG },
                ..Default::default()
            })
        }))
    }
    /// Resolve live stat fields from an already-read inode for point and batch reads.
    fn stat_from_metadata(
        &self,
        path: &str,
        zone_id: &str,
        route: crate::vfs_router::RouteResult,
        entry: FileMetadata,
    ) -> Result<Option<StatResult>, KernelError> {
        // A replicated inode can name another node's bytes. That node's
        // durable metadata remains authoritative over this node's filesystem.
        let reference =
            reference_file_metadata(&route, &entry, self.self_address.read().as_deref());
        if let Some(observation) = reference {
            let Some(metadata) = observe_io(observation)? else {
                return Ok(None);
            };
            let mut stat = StatResult::from(entry);
            stat.lock = self.advisory_lock_info(path, zone_id);
            apply_reference_metadata(&mut stat, metadata);
            return Ok(Some(stat));
        }
        // Virtual directory inodes may exist without a native directory. When
        // there is one, report its real permissions without persisting a copy.
        if entry.entry_type == DT_DIR
            && has_local_content_origin(&entry, self.self_address.read().as_deref())
        {
            if let Some(metadata) = route
                .backend
                .as_ref()
                .and_then(|b| b.reference_metadata(&route.backend_path))
                .map(observe_io)
                .transpose()?
                .flatten()
                .filter(|m| m.is_dir)
            {
                let mut stat = StatResult::from(entry);
                stat.lock = self.advisory_lock_info(path, zone_id);
                apply_reference_metadata(&mut stat, metadata);
                return Ok(Some(stat));
            }
        }

        let mut stat = StatResult::from(entry);
        if stat.path != path {
            stat.path = path.to_owned();
        }
        stat.lock = self.advisory_lock_info(path, zone_id);
        if stat.entry_type == DT_STREAM {
            let key = super::StreamAddress::from_route(path, zone_id, Some(&route)).key();
            if let Some(tail) = self.stream_manager.tail(&key) {
                stat.size = tail as u64;
            }
            stat.modified_at_ms = self
                .stream_manager
                .last_append_ms(&key)
                .or(stat.modified_at_ms);
        }
        Ok(Some(stat))
    }
}

enum StatTarget {
    Observed(Option<StatResult>),
    Mount(RouteResult),
}

fn directory(path: &str, route: &RouteResult, kind: u8) -> StatResult {
    StatResult::from(FileMetadata {
        path: path.into(),
        zone_id: Some(route.zone_id.clone()),
        entry_type: kind,
        version: u32::from(kind == DT_MOUNT),
        ..Default::default()
    })
}
fn resolve_miss(store: &dyn MetaStore, path: &str) -> Result<StatLookup, KernelError> {
    let mut results = store.resolve_stat_misses(&[path]).map_err(store_error)?;
    if results.len() != 1 {
        return Err(incomplete());
    }
    results.pop().ok_or_else(incomplete)
}

fn incomplete() -> KernelError {
    KernelError::IOError("incomplete metastore Stat response".into())
}
