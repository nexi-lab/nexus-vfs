//! Stream identity is the owning zone and its path, independent of mount spelling.

use crate::core::vfs_router::RouteResult;
use crate::meta_store::DT_STREAM;

use super::{validate_path_fast, Kernel, KernelError, OperationContext};

pub(crate) struct StreamAddress {
    pub zone: String,
    pub path: String,
}

impl StreamAddress {
    pub fn from_route(path: &str, zone: &str, route: Option<&RouteResult>) -> Self {
        match route {
            Some(route) => Self {
                zone: route.zone_id.clone(),
                path: if route.target_zone_id.is_some() {
                    format!("/{}", route.backend_path.trim_start_matches('/'))
                } else {
                    path.to_owned()
                },
            },
            None => Self {
                zone: zone.to_owned(),
                path: path.to_owned(),
            },
        }
    }

    /// An in-memory registry key, never a VFS path or persisted WAL key.
    /// Root retains plain paths for local IPC producers. NUL is forbidden in
    /// user paths, so a non-root zone cannot collide with a root stream.
    pub fn key(&self) -> String {
        if self.zone == contracts::ROOT_ZONE_ID {
            self.path.clone()
        } else {
            format!("{}\0{}", self.zone, self.path)
        }
    }

    pub fn from_key(key: &str) -> Self {
        let (zone, path) = key
            .split_once('\0')
            .unwrap_or((contracts::ROOT_ZONE_ID, key));
        Self {
            zone: zone.to_owned(),
            path: path.to_owned(),
        }
    }
}

impl Kernel {
    pub(super) fn stream_address(&self, path: &str, zone: &str) -> StreamAddress {
        StreamAddress::from_route(path, zone, self.vfs_router.route(path, zone).as_ref())
    }

    /// Resolve links using the existing one-hop contract. The caller's gate
    /// runs on every link spelling and on the backing path in its owning zone.
    pub(super) fn resolve_stream_address(
        &self,
        path: &str,
        ctx: &OperationContext,
        mut gate: impl FnMut(&str, Option<&RouteResult>, &OperationContext) -> Result<(), KernelError>,
    ) -> Result<StreamAddress, KernelError> {
        let mut path = path.to_owned();
        for hops in 0..=1 {
            validate_path_fast(&path)?;
            let route = self.vfs_router.route(&path, &ctx.zone_id);
            gate(&path, route.as_ref(), ctx)?;
            let target = self.directory_link_target(&path, &ctx.zone_id)?;
            let target = match target {
                Some(target) => Some(target),
                None => {
                    let entry = match route.as_ref() {
                        Some(route) => self
                            .with_metastore_route(route, |ms| ms.get(&path))
                            .transpose()
                            .map_err(|e| KernelError::IOError(format!("stream metadata: {e:?}")))?
                            .flatten(),
                        None => self.metastore_get(&path).ok().flatten(),
                    };
                    match entry {
                        Some(entry) => Self::dt_link_target(&path, &entry)?.map(str::to_owned),
                        None => None,
                    }
                }
            };
            if let Some(target) = target {
                if hops == 1 {
                    return Err(KernelError::PermissionDenied(format!(
                        "DT_LINK chain rejected (ELOOP) at {path}"
                    )));
                }
                path = target;
                continue;
            }
            let address = StreamAddress::from_route(&path, &ctx.zone_id, route.as_ref());
            if address.path != path || address.zone != ctx.zone_id {
                let mut target_ctx = ctx.clone();
                target_ctx.zone_id = address.zone.clone();
                gate(&address.path, route.as_ref(), &target_ctx)?;
            }
            return Ok(address);
        }
        unreachable!("link hop limit returns above")
    }

    pub(super) fn materialize_stream(
        &self,
        key: &str,
    ) -> Result<Option<std::sync::Arc<dyn crate::stream::StreamBackend>>, String> {
        let address = StreamAddress::from_key(key);
        for (zone, path) in self
            .vfs_router
            .project_zone_path(&address.zone, &address.path)
        {
            let Some(route) = self.vfs_router.route(&path, &zone) else {
                continue;
            };
            if StreamAddress::from_route(&path, &zone, Some(&route)).key() != key {
                continue;
            }
            let meta = self
                .with_metastore_route(&route, |ms| ms.get(&path))
                .transpose()
                .map_err(|e| e.to_string())?
                .flatten();
            if let Some(meta) = meta.filter(|meta| meta.entry_type == DT_STREAM) {
                return self
                    .wal_backend_for(&address, meta.size)
                    .map_err(|e| format!("{e:?}"));
            }
        }
        Ok(None)
    }
}
