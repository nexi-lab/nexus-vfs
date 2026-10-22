//! Advisory lock syscalls — `sys_lock`, `sys_unlock`, lock listing.
//!
//! Methods stay members of [`Kernel`] via `impl Kernel { ... }` blocks.
//!
//! Advisory locks follow the same mount/zone projection as file metadata.
//! The raft implementation remains behind `DistributedCoordinator::locks_for_zone`;
//! the kernel never names a consensus type or installs one process-wide zone.

use std::sync::Arc;

use contracts::lock_state::Locks;

use super::{validate_path_fast, Kernel, KernelError};
use crate::core::lock::{normalize_path, shared_lock_to_kernel, KernelLockInfo};
use crate::core::vfs_router::{extract_zone_from_canonical, project_zone_key, zone_relative_path};

impl Kernel {
    /// Resolve both the lock domain and the key from one routing result.
    /// Different mount spellings of the same zone subtree must contend; two
    /// subtrees in that zone must not collapse onto the same relative key.
    fn advisory_lock_target(
        &self,
        path: &str,
        lookup_zone: &str,
    ) -> Result<(Arc<dyn Locks>, String), KernelError> {
        validate_path_fast(path)?;
        let path = normalize_path(path);
        let route = self.vfs_router.route(&path, lookup_zone);
        let coordinator = self.distributed_coordinator();
        if !coordinator.is_initialized(self) {
            if route.as_ref().is_some_and(|r| r.target_zone_id.is_some()) {
                return Err(KernelError::IOError(format!(
                    "advisory lock at {path}: the routed zone has no distributed coordinator"
                )));
            }
            return Ok((self.lock_manager.locks_backend(), path.into_owned()));
        }
        let zone = route.as_ref().map_or(lookup_zone, |r| r.zone_id.as_str());
        let key = route.as_ref().map_or_else(
            || path.to_string(),
            |r| {
                if r.target_zone_id.is_some() {
                    format!("/{}", r.backend_path)
                } else {
                    // Plain storage mounts do not change metadata identity.
                    // /work/a and /other/a remain different root-zone keys.
                    path.to_string()
                }
            },
        );
        let backend = coordinator.locks_for_zone(self, zone).map_err(|error| {
            KernelError::IOError(format!("advisory lock in zone {zone}: {error}"))
        })?;
        Ok((backend, key))
    }

    /// Observational reads use the same zone/key as mutations. An unavailable
    /// replicated domain must never be replaced by a node-local lock table.
    pub(crate) fn advisory_lock_info(&self, path: &str, zone: &str) -> Option<KernelLockInfo> {
        let (backend, key) = self.advisory_lock_target(path, zone).ok()?;
        backend.get_lock(&key).map(|mut info| {
            info.path = path.to_string();
            shared_lock_to_kernel(info)
        })
    }

    pub(crate) fn list_advisory_locks(&self, prefix: &str, limit: usize) -> Vec<KernelLockInfo> {
        if limit == 0 {
            return Vec::new();
        }
        let coordinator = self.distributed_coordinator();
        if !coordinator.is_initialized(self) {
            return self.lock_manager.list_locks(prefix, limit);
        }
        let mut visible = std::collections::BTreeMap::new();
        // Query each visible mount in its own key space. Applying `limit`
        // before translating the prefix would let unrelated rows hide a
        // requested lock. Drop the mount-table guard before routing again.
        for canonical in self.vfs_router.canonical_keys() {
            let (lookup_zone, mount) = extract_zone_from_canonical(&canonical);
            if lookup_zone != contracts::ROOT_ZONE_ID {
                continue;
            }
            let Some(entry) = self.vfs_router.get_canonical(&canonical) else {
                continue;
            };
            let target = entry.target_zone_id.clone();
            let subtree = entry.target_subtree.clone();
            drop(entry);
            let zone = target.as_deref().unwrap_or(&lookup_zone);
            let under_mount = mount == "/"
                || prefix == mount
                || prefix
                    .strip_prefix(&mount)
                    .is_some_and(|s| s.starts_with('/'));
            let key_prefix = if under_mount {
                if target.is_some() {
                    format!(
                        "/{}",
                        zone_relative_path(prefix, &mount, subtree.as_deref())
                    )
                } else {
                    prefix.to_string()
                }
            } else if mount.starts_with(prefix) {
                if target.is_some() {
                    subtree.clone().unwrap_or_else(|| "/".to_string())
                } else {
                    mount.clone()
                }
            } else {
                continue;
            };
            let Ok(backend) = coordinator.locks_for_zone(self, zone) else {
                continue;
            };
            let mut requested = limit;
            loop {
                let rows = backend.list_locks(&key_prefix, requested);
                let exhausted = rows.len() < requested;
                let mut matching = std::collections::BTreeSet::new();
                for info in rows {
                    let path = if target.is_some() {
                        let Some(path) =
                            project_zone_key(&mount, subtree.as_deref().unwrap_or("/"), &info.path)
                        else {
                            continue;
                        };
                        path
                    } else {
                        info.path.clone()
                    };
                    if !path.starts_with(prefix) {
                        continue;
                    }
                    // A more-specific mount can shadow an older root-zone row.
                    // Only expose the lock through a spelling that still routes
                    // to this exact domain/key.
                    let Some(route) = self.vfs_router.route(&path, &lookup_zone) else {
                        continue;
                    };
                    let key = if route.target_zone_id.is_some() {
                        format!("/{}", route.backend_path)
                    } else {
                        path.clone()
                    };
                    if route.zone_id != zone || key != info.path {
                        continue;
                    }
                    matching.insert(path.clone());
                    let mut projected = info.clone();
                    projected.path = path.clone();
                    visible.insert(path, shared_lock_to_kernel(projected));
                }
                // More-specific mounts can shadow rows from this domain.
                // Fetch past them rather than returning an incomplete page.
                if exhausted || matching.len() >= limit || requested == usize::MAX {
                    break;
                }
                requested = requested.saturating_mul(2);
            }
        }
        visible.into_values().take(limit).collect()
    }

    // ── Advisory lock primitive ─────────────────────────────────

    /// Acquire or extend an advisory lock.
    ///
    /// `lock_id` empty → try-acquire (returns `Some(new_uuid)` or
    /// `None` on conflict). `lock_id` non-empty → extend TTL
    /// (returns `Some(lock_id)` or `None` if holder not found).
    ///
    /// `max_holders` parametrizes the lock shape: `1` is a mutex,
    /// `> 1` is a counting semaphore.
    pub fn sys_lock(
        &self,
        path: &str,
        lock_id: &str,
        max_holders: u32,
        ttl_secs: u64,
        holder_info: &str,
    ) -> Result<Option<String>, KernelError> {
        let (backend, key) = self.advisory_lock_target(path, contracts::ROOT_ZONE_ID)?;
        let ttl_secs = ttl_secs.min(u32::MAX as u64) as u32;
        if lock_id.is_empty() {
            let generated_id = uuid::Uuid::new_v4().to_string();
            let acquired = backend
                .acquire(&key, &generated_id, max_holders, ttl_secs, holder_info)
                .map_err(|e| KernelError::IOError(format!("sys_lock({path}): {e}")))?;
            Ok(if acquired { Some(generated_id) } else { None })
        } else {
            let extended = backend
                .extend(&key, lock_id, ttl_secs)
                .map_err(|e| KernelError::IOError(format!("sys_lock({path}): {e}")))?;
            Ok(if extended {
                Some(lock_id.to_string())
            } else {
                None
            })
        }
    }

    /// Release a specific holder, or force-release all holders.
    pub fn sys_unlock(&self, path: &str, lock_id: &str, force: bool) -> Result<bool, KernelError> {
        let (backend, key) = self.advisory_lock_target(path, contracts::ROOT_ZONE_ID)?;
        if force {
            backend
                .force_release(&key)
                .map_err(|e| KernelError::IOError(format!("sys_unlock({path}): {e}")))
        } else {
            backend
                .release(&key, lock_id)
                .map_err(|e| KernelError::IOError(format!("sys_unlock({path}): {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lock::locks::LocalLocks;
    use crate::hal::distributed_coordinator::{
        ClusterInfo, CoordinatorResult, DistributedCoordinator, ShareInfo,
    };
    use crate::meta_store::MetaStore;
    use contracts::lock_state::LockState;
    use std::collections::BTreeMap;

    struct Zones(BTreeMap<String, Arc<dyn Locks>>);

    impl DistributedCoordinator for Zones {
        fn list_zones(&self, _: &Kernel) -> Vec<String> {
            self.0.keys().cloned().collect()
        }
        fn cluster_info(&self, _: &Kernel, _: &str) -> CoordinatorResult<ClusterInfo> {
            unreachable!()
        }
        fn create_zone(&self, _: &Kernel, _: &str) -> CoordinatorResult<()> {
            unreachable!()
        }
        fn remove_zone(&self, _: &Kernel, _: &str, _: bool) -> CoordinatorResult<()> {
            unreachable!()
        }
        fn join_zone(&self, _: &Kernel, _: &str, _: bool) -> CoordinatorResult<()> {
            unreachable!()
        }
        fn wire_mount(&self, _: &Kernel, _: &str, _: &str, _: &str) -> CoordinatorResult<()> {
            unreachable!()
        }
        fn unwire_mount(&self, _: &Kernel, _: &str, _: &str) -> CoordinatorResult<()> {
            unreachable!()
        }
        fn share_zone(&self, _: &Kernel, _: &str, _: &str) -> CoordinatorResult<ShareInfo> {
            unreachable!()
        }
        fn lookup_share(&self, _: &Kernel, _: &str) -> CoordinatorResult<Option<ShareInfo>> {
            unreachable!()
        }
        fn metastore_for_zone(&self, _: &Kernel, _: &str) -> CoordinatorResult<Arc<dyn MetaStore>> {
            unreachable!()
        }
        fn locks_for_zone(&self, _: &Kernel, zone: &str) -> CoordinatorResult<Arc<dyn Locks>> {
            self.0
                .get(zone)
                .cloned()
                .ok_or_else(|| "zone unavailable".into())
        }
    }

    fn locks() -> Arc<dyn Locks> {
        Arc::new(LocalLocks::new(Arc::new(parking_lot::Mutex::new(
            LockState::new(),
        ))))
    }

    #[test]
    fn lock_queries_project_prefixes_before_limiting_and_skip_shadowed_rows() {
        let root = locks();
        let shared = locks();
        let k = Kernel::new();
        k.set_distributed_coordinator(Arc::new(Zones(BTreeMap::from([
            ("root".into(), root.clone()),
            ("shared".into(), shared.clone()),
        ]))));
        k.vfs_router.add_mount("/", "root", None, false);
        // A stale pre-mount row must not hide a later visible root lock.
        assert!(root.acquire("/agents/stale", "old", 1, 60, "test").unwrap());
        assert!(root.acquire("/z/seat", "local", 1, 60, "test").unwrap());
        // A nonmatching earlier row must not consume a prefix query's cap.
        assert!(shared
            .acquire("/a/earlier", "other", 1, 60, "test")
            .unwrap());
        assert!(shared
            .acquire("/agents/worker/seat", "live", 1, 60, "test")
            .unwrap());
        k.vfs_router
            .add_federation_mount("/agents", "root", None, "shared", "/agents", false);
        k.vfs_router
            .add_federation_mount("/alias", "root", None, "shared", "/agents", false);
        assert_eq!(
            k.list_advisory_locks("/agents", 1)[0].path,
            "/agents/worker/seat"
        );
        assert_eq!(
            k.list_advisory_locks("/alias", 1)[0].path,
            "/alias/worker/seat"
        );
        assert_eq!(
            k.list_advisory_locks("/ag", 1)[0].path,
            "/agents/worker/seat"
        );
        assert!(k.list_advisory_locks("", 0).is_empty());
        let root_only = k.list_advisory_locks("/z", 1);
        assert_eq!(root_only[0].holders[0].lock_id, "local");
        assert!(k
            .list_advisory_locks("", 20)
            .iter()
            .all(|row| row.path != "/agents/stale"));
        assert_eq!(
            k.advisory_lock_info("/alias/worker/seat", "root")
                .unwrap()
                .holders[0]
                .lock_id,
            "live"
        );
        // With cap=1, the stale root row sorts before the legitimate row:
        // overfetching must still find the first visible lock.
        k.vfs_router.remove("/alias", "root");
        assert_eq!(k.list_advisory_locks("", 1)[0].path, "/agents/worker/seat");
        assert!(shared.force_release("/agents/worker/seat").unwrap());
        assert_eq!(k.list_advisory_locks("", 1)[0].path, "/z/seat");
    }

    #[test]
    fn plain_mounts_keep_full_keys_and_missing_distributed_zones_fail_closed() {
        let root = locks();
        let k = Kernel::new();
        k.set_distributed_coordinator(Arc::new(Zones(BTreeMap::from([("root".into(), root)]))));
        k.vfs_router.add_mount("/", "root", None, false);
        k.vfs_router.add_mount("/work", "root", None, false);
        k.vfs_router.add_mount("/other", "root", None, false);
        assert!(k
            .sys_lock("/work/seat", "", 1, 60, "first")
            .unwrap()
            .is_some());
        assert!(k
            .sys_lock("/other/seat", "", 1, 60, "second")
            .unwrap()
            .is_some());
        assert!(k
            .sys_lock("/work/seat", "", 1, 60, "conflict")
            .unwrap()
            .is_none());
        assert_eq!(k.list_advisory_locks("/work", 1)[0].path, "/work/seat");
        k.vfs_router
            .add_federation_mount("/missing", "root", None, "absent", "/", false);
        assert!(k
            .sys_lock("/missing/seat", "", 1, 60, "no fallback")
            .is_err());
        assert!(k.advisory_lock_info("/missing/seat", "root").is_none());
    }
}
