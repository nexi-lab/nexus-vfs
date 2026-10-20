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
        let key = route
            .as_ref()
            .map_or_else(|| path.into_owned(), |r| format!("/{}", r.backend_path));
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
        let coordinator = self.distributed_coordinator();
        if !coordinator.is_initialized(self) {
            return self.lock_manager.list_locks(prefix, limit);
        }
        let mut visible = std::collections::BTreeMap::new();
        for zone in coordinator.list_zones(self) {
            let Ok(backend) = coordinator.locks_for_zone(self, &zone) else {
                continue;
            };
            for info in backend.list_locks("", limit) {
                for (lookup_zone, path) in self.vfs_router.project_zone_path(&zone, &info.path) {
                    if lookup_zone != contracts::ROOT_ZONE_ID || !path.starts_with(prefix) {
                        continue;
                    }
                    // A more-specific mount can shadow an older root-zone row.
                    // Only expose the lock through a spelling that still routes
                    // to this exact domain/key.
                    let Some(route) = self.vfs_router.route(&path, &lookup_zone) else {
                        continue;
                    };
                    if route.zone_id != zone || format!("/{}", route.backend_path) != info.path {
                        continue;
                    }
                    let mut projected = info.clone();
                    projected.path = path.clone();
                    visible.insert(path, shared_lock_to_kernel(projected));
                }
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
