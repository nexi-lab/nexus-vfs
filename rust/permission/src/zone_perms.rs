//! `ZonePermsProvider` — the path-aware zone-perm impl of
//! [`PermissionProvider`].
//!
//! Contract: for each request, extract the request path's owning zone
//! (either from the caller-supplied `RouteResult` or by consulting no
//! source at all — see below), then verify the caller's
//! `OperationContext.zone_perms` contains a matching `(zone_id,
//! perm_chars)` grant whose `perm_chars` includes the requested
//! permission's character (`'r'` for Read / Traverse, `'w'` for Write).
//!
//! Historical note (SSOT bug fixed at the 2026-07-23 refactor): the
//! pre-refactor inline gate in `kernel::dispatch::check_permission`
//! iterated `ctx.zone_perms` with the `zone_id` field **unused** —
//! effectively "if any zone in the caller's grants has the right
//! perm_char, allow".  That was too permissive: an agent granted
//! `[("eng", "rw"), ("knowledge", "r")]` could WRITE to
//! `/knowledge/*` because the iterator saw `"rw"` on `eng` and
//! accepted the character match regardless of path.  This impl fixes
//! that: `path`'s owning zone is derived from routing, then only that
//! zone's grant participates.
//!
//! On path-to-zone extraction: the provider prefers `route.zone_id`
//! when the syscall body already routed; otherwise it falls back to
//! `ctx.context_zone_id` (the caller's ambient zone).  Falling back
//! to routing here on every miss would double the VFSRouter cost —
//! callers are expected to route once at the top of the syscall body
//! and pass the result through.  The kernel gate's
//! `check_permission_with_route` hook wires this for every syscall
//! that routes for I/O anyway.

use std::sync::Arc;
use std::time::Duration;

use contracts::ROOT_ZONE_ID;
use kernel::kernel::{KernelError, OperationContext};
use kernel::vfs_router::RouteResult;
use kernel::{Permission, PermissionProvider};

use crate::lease_cache::PermissionLeaseCache;

/// Default lease TTL (30s) mirrors the pre-refactor kernel default and
/// the Python `PermissionLeaseTable`.  Callers that need a different
/// policy construct via `ZonePermsProvider::with_cache(...)`.
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(30);
/// Default lease cap (100k unique paths) matches the pre-refactor
/// kernel default.
const DEFAULT_LEASE_MAX: usize = 100_000;

/// Path-aware zone-perm authorization provider.
///
/// See the module docstring for the SSOT contract and the historical
/// bug this fixes.  Internal lease cache memoises hits at ~100-200ns.
pub struct ZonePermsProvider {
    lease_cache: Arc<PermissionLeaseCache>,
}

impl Default for ZonePermsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ZonePermsProvider {
    /// Construct with the default lease cache (30s TTL, 100k paths).
    pub fn new() -> Self {
        Self {
            lease_cache: Arc::new(PermissionLeaseCache::new(
                DEFAULT_LEASE_TTL,
                DEFAULT_LEASE_MAX,
            )),
        }
    }

    /// Construct with a shared/pre-built lease cache — for tests and
    /// for profiles that want to plug custom TTL/capacity.
    pub fn with_cache(lease_cache: Arc<PermissionLeaseCache>) -> Self {
        Self { lease_cache }
    }

    /// Expose the internal lease cache so profile boot code can wire
    /// invalidation observers (e.g. auth-key revocation → drop leases
    /// for that agent).  Read-only handle; mutation happens through
    /// the cache's own `invalidate_*` methods.
    pub fn lease_cache(&self) -> Arc<PermissionLeaseCache> {
        Arc::clone(&self.lease_cache)
    }
}

fn permission_char(permission: Permission) -> char {
    match permission {
        // Traverse is a directory descent — treated as Read for grant
        // purposes (matches the pre-refactor gate's Read/Traverse
        // collapse; no separate Traverse grant character exists in
        // `zone_perms`).
        Permission::Read | Permission::Traverse => 'r',
        Permission::Write => 'w',
    }
}

/// Determine the zone that owns `path` for authorization purposes.
///
/// Preference order:
/// 1. `route.zone_id` when the caller has already routed — this is
///    the authoritative answer (`RouteResult.zone_id` comes from
///    VFSRouter's mount table, same SSOT `sys_read`/`sys_write` use).
/// 2. `ctx.context_zone_id` — the caller's ambient zone (federation
///    tokens frame a request "as if in zone X").
/// 3. `ROOT_ZONE_ID` — final fallback for kernel-owned root paths.
fn owning_zone<'a>(route: Option<&'a RouteResult>, ctx: &'a OperationContext) -> &'a str {
    if let Some(r) = route {
        return r.zone_id.as_str();
    }
    ctx.context_zone_id.as_deref().unwrap_or(ROOT_ZONE_ID)
}

impl PermissionProvider for ZonePermsProvider {
    fn check(
        &self,
        path: &str,
        route: Option<&RouteResult>,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        // Lease cache — hot path early-return.  Uses `agent_id` when
        // present, falls back to `user_id` (same as the pre-refactor
        // gate).  Empty caller id ⇒ skip cache (lease_cache.check
        // returns false immediately on empty id).
        let agent_id = ctx.agent_id.as_deref().unwrap_or(&ctx.user_id);
        if self.lease_cache.check(path, agent_id) {
            return Ok(());
        }

        // Zone-perms path-aware check.  Empty `zone_perms` under an
        // installed provider means "no grants" — deny.  Callers that
        // want the pre-refactor "no zone_perms ⇒ fall through" shape
        // should compose this provider with a second provider that
        // handles the empty case; the pre-refactor fall-through to a
        // Python hook was the shortcut this refactor deliberately
        // removes so the Rust tier owns the contract end-to-end.
        let perm_char = permission_char(permission);
        let path_zone = owning_zone(route, ctx);
        let has_zone_grant = ctx
            .zone_perms
            .iter()
            .any(|(zone_id, perm_chars)| zone_id == path_zone && perm_chars.contains(perm_char));

        if has_zone_grant {
            self.lease_cache.stamp(path, agent_id);
            return Ok(());
        }

        Err(KernelError::PermissionDenied(format!(
            "zone permission denied: no {perm_char} grant for '{path}' \
             in zone '{path_zone}' (caller grants: {:?})",
            ctx.zone_perms,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(
        agent_id: &str,
        user_id: &str,
        zone_perms: Vec<(String, String)>,
    ) -> OperationContext {
        let mut ctx = OperationContext::new(user_id, ROOT_ZONE_ID, false, None, false);
        ctx.agent_id = Some(agent_id.to_string());
        ctx.zone_perms = zone_perms;
        ctx
    }

    /// Regression against the pre-refactor bug: an agent granted
    /// `[("eng","rw"),("knowledge","r")]` MUST be denied when writing
    /// to a path routed to `knowledge-zone`.
    #[test]
    fn writing_read_only_zone_is_denied_even_when_another_zone_has_write() {
        let provider = ZonePermsProvider::new();
        let ctx = ctx_with(
            "agent-1",
            "alice",
            vec![
                ("eng".into(), "rw".into()),
                ("knowledge".into(), "r".into()),
            ],
        );

        // Simulate the syscall body having already routed the path
        // to `knowledge-zone`.
        let route = RouteResult {
            mount_point: "/knowledge/doc".into(),
            backend_path: "doc".into(),
            zone_id: "knowledge".into(),
            is_external: false,
            is_cas: false,
            backend: None,
            metastore: None,
            target_zone_id: None,
        };

        let err = provider
            .check("/knowledge/doc", Some(&route), Permission::Write, &ctx)
            .expect_err("write into knowledge zone must be denied — pre-refactor bug's regression");
        assert!(
            matches!(err, KernelError::PermissionDenied(_)),
            "expected PermissionDenied, got {err:?}",
        );
    }

    /// Same agent reading the same path must be allowed —
    /// `knowledge: r` grants Read.
    #[test]
    fn reading_read_only_zone_is_allowed() {
        let provider = ZonePermsProvider::new();
        let ctx = ctx_with(
            "agent-1",
            "alice",
            vec![
                ("eng".into(), "rw".into()),
                ("knowledge".into(), "r".into()),
            ],
        );
        let route = RouteResult {
            mount_point: "/knowledge/doc".into(),
            backend_path: "doc".into(),
            zone_id: "knowledge".into(),
            is_external: false,
            is_cas: false,
            backend: None,
            metastore: None,
            target_zone_id: None,
        };
        provider
            .check("/knowledge/doc", Some(&route), Permission::Read, &ctx)
            .expect("read must be allowed under 'r' grant");
    }

    /// Same agent writing to a zone they have `rw` on must be allowed.
    #[test]
    fn writing_read_write_zone_is_allowed() {
        let provider = ZonePermsProvider::new();
        let ctx = ctx_with(
            "agent-1",
            "alice",
            vec![
                ("eng".into(), "rw".into()),
                ("knowledge".into(), "r".into()),
            ],
        );
        let route = RouteResult {
            mount_point: "/eng/src".into(),
            backend_path: "src".into(),
            zone_id: "eng".into(),
            is_external: false,
            is_cas: false,
            backend: None,
            metastore: None,
            target_zone_id: None,
        };
        provider
            .check("/eng/src", Some(&route), Permission::Write, &ctx)
            .expect("write must be allowed under 'rw' grant on this zone");
    }

    /// Caller with no zone_perms is denied under an armed provider —
    /// this is the deliberate contract change from the pre-refactor
    /// gate (which fell through to a Python hook on empty zone_perms).
    #[test]
    fn empty_zone_perms_is_denied_under_armed_provider() {
        let provider = ZonePermsProvider::new();
        let ctx = ctx_with("agent-1", "alice", vec![]);
        let err = provider
            .check("/any/path", None, Permission::Read, &ctx)
            .expect_err("empty zone_perms must deny");
        assert!(matches!(err, KernelError::PermissionDenied(_)));
    }

    /// Lease cache short-circuits repeat hits (perf contract).
    #[test]
    fn lease_cache_short_circuits_repeat_hits() {
        let provider = ZonePermsProvider::new();
        let ctx = ctx_with("agent-1", "alice", vec![("eng".into(), "rw".into())]);
        let route = RouteResult {
            mount_point: "/eng/x".into(),
            backend_path: "x".into(),
            zone_id: "eng".into(),
            is_external: false,
            is_cas: false,
            backend: None,
            metastore: None,
            target_zone_id: None,
        };
        // First call: cache miss → full check → stamp.
        provider
            .check("/eng/x", Some(&route), Permission::Read, &ctx)
            .expect("first call must succeed via full check");
        // Second call: lease cache hit — same result even if we
        // deliberately pass an empty `zone_perms` (proves the cache
        // is what answered, not the perms iter).
        let mut ctx2 = ctx.clone();
        ctx2.zone_perms.clear();
        provider
            .check("/eng/x", Some(&route), Permission::Read, &ctx2)
            .expect("second call must hit lease cache and succeed");
    }
}
