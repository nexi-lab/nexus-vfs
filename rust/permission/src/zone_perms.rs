//! Zone grants authorize each operation against the path's owning zone.
//! The request's authenticated grants are the authority. Checks are a linear
//! scan of that small grant list, without cached decisions or path inheritance.

use contracts::ROOT_ZONE_ID;
use kernel::kernel::{KernelError, OperationContext};
use kernel::vfs_router::RouteResult;
use kernel::{Permission, PermissionProvider};

/// Path-aware authorization from the current request's zone grants.
#[derive(Default)]
pub struct ZonePermsProvider;

impl ZonePermsProvider {
    pub fn new() -> Self {
        Self
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
        let perm_char = permission_char(permission);
        let path_zone = owning_zone(route, ctx);
        let has_zone_grant = ctx
            .zone_perms
            .iter()
            .any(|(zone_id, perm_chars)| zone_id == path_zone && perm_chars.contains(perm_char));

        if has_zone_grant {
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

    /// A prior success must not authorize a later request without grants.
    #[test]
    fn every_request_uses_its_current_grants() {
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
        provider
            .check("/eng/x", Some(&route), Permission::Read, &ctx)
            .expect("first call must succeed via full check");
        let mut ctx2 = ctx.clone();
        ctx2.zone_perms.clear();
        provider
            .check("/eng/x", Some(&route), Permission::Read, &ctx2)
            .expect_err("a previous success cannot outlive the request grants");
    }
}
