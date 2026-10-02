//! Kernel permission provider over per-zone relationship graphs. System and
//! administrator contexts bypass graph checks. Other callers need a matching
//! direct or userset grant; missing grants and store failures deny access.
//!
//! Read and traverse accept viewer, reader, writer, or owner. Write accepts
//! writer or owner. An optional namespace registry defines richer expansions.
//! Graphs are refreshed from the locally applied store revision.

use std::sync::Arc;

use ahash::AHashMap;
use kernel::core::dispatch::{Permission, PermissionProvider};
use kernel::core::vfs_router::RouteResult;
use kernel::kernel::KernelError;
use kernel::kernel::OperationContext;
use lib::rebac::{compute_permission, ReBACGraph};
use lib::types::Entity;

use crate::graph_cache::ReBACGraphCache;

/// Relations that satisfy each `Permission` in the fixed v1 map.
///
/// Zanzibar's convention: stronger → weaker.  A caller with `owner`
/// implicitly reads and writes; a `writer` implicitly reads.  A
/// namespace-config import (follow-up) replaces this with per-
/// namespace expansion.
///
/// Kept as `&'static [&'static str]` (not `Vec`) so the hot-path
/// candidate loop allocates zero bytes.
#[inline]
fn candidate_relations(permission: Permission) -> &'static [&'static str] {
    match permission {
        Permission::Read | Permission::Traverse => &["viewer", "reader", "writer", "owner"],
        Permission::Write => &["writer", "owner"],
    }
}

/// The ReBAC enforcer.  Wraps a `ReBACGraphCache` + a namespace
/// registry (empty in v1) and impls `kernel::PermissionProvider`.
///
/// Clone-cheap — internal state is behind `Arc`.  A single instance
/// is composed at the composition root, cloned into the kernel's
/// permission-provider slot and any admin tool that wants direct
/// enforcer access.
pub struct RebacPermissionProvider {
    cache: Arc<ReBACGraphCache>,
    /// Namespace configs — empty in v1 (see module doc); the
    /// non-empty path lands with the Python-namespace-YAML port.
    /// Stored as `Arc` so the check hot path lends the reference
    /// to `compute_permission` without holding a lock.
    namespaces: Arc<AHashMap<String, lib::types::NamespaceConfig>>,
}

impl RebacPermissionProvider {
    /// Wrap a `ReBACGraphCache` with the v1 (empty-namespace)
    /// enforcer.  The composition root builds one `Arc<Self>` and
    /// hands it to `kernel::Kernel::set_permission_provider`.
    pub fn new(cache: Arc<ReBACGraphCache>) -> Self {
        Self {
            cache,
            namespaces: Arc::new(AHashMap::new()),
        }
    }

    /// Wrap a `ReBACGraphCache` with a pre-loaded namespace
    /// registry.  For tests + the follow-up that ports the Python
    /// YAML namespace config.  Kept `pub` so downstream tooling can
    /// build the registry independently.
    pub fn with_namespaces(
        cache: Arc<ReBACGraphCache>,
        namespaces: AHashMap<String, lib::types::NamespaceConfig>,
    ) -> Self {
        Self {
            cache,
            namespaces: Arc::new(namespaces),
        }
    }

    /// Extract the subject `Entity` from an `OperationContext`.
    ///
    /// * `subject_id` overrides `user_id` when set (the auth layer
    ///   stamps `subject_id` for agent-initiated calls where the
    ///   ReBAC identity differs from the human owner).
    /// * `subject_type` defaults to `"user"` on the context struct
    ///   itself — used verbatim.
    ///
    /// `#[inline]` — trivial field-copy on every check.
    #[inline]
    fn subject_of(ctx: &OperationContext) -> Entity {
        Entity {
            entity_type: ctx.subject_type.clone(),
            entity_id: ctx
                .subject_id
                .clone()
                .unwrap_or_else(|| ctx.user_id.clone()),
        }
    }

    /// Build the object `Entity` for a permission check.
    ///
    /// v1 shape: `entity_type = "file"`, `entity_id = <path>`.  A
    /// namespace-config with per-type expansion would differentiate
    /// `file` vs `folder` via a suffix check; today's fixed shape
    /// suffices because the fallback path (`namespaces.get(type) ==
    /// None`) treats every object uniformly.
    #[inline]
    fn object_of(path: &str) -> Entity {
        Entity {
            entity_type: "file".to_string(),
            entity_id: path.to_string(),
        }
    }

    /// Extract the effective zone id for the check.
    ///
    /// Prefer `route.zone_id` when available (the syscall body has
    /// already resolved the mount → zone mapping — cheaper than a
    /// re-lookup and correct across zone-remap edge cases).  Fall
    /// back to `ctx.zone_id` for calls where the router has not
    /// been consulted yet.
    #[inline]
    fn zone_of<'a>(ctx: &'a OperationContext, route: Option<&'a RouteResult>) -> &'a str {
        route.map(|r| r.zone_id.as_str()).unwrap_or(&ctx.zone_id)
    }

    /// Try each candidate relation; return `true` on the first hit.
    ///
    /// Delegates to `lib::rebac::compute_permission` per relation so
    /// userset expansion (group membership) and (future) namespace-
    /// config expansion both apply.  Under an empty namespace
    /// registry, `compute_permission` reduces to `check_direct_
    /// relation` OR-ed with userset expansion for each relation
    /// name — matches the v1 direct+group model.
    fn allows(
        &self,
        subject: &Entity,
        permission: Permission,
        object: &Entity,
        graph: &ReBACGraph,
    ) -> bool {
        for relation in candidate_relations(permission) {
            let mut memo = AHashMap::new();
            let mut visited = ahash::AHashSet::new();
            if compute_permission(
                subject,
                relation,
                object,
                graph,
                &self.namespaces,
                &mut memo,
                &mut visited,
                0,
            ) {
                return true;
            }
        }
        false
    }
}

impl PermissionProvider for RebacPermissionProvider {
    fn check(
        &self,
        path: &str,
        route: Option<&RouteResult>,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        // Short-circuit: kernel-internal system ops bypass ReBAC.
        // Matches the Linux `struct cred` posture — background
        // reconciliation and boot-time metadata population would
        // otherwise deadlock on themselves (they need to write
        // grants that permit their own reads).
        if ctx.is_system {
            return Ok(());
        }
        // Short-circuit: admin break-glass.  Admin identity is
        // granted by the auth layer (key-mint carries admin=true)
        // and the enforcer treats it as unconditional.  Regular
        // callers never hit this branch.
        if ctx.is_admin {
            return Ok(());
        }

        let zone = Self::zone_of(ctx, route);
        let graph = self.cache.graph_for_zone(zone).map_err(|e| {
            // Fail-closed on store errors — an enforcer that cannot
            // read its own substrate MUST deny.  Bubble the reason
            // through PermissionDenied so the operator log names the
            // backend failure, not just "denied".
            KernelError::PermissionDenied(format!(
                "rebac: cannot load graph for zone {zone:?}: {e}"
            ))
        })?;

        let subject = Self::subject_of(ctx);
        let object = Self::object_of(path);

        if self.allows(&subject, permission, &object, &graph) {
            Ok(())
        } else {
            // Deny with structured detail so the operator log can
            // pin the exact tuple that WOULD have granted access.
            // Format matches the Python side's rebac_denied log
            // spelling so alert queries transfer as-is.
            Err(KernelError::PermissionDenied(format!(
                "rebac: {subj_type}:{subj_id} lacks {perm:?} on {path} (zone={zone})",
                subj_type = subject.entity_type,
                subj_id = subject.entity_id,
                perm = permission,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inmem::InMemoryReBACTupleStore;
    use crate::store::ReBACTupleStore;
    use crate::tuple_key;
    use lib::types::ReBACTuple;

    fn tuple(
        obj_type: &str,
        obj_id: &str,
        rel: &str,
        subj_type: &str,
        subj_id: &str,
    ) -> ReBACTuple {
        ReBACTuple {
            object_type: obj_type.to_string(),
            object_id: obj_id.to_string(),
            relation: rel.to_string(),
            subject_type: subj_type.to_string(),
            subject_id: subj_id.to_string(),
            subject_relation: None,
        }
    }

    fn put(store: &InMemoryReBACTupleStore, zone: &str, t: &ReBACTuple) {
        let key = tuple_key::encode(zone, t).expect("encode");
        store.put(&key, b"").expect("put");
    }

    /// Assemble a `RebacPermissionProvider` backed by an in-memory
    /// store pre-populated with the given tuples.
    fn make_provider(zone: &str, tuples: &[ReBACTuple]) -> RebacPermissionProvider {
        let store = Arc::new(InMemoryReBACTupleStore::new());
        for t in tuples {
            put(&store, zone, t);
        }
        let cache = Arc::new(ReBACGraphCache::new(store));
        RebacPermissionProvider::new(cache)
    }

    /// Build an `OperationContext` shaped like a real user call.
    fn ctx(user: &str, zone: &str) -> OperationContext {
        OperationContext::new(
            user, zone, /* is_admin */ false, None, /* is_system */ false,
        )
    }

    /// Direct `reader` grant → `Permission::Read` allowed.
    #[test]
    fn direct_reader_grant_allows_read() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[tuple("file", path, "reader", "user", "alice")]);
        assert!(provider
            .check(path, None, Permission::Read, &ctx("alice", "root"))
            .is_ok());
    }

    /// A user without any grant is denied.
    #[test]
    fn no_grant_denies() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[]);
        let err = provider
            .check(path, None, Permission::Read, &ctx("alice", "root"))
            .expect_err("must deny");
        assert!(
            matches!(err, KernelError::PermissionDenied(_)),
            "denial must be PermissionDenied, not a generic error",
        );
    }

    /// `writer` implies `read` under the v1 fixed candidate map —
    /// pinning the Zanzibar "stronger → weaker" convention.  A
    /// regression that dropped `writer` from Read's candidate set
    /// would trip this.
    #[test]
    fn writer_grant_implicitly_allows_read() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[tuple("file", path, "writer", "user", "alice")]);
        assert!(provider
            .check(path, None, Permission::Read, &ctx("alice", "root"))
            .is_ok());
    }

    /// `owner` implies write.
    #[test]
    fn owner_grant_allows_write() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[tuple("file", path, "owner", "user", "alice")]);
        assert!(provider
            .check(path, None, Permission::Write, &ctx("alice", "root"))
            .is_ok());
    }

    /// `reader` alone does NOT grant write — pins the asymmetry.
    #[test]
    fn reader_grant_does_not_allow_write() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[tuple("file", path, "reader", "user", "alice")]);
        assert!(provider
            .check(path, None, Permission::Write, &ctx("alice", "root"))
            .is_err());
    }

    /// `is_system == true` short-circuits (kernel-internal ops).
    /// Even with zero tuples, a system call is allowed.  A
    /// regression that removed this bypass would deadlock
    /// background reconciliation (which writes grants that
    /// permit its own reads).
    #[test]
    fn system_operation_short_circuits_allow() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[]);
        let mut sys_ctx = ctx("alice", "root");
        sys_ctx.is_system = true;
        assert!(provider
            .check(path, None, Permission::Read, &sys_ctx)
            .is_ok());
    }

    /// `is_admin == true` short-circuits (break-glass).  Any admin
    /// wins any check.
    #[test]
    fn admin_short_circuits_allow() {
        let path = "/root/documents/spec.md";
        let provider = make_provider("root", &[]);
        let mut admin_ctx = ctx("alice", "root");
        admin_ctx.is_admin = true;
        assert!(provider
            .check(path, None, Permission::Write, &admin_ctx)
            .is_ok());
    }

    /// Cross-zone isolation: a grant in `zone_a` does NOT allow a
    /// `zone_b` call on the same path.  Pins the zone-scoping
    /// invariant end-to-end (encode → store → cache → enforcer).
    /// A regression that broke zone extraction would flip this.
    #[test]
    fn grant_in_zone_a_does_not_leak_to_zone_b() {
        let path = "/some/doc";
        let provider = {
            let store = Arc::new(InMemoryReBACTupleStore::new());
            put(
                &store,
                "zone_a",
                &tuple("file", path, "reader", "user", "alice"),
            );
            let cache = Arc::new(ReBACGraphCache::new(store));
            RebacPermissionProvider::new(cache)
        };
        assert!(provider
            .check(path, None, Permission::Read, &ctx("alice", "zone_a"))
            .is_ok());
        assert!(
            provider
                .check(path, None, Permission::Read, &ctx("alice", "zone_b"))
                .is_err(),
            "grant in zone_a must NOT leak to zone_b",
        );
    }

    /// `subject_id` overrides `user_id` — the auth layer stamps a
    /// distinct subject id for agent-initiated calls where the ReBAC
    /// identity differs from the human owner.  Grant is against the
    /// subject_id, not user_id.
    #[test]
    fn subject_id_overrides_user_id_when_set() {
        let path = "/root/doc";
        // Grant is to `agent_x`, not to `alice`.
        let provider = make_provider("root", &[tuple("file", path, "reader", "user", "agent_x")]);

        // alice with subject_id=agent_x → wins.
        let mut sub_ctx = ctx("alice", "root");
        sub_ctx.subject_id = Some("agent_x".to_string());
        assert!(provider
            .check(path, None, Permission::Read, &sub_ctx)
            .is_ok());

        // alice without the override → loses (user_id is not granted).
        assert!(provider
            .check(path, None, Permission::Read, &ctx("alice", "root"))
            .is_err());
    }

    /// Group userset: `alice` is a `member` of `group:eng`; the
    /// group has `reader` on the file.  Zanzibar userset expansion
    /// resolves through the group.  Pins the userset-as-subject
    /// path end-to-end (encode with `subject_relation=member` →
    /// decode → graph builds a userset index → enforcer walks it).
    #[test]
    fn group_userset_grant_reaches_member() {
        let path = "/root/team-doc";
        let store = Arc::new(InMemoryReBACTupleStore::new());

        // Tuple 1: alice member-of group:eng
        put(
            &store,
            "root",
            &tuple("group", "eng", "member", "user", "alice"),
        );
        // Tuple 2: `group:eng#member` has reader on the file (a
        // userset-as-subject tuple — subject_relation = "member").
        let userset_tuple = ReBACTuple {
            object_type: "file".to_string(),
            object_id: path.to_string(),
            relation: "reader".to_string(),
            subject_type: "group".to_string(),
            subject_id: "eng".to_string(),
            subject_relation: Some("member".to_string()),
        };
        put(&store, "root", &userset_tuple);

        let cache = Arc::new(ReBACGraphCache::new(store));
        let provider = RebacPermissionProvider::new(cache);

        assert!(
            provider
                .check(path, None, Permission::Read, &ctx("alice", "root"))
                .is_ok(),
            "group-membership must reach the file via userset expansion",
        );

        // Non-member is still denied.
        assert!(provider
            .check(path, None, Permission::Read, &ctx("bob", "root"))
            .is_err());
    }

    /// A store-read failure denies fail-closed (rather than allowing
    /// or panicking).  Regression pin for the "cannot read → deny"
    /// contract.
    #[test]
    fn store_error_denies_fail_closed() {
        use crate::store::ReBACTupleStoreError;

        struct AlwaysErrStore;
        impl ReBACTupleStore for AlwaysErrStore {
            fn put(&self, _k: &str, _v: &[u8]) -> Result<(), ReBACTupleStoreError> {
                Ok(())
            }
            fn delete(&self, _k: &str) -> Result<bool, ReBACTupleStoreError> {
                Ok(false)
            }
            fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, ReBACTupleStoreError> {
                Ok(None)
            }
            fn list(&self) -> Result<Vec<(String, Vec<u8>)>, ReBACTupleStoreError> {
                Err(ReBACTupleStoreError::Backend("backend unavailable".into()))
            }
            fn revision(&self) -> Result<u64, ReBACTupleStoreError> {
                Ok(0)
            }
        }

        let cache = Arc::new(ReBACGraphCache::new(Arc::new(AlwaysErrStore)));
        let provider = RebacPermissionProvider::new(cache);
        let err = provider
            .check("/root/doc", None, Permission::Read, &ctx("alice", "root"))
            .expect_err("must deny on store error");
        match err {
            KernelError::PermissionDenied(msg) => {
                assert!(
                    msg.contains("backend unavailable"),
                    "denial reason must surface the backend error for the operator log: {msg}",
                );
            }
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
    }

    /// `zone_of(ctx, None)` falls back to `ctx.zone_id`.  The
    /// `Some(route)` branch is exercised by real-integration tests
    /// (deferred to PR 4b's nexusd wire — constructing a valid
    /// `RouteResult` needs an actual router + mount, which is
    /// out-of-scope for this in-crate PR).
    #[test]
    fn zone_of_falls_back_to_ctx_zone_id_when_no_route() {
        let c = ctx("alice", "home_zone");
        assert_eq!(RebacPermissionProvider::zone_of(&c, None), "home_zone");
    }
}
