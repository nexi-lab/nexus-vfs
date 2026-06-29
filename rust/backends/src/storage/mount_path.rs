//! Shared mount-path reassembly for proxy ObjectStore impls.
//!
//! The kernel hands every `ObjectStore` method a `backend_path` that
//! has been stripped of the mount-point prefix.  `RemoteBackend`
//! (the Python-hub proxy) speaks to a remote that expects the
//! *absolute* zone-rooted path — so it re-prepends the mount root
//! before issuing the RPC.  Extracted as a standalone helper so the
//! Issue #4273 boundary rule lives in one place; if a future proxy
//! ObjectStore is wired (federation-over-typed-RPC was a previous
//! attempt — see `kernel/federation/grpc_ops.rs` for the path that
//! replaced it), it consumes the same helper.
//!
//! Issue #4273 boundary check: the kernel may hand the proxy EITHER a
//! mount-relative route path (`file.txt`) OR a server content id that
//! is already zone-rooted (`zone/shared/file.txt`).  The proxy can't
//! distinguish the two at the API layer, so this helper applies one
//! rule that serves both: prepend `mount_root` UNLESS `backend_path`
//! is already zone-prefixed on a path-component boundary (equals
//! `mount_root` or starts with `"<mount_root>/"`).  Root mounts
//! (`mount_root` `""` / `"/"`) just ensure a leading slash.
//!
//! Without the `/`-boundary check, a crafted sibling `zone/acme2/file`
//! under `/zone/acme` would `starts_with("zone/acme")` and be emitted
//! as `/zone/acme2/file` — escape to a sibling subtree.  With the
//! boundary, it's treated as mount-relative and stays contained at
//! `/zone/acme/zone/acme2/file`.
//!
//! KNOWN LIMITATION: a route path that *literally re-uses* the mount's
//! own prefix (`zone/acme/x` under `/zone/acme`) is indistinguishable
//! from a content id and is treated as already-absolute.  It only ever
//! aliases WITHIN the mounted subtree (never a cross-tenant escape) and
//! is applied CONSISTENTLY across read/write/delete/rename.  Resolving
//! it requires a kernel-API change (a route-vs-content-id signal);
//! tracked as a #4273 follow-up.  Pinned by the tests below so a future
//! kernel-side fix updates them deliberately.

/// Reassemble the absolute server / peer path from a mount root and a
/// kernel-stripped `backend_path`.  See module docs for the boundary
/// rule that prevents both directory-escape (cross-tenant) and
/// double-prefixing (zone-rooted content ids).
///
/// `#[inline]` so the proxy ObjectStore's hot path (every `read_content`
/// / `write_content` / `stat` call) eats only the body, not the function
/// call frame.
#[inline]
pub(crate) fn to_mount_path(mount_root: &str, backend_path: &str) -> String {
    let bp = if backend_path.is_empty() || backend_path == "/" {
        String::new()
    } else if backend_path.starts_with('/') {
        backend_path.to_string()
    } else {
        format!("/{backend_path}")
    };
    if mount_root.is_empty() || mount_root == "/" {
        if bp.is_empty() {
            "/".to_string()
        } else {
            bp
        }
    } else {
        let root = mount_root.trim_matches('/');
        let rel = bp.trim_start_matches('/');
        if rel == root || rel.starts_with(&format!("{root}/")) {
            format!("/{rel}")
        } else {
            format!("/{root}{bp}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_mount_passes_through() {
        assert_eq!(to_mount_path("", "file.txt"), "/file.txt");
        assert_eq!(to_mount_path("/", "/zone/x/file.txt"), "/zone/x/file.txt");
        assert_eq!(to_mount_path("", ""), "/");
    }

    #[test]
    fn subpath_prefixes_mount_relative_route() {
        assert_eq!(
            to_mount_path("/zone/acme", "file.txt"),
            "/zone/acme/file.txt"
        );
        assert_eq!(
            to_mount_path("/zone/acme", "sub/dir/file.txt"),
            "/zone/acme/sub/dir/file.txt"
        );
        // Empty backend_path resolves to the mount root, not "/".
        assert_eq!(to_mount_path("/zone/acme", ""), "/zone/acme");
    }

    #[test]
    fn crafted_relative_path_does_not_escape_mount() {
        // Sibling-prefix `zone/acme2` under `/zone/acme` stays contained.
        let out = to_mount_path("/zone/acme", "zone/acme2/secret");
        assert!(
            out.starts_with("/zone/acme/"),
            "crafted path escaped the mount: {out}"
        );
        assert_eq!(out, "/zone/acme/zone/acme2/secret");
    }

    #[test]
    fn does_not_double_prefix_zone_rooted_content_id() {
        assert_eq!(
            to_mount_path("/zone/shared", "zone/shared/readback.txt"),
            "/zone/shared/readback.txt"
        );
        assert_eq!(
            to_mount_path("/zone/shared", "/zone/shared/sub/f.txt"),
            "/zone/shared/sub/f.txt"
        );
        // Exact-mount id maps to the mount root.
        assert_eq!(to_mount_path("/zone/shared", "zone/shared"), "/zone/shared");
    }

    #[test]
    fn subpath_round_trips_to_same_server_path() {
        // Invariant: write sends `server_path`; the hub echoes that path
        // as a slash-stripped content id which we persist VERBATIM;
        // readback `to_mount_path(stored_id)` must land on the original
        // `server_path`.
        let zone = "/zone/acme";
        for route in ["file.txt", "sub/dir/file.txt"] {
            let server_path = to_mount_path(zone, route);
            let stored = server_path.trim_start_matches('/').to_string();
            assert_eq!(
                to_mount_path(zone, &stored),
                server_path,
                "round-trip mismatch for route {route}"
            );
        }
    }

    #[test]
    fn read_repair_content_id_is_not_double_prefixed() {
        assert_eq!(
            to_mount_path("/zone/acme", "zone/acme/file.txt"),
            "/zone/acme/file.txt"
        );
    }

    #[test]
    fn self_prefixed_route_aliases_consistently_known_limitation() {
        // KNOWN LIMITATION: a route path that literally re-uses the
        // mount's own prefix is indistinguishable from a content id, so
        // it aliases to the collapsed path.  Applied CONSISTENTLY to
        // every op (read/write/delete/rename/stat all agree), so a
        // self-prefixed file is read and deleted at the same place it
        // was written, and it never escapes the mounted subtree.
        // Pinning so a future kernel-side fix (route-vs-content-id
        // signal) updates it deliberately.
        let aliased = to_mount_path("/zone/acme", "zone/acme/x");
        assert_eq!(aliased, "/zone/acme/x");
        assert!(
            aliased.starts_with("/zone/acme"),
            "must stay within the mount: {aliased}"
        );
    }
}
