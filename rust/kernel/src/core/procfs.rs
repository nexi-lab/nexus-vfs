//! Procfs registry — §4 kernel primitive.
//!
//! **Linux analogue:** `proc_create()` / `struct proc_dir_entry`. The VFS
//! does not special-case `/proc/locks` in its readdir path; the lock
//! subsystem *registers* a proc entry and procfs dispatches to it. Same
//! here: a subsystem that wants a read-only `/__sys__/<name>` view
//! registers a [`ProcfsProvider`], and the syscall spine keeps **one**
//! dispatch instead of growing a branch per view.
//!
//! ## What belongs behind this, and what does not
//!
//! A procfs view is a **projection of state the kernel already holds**,
//! synthesised on read — advisory locks, cluster zones, credential
//! hashes. It exists because that state is a kernel-internal primitive
//! that deliberately is *not* a file (a lock is not a file; a credential
//! record is not a file), yet still needs an introspection surface.
//!
//! State that *can* be a file should just be one. `/proc/{pid}` is the
//! counter-example worth keeping in mind: the managed-agent service
//! materialises real dirents through ordinary syscalls, so the kernel
//! carries zero code for it. Reach for a provider only when materialising
//! the entries would put the SSOT somewhere it must not be.
//!
//! ## Contract
//!
//! * **Read-only.** There is no write path through a view. A `sys_write`
//!   at a view's path lands (at most) an inert metadata entry in the file
//!   tree; it cannot mutate the primitive behind the view.
//! * **Gated at the view, not at `/__sys__`.** Each provider declares its
//!   own [`ProcfsProvider::admin_only`]. A refused caller gets an **empty
//!   listing, never an error** — an error would answer "does this entry
//!   exist?" to someone who may not ask.
//! * **Providers take `&Kernel`** so they stay unit structs with no
//!   back-reference, the same shape the §3.B HAL traits use.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::kernel::Kernel;

/// A read-only synthesised view rooted at a `/__sys__/<name>` prefix.
pub trait ProcfsProvider: Send + Sync {
    /// Virtual path this provider owns, e.g. `/__sys__/locks`. The
    /// registry routes `<prefix>` and `<prefix>/<sub_path>` to it.
    fn prefix(&self) -> &str;

    /// Whether only admins may see the entries. Default `true`: an
    /// introspection view over kernel-internal state is privileged unless
    /// the owner says otherwise.
    fn admin_only(&self) -> bool {
        true
    }

    /// Every entry under `sub_path` (`""` at the view root), as
    /// `(name, entry_type)`. Order does not matter — the registry sorts,
    /// which is what makes the pagination cursor well-defined.
    fn readdir(&self, kernel: &Kernel, sub_path: &str) -> Vec<(String, u8)>;
}

/// The registered views. One per prefix.
#[derive(Default)]
pub struct ProcfsRegistry {
    providers: RwLock<Vec<Arc<dyn ProcfsProvider>>>,
}

impl ProcfsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the provider for its prefix.
    ///
    /// Replace-by-prefix, not accumulate: boot paths that run more than
    /// once must not stack duplicate providers behind one path, which
    /// would double every entry in the listing.
    pub fn register(&self, provider: Arc<dyn ProcfsProvider>) {
        let mut providers = self.providers.write();
        let prefix = provider.prefix().to_string();
        providers.retain(|p| p.prefix() != prefix);
        providers.push(provider);
    }

    /// Find the view owning `path`, plus the path *within* that view
    /// (`""` at the view root).
    ///
    /// Matches `<prefix>` exactly, or `<prefix>/…` at a `/` boundary — so
    /// a `/__sys__/locksmith` path never lands in the `/__sys__/locks`
    /// view.
    pub fn resolve(&self, path: &str) -> Option<(Arc<dyn ProcfsProvider>, String)> {
        let providers = self.providers.read();
        for provider in providers.iter() {
            let prefix = provider.prefix();
            if path == prefix {
                return Some((Arc::clone(provider), String::new()));
            }
            if let Some(rest) = path.strip_prefix(prefix) {
                if let Some(sub) = rest.strip_prefix('/') {
                    return Some((Arc::clone(provider), sub.to_string()));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(&'static str, bool);

    impl ProcfsProvider for Fake {
        fn prefix(&self) -> &str {
            self.0
        }
        fn admin_only(&self) -> bool {
            self.1
        }
        fn readdir(&self, _kernel: &Kernel, _sub_path: &str) -> Vec<(String, u8)> {
            Vec::new()
        }
    }

    #[test]
    fn resolves_the_view_root_and_sub_paths() {
        let reg = ProcfsRegistry::new();
        reg.register(Arc::new(Fake("/__sys__/locks", true)));

        let (p, sub) = reg.resolve("/__sys__/locks").expect("view root");
        assert_eq!(p.prefix(), "/__sys__/locks");
        assert_eq!(sub, "");

        let (_, sub) = reg.resolve("/__sys__/locks/docs/a.md").expect("sub path");
        assert_eq!(sub, "docs/a.md");
    }

    #[test]
    fn a_prefix_only_matches_at_a_path_boundary() {
        let reg = ProcfsRegistry::new();
        reg.register(Arc::new(Fake("/__sys__/locks", true)));
        // Neighbouring name that merely shares a string prefix.
        assert!(reg.resolve("/__sys__/locksmith").is_none());
        assert!(reg.resolve("/__sys__/zones").is_none());
        assert!(reg.resolve("/docs/readme.md").is_none());
    }

    #[test]
    fn re_registering_a_prefix_replaces_rather_than_stacks() {
        let reg = ProcfsRegistry::new();
        reg.register(Arc::new(Fake("/__sys__/locks", true)));
        reg.register(Arc::new(Fake("/__sys__/locks", false)));
        assert_eq!(reg.providers.read().len(), 1);
        // The later registration wins.
        let (p, _) = reg.resolve("/__sys__/locks").expect("view");
        assert!(!p.admin_only());
    }
}
