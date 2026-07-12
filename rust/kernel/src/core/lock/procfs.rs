//! `/__sys__/locks` — the advisory-lock procfs view.
//!
//! Linux `/proc/locks`. An advisory lock is a kernel object, not a file,
//! so enumeration needs a projection rather than a directory. Lives with
//! `LockManager` (its owner), registered into the [`crate::core::procfs`]
//! registry at kernel boot.

use crate::core::procfs::ProcfsProvider;
use crate::kernel::Kernel;

/// Upper bound on one enumeration. Matches the page ceiling the readdir
/// path applies when a caller asks for "everything".
const MAX_LOCKS: usize = 10_000;

/// Entry type reported for each lock. `DT_REG` — a lock projects as a
/// leaf, the way `/proc/locks` presents one line per lock.
const DT_REG: u8 = 0;

pub struct LocksProcfs;

impl ProcfsProvider for LocksProcfs {
    fn prefix(&self) -> &str {
        contracts::LOCKS_PATH_PREFIX
    }

    /// Which paths are locked, and by whom, is privileged.
    fn admin_only(&self) -> bool {
        true
    }

    /// `sub_path` narrows the enumeration to locks under that path, so
    /// `readdir("/__sys__/locks/docs")` lists the locks held under
    /// `/docs`. Entries are the locked paths themselves.
    ///
    /// Lock keys are absolute (`/docs/a.md`) while a view sub-path is
    /// relative to the view root (`docs`), so the leading `/` has to go
    /// back on before matching — without it the filter compares
    /// `"/docs/a.md".starts_with("docs")` and silently narrows to
    /// nothing.
    fn readdir(&self, kernel: &Kernel, sub_path: &str) -> Vec<(String, u8)> {
        let path_prefix = if sub_path.is_empty() {
            String::new()
        } else {
            format!("/{sub_path}")
        };
        kernel
            .lock_manager_arc()
            .list_locks(&path_prefix, MAX_LOCKS)
            .into_iter()
            .map(|lock| (lock.path, DT_REG))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contracts::LOCKS_PATH_PREFIX;

    /// The view had no coverage while it was hand-rolled inside
    /// `readdir_paged`. These pin the behaviour the registry now serves.
    fn names(result: &crate::kernel::ReadDirResult) -> Vec<String> {
        result.items.iter().map(|(name, _)| name.clone()).collect()
    }

    fn kernel_with_locks(paths: &[&str]) -> Kernel {
        let k = Kernel::new();
        for path in paths {
            // Empty lock_id = acquire (a non-empty one means "extend an
            // existing lock", which quietly no-ops when there is none).
            let token = k
                .sys_lock(path, "", 1, 60, "tester")
                .expect("sys_lock must not error");
            assert!(token.is_some(), "lock on {path} must be acquired");
        }
        k
    }

    #[test]
    fn admin_sees_every_held_lock() {
        let k = kernel_with_locks(&["/docs/b.md", "/docs/a.md", "/src/main.rs"]);
        let listed = k.readdir_paged(LOCKS_PATH_PREFIX, "root", true, 0, None);
        assert_eq!(
            names(&listed),
            vec!["/docs/a.md", "/docs/b.md", "/src/main.rs"]
        );
    }

    #[test]
    fn non_admin_sees_nothing() {
        let k = kernel_with_locks(&["/docs/a.md"]);
        let listed = k.readdir_paged(LOCKS_PATH_PREFIX, "root", false, 0, None);
        assert!(names(&listed).is_empty());
    }

    #[test]
    fn a_sub_path_narrows_to_locks_under_it() {
        let k = kernel_with_locks(&["/docs/a.md", "/src/main.rs"]);
        let listed = k.readdir_paged(&format!("{LOCKS_PATH_PREFIX}/docs"), "root", true, 0, None);
        assert_eq!(names(&listed), vec!["/docs/a.md"]);
    }

    /// The cursor was accepted and then ignored while this view was
    /// hand-rolled, so page 2 handed back page 1 forever. Going through
    /// the registry, paging terminates.
    #[test]
    fn paging_advances_instead_of_repeating_the_first_page() {
        let k = kernel_with_locks(&["/a", "/b", "/c"]);

        let first = k.readdir_paged(LOCKS_PATH_PREFIX, "root", true, 2, None);
        assert_eq!(names(&first), vec!["/a", "/b"]);
        assert!(first.has_more);

        let second = k.readdir_paged(
            LOCKS_PATH_PREFIX,
            "root",
            true,
            2,
            first.next_cursor.as_deref(),
        );
        assert_eq!(names(&second), vec!["/c"]);
        assert!(!second.has_more);
    }
}
