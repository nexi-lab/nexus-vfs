//! Regression test for nexi-lab/nexus-vfs#320 — a directory that exists only on the
//! backend must be deletable, and a directory that still holds one must not be
//! reported as deleted.
//!
//! `path_local` creates parent directories physically when a write lands, without
//! metastore rows. Once the files under such a directory are deleted, the kernel's
//! operations disagreed about whether it exists:
//!
//! * `sys_stat` and `sys_readdir` merge backend results, so it is visible;
//! * `sys_unlink` found no row and called `backend.delete_file`, which returns EISDIR
//!   for a directory. That error was swallowed into a miss with `entry_type = 0`, which
//!   the HTTP layer maps to **404**.
//!
//! Visible and undeletable. On one production deployment every workspace folder emptied
//! by file deletes was stuck that way.
//!
//! The second half is the opposite failure: `rmdir` checked emptiness against metastore
//! children only and then discarded the backend's answer (`let _ = b.rmdir(…)`), so a
//! directory holding a physical-only subdirectory had its row deleted, returned success,
//! and stayed on disk — a row gone while the thing it described lives on.
//!
//! Run against a real daemon because the defect is in how the kernel and a real
//! `path_local` backend disagree. A test backend that answered the way I assumed
//! `path_local` does would be testing my assumption.

mod common;

use std::time::Duration;

use common::{free_port, Daemon, Vfs, LOG_FILTER};

const BUDGET: Duration = Duration::from_secs(90);
const DT_DIR: u32 = 1;

#[tokio::test]
async fn an_implicit_directory_can_be_deleted_and_a_populated_one_cannot() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data").to_string_lossy().into_owned();
    let id = tmp.path().join("identity").to_string_lossy().into_owned();
    let port = free_port();
    let adv = format!("127.0.0.1:{port}");

    let env = vec![
        ("NEXUS_DATA_DIR", data.as_str()),
        ("NEXUS_IDENTITY_DIR", id.as_str()),
        ("NEXUS_ADVERTISE_ADDR", adv.as_str()),
        ("NEXUS_NO_TLS", "true"),
        ("NEXUS_INSECURE_NO_AUTH", "true"),
        ("RUST_LOG", LOG_FILTER),
    ];
    let mut d = Daemon::spawn(&["--bind-addr", &adv], &env);
    d.wait_for_log("VFS data plane ready", BUDGET)
        .await
        .expect("daemon serves");

    let mut vfs = Vfs::connect_serving(port, BUDGET).await;
    let t = "";

    // ── 1. A directory nobody mkdir'd, emptied of its files ───────────────────
    // The write creates `/ws/d` physically; no row is ever made for it.
    vfs.write_file("/ws/d/x.txt", b"hello", t)
        .await
        .expect("write through an implicit parent");
    let (removed_file, _) = vfs
        .delete("/ws/d/x.txt", false, t)
        .await
        .expect("delete the file");
    assert_eq!(
        removed_file,
        Some(true),
        "the file itself was always deletable"
    );

    // The directory is still visible — both stat and readdir merge the backend.
    assert!(
        vfs.stat_found("/ws/d", t).await,
        "an implicit directory is visible, which is why being undeletable was a bug \
         rather than a curiosity"
    );

    // This is #320: it used to answer (Some(false), 0) — a miss, 404 at the HTTP layer.
    let (removed_dir, entry_type) = vfs
        .delete("/ws/d", false, t)
        .await
        .expect("delete the implicit directory");
    assert_eq!(
        (removed_dir, entry_type),
        (Some(true), DT_DIR),
        "an implicit directory must delete AS A DIRECTORY, not miss as entry_type 0"
    );
    assert!(
        !vfs.stat_found("/ws/d", t).await,
        "after the delete it must be gone from stat too, not just from the metastore"
    );
    let listing = vfs.readdir_names("/ws", t).await.unwrap_or_default();
    assert!(
        !listing.iter().any(|n| n == "d"),
        "and gone from the listing; got {listing:?}"
    );

    // ── 2. A real directory that still holds a physical-only child ────────────
    // `/ws/e` gets a row; `/ws/e/sub` exists only on disk, created by the write.
    vfs.mkdir("/ws/e", t).await.expect("mkdir /ws/e");
    vfs.write_file("/ws/e/sub/y.txt", b"hi", t)
        .await
        .expect("write through an implicit child");
    vfs.delete("/ws/e/sub/y.txt", false, t)
        .await
        .expect("delete the file, leaving sub physical-only");

    // The metastore now has no children under /ws/e, so the old emptiness check said
    // "empty", deleted the row, returned success — and left `sub` on disk.
    let refused = vfs.delete("/ws/e", false, t).await;
    assert!(
        refused.is_err(),
        "a directory holding a physical-only child must be refused without recursive; \
         got {refused:?}"
    );
    assert!(
        vfs.stat_found("/ws/e", t).await,
        "a refused rmdir must leave the row: the directory still exists, and a row \
         deleted anyway is the worse half of #320"
    );

    // ── 3. recursive removes it, row and disk together ────────────────────────
    let (removed_tree, _) = vfs
        .delete("/ws/e", true, t)
        .await
        .expect("recursive delete succeeds");
    assert_eq!(removed_tree, Some(true), "recursive must remove the tree");
    assert!(
        !vfs.stat_found("/ws/e", t).await,
        "and leave nothing behind for stat to find"
    );
}
