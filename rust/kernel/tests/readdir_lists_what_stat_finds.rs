//! Regression tests for nexi-lab/nexus-vfs#339 — a listing may not omit
//! something that stats.
//!
//! A write plants the LEAF's metastore row only, so writing `/a/b/c` left `b`
//! with no row of its own. `sys_stat` resolves a path, so `b` answered "yes, a
//! directory"; `sys_readdir` filtered its prefix scan down to rows at exactly one
//! level, so `/a` listed nothing. The two answers disagreed, and nothing could
//! repair the second — `sys_setattr(DT_DIR)` on an entry that already resolves is
//! a no-op, so the caller who noticed had no move.
//!
//! What it cost: agent discovery in the live Win↔Mac duet. An agent whose subtree
//! was first touched deep — a peer writing `/agents/<name>/conversations/<peer>`
//! — never appeared in `readdir /agents` on that node, so `agent_list` told a
//! model it had no peers while `stat` found every one of them, and the two nodes
//! listed two different sets.
//!
//! The fix derives membership from the rows that exist instead of storing it a
//! second time, so these tests are written as the property rather than as the
//! symptom: **every path that stats under a listing root appears in that
//! listing.**
//!
//! Public Kernel API only.

use kernel::kernel::syscall::{KernelSyscall, ReaddirOpts};
use kernel::kernel::{Kernel, OperationContext};
use kernel::meta_store::{DT_DIR, DT_REG};

mod common;

/// Boot a kernel with the shared in-memory backend mounted at "/".
fn boot() -> (Kernel, OperationContext) {
    let k = Kernel::new();
    common::mount_mem_root(&k);
    (k, common::admin_ctx())
}

/// Plant a directory the way a service announces presence: `sys_setattr(DT_DIR)`,
/// no content.
fn mkdir(k: &Kernel, path: &str) {
    KernelSyscall::sys_setattr(
        k,
        path,
        i32::from(DT_DIR),
        "",
        None,
        None,
        None,
        "",
        kernel::ROOT_ZONE_ID,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap_or_else(|e| panic!("provision {path}: {e:?}"));
}

/// Child names a listing reports for `dir`.
fn names(k: &Kernel, dir: &str) -> Vec<String> {
    KernelSyscall::sys_readdir(k, dir, kernel::ROOT_ZONE_ID, true, ReaddirOpts::default())
        .into_iter()
        .map(|(path, _)| path.rsplit('/').next().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn a_deep_write_makes_its_intermediate_a_listed_child() {
    let (k, ctx) = boot();

    // The shape the duet hit: nothing ever wrote `/agents` or `/agents/deep`.
    KernelSyscall::sys_write(&k, "/agents/deep/conversations/x", &ctx, b"hi", 0)
        .expect("deep write");

    let stat = KernelSyscall::sys_stat(&k, "/agents/deep", kernel::ROOT_ZONE_ID)
        .expect("the intermediate stats");
    assert!(stat.is_directory, "the intermediate stats as a directory");

    let listed = names(&k, "/agents");
    assert!(
        listed.iter().any(|n| n == "deep"),
        "readdir /agents must list what stat finds, got {listed:?}"
    );
}

#[test]
fn every_level_of_a_deep_write_is_listed_by_its_own_parent() {
    let (k, ctx) = boot();
    KernelSyscall::sys_write(&k, "/agents/deep/conversations/x", &ctx, b"hi", 0)
        .expect("deep write");

    // Walking down from the root, each level lists the next. A fix that only
    // patched the first boundary passes the test above and fails here.
    for (dir, child) in [
        ("/", "agents"),
        ("/agents", "deep"),
        ("/agents/deep", "conversations"),
        ("/agents/deep/conversations", "x"),
    ] {
        let listed = names(&k, dir);
        assert!(
            listed.iter().any(|n| n == child),
            "readdir {dir} must list {child}, got {listed:?}"
        );
    }
}

#[test]
fn an_agent_announced_after_a_peer_wrote_into_its_subtree_is_discoverable() {
    let (k, ctx) = boot();

    // The live sequence, in order. 1: a PEER writes first — it files the
    // conversation under both participants, so `/agents/bot` is touched before
    // `bot` itself ever announces anything.
    KernelSyscall::sys_write(
        &k,
        "/agents/bot/conversations/peer",
        &ctx,
        b"/conversations/7f3a",
        0,
    )
    .expect("the peer's write");

    // 2: `bot` announces itself, planting every component of its presence — and
    // both of these are NO-OPS, because the paths already resolve. That is why the
    // caller-side fix (dropping the "already a directory" skip so it re-plants)
    // could not work, and why this has to be the listing's problem: a re-`setattr`
    // on an entry that exists changes nothing.
    mkdir(&k, "/agents/bot");
    mkdir(&k, "/agents/bot/conversations");

    // 3: discovery — the question `agent_list` answers.
    let listed = names(&k, "/agents");
    assert!(
        listed.iter().any(|n| n == "bot"),
        "an agent whose subtree a peer touched first must still be discoverable, got {listed:?}"
    );
}

#[test]
fn a_recursive_listing_has_no_holes() {
    let (k, ctx) = boot();
    KernelSyscall::sys_write(&k, "/agents/deep/conversations/x", &ctx, b"hi", 0)
        .expect("deep write");

    let paths: Vec<String> = KernelSyscall::sys_readdir(
        &k,
        "/agents",
        kernel::ROOT_ZONE_ID,
        true,
        ReaddirOpts {
            recursive: true,
            ..ReaddirOpts::default()
        },
    )
    .into_iter()
    .map(|(path, _)| path)
    .collect();

    // A recursive scan reports a subtree, and a subtree with holes is the same
    // defect one level down: a caller building a tree from it would attach `x` to
    // a parent that was never listed.
    for expected in [
        "/agents/deep",
        "/agents/deep/conversations",
        "/agents/deep/conversations/x",
    ] {
        assert!(
            paths.iter().any(|p| p == expected),
            "recursive readdir must include {expected}, got {paths:?}"
        );
    }
}

#[test]
fn a_stored_entry_keeps_its_own_type_against_a_deeper_row() {
    let (k, ctx) = boot();

    // A real row, then a row BELOW it — a contradictory state the namespace can
    // reach (a file exists; something writes a path through it). The deeper row
    // implies a directory at the same path, and the stored row has to win, or a
    // listing would silently re-type an entry that exists. `DT_REG` because the
    // property is type-agnostic and a plain write is the cheapest way to store one.
    KernelSyscall::sys_write(&k, "/agents/bot/note", &ctx, b"x", 0).expect("the real row");
    KernelSyscall::sys_write(&k, "/agents/bot/note/nested", &ctx, b"y", 0)
        .expect("a row beneath it");

    let entries = KernelSyscall::sys_readdir(
        &k,
        "/agents/bot",
        kernel::ROOT_ZONE_ID,
        true,
        ReaddirOpts::default(),
    );
    let note = entries
        .iter()
        .find(|(path, _)| path.ends_with("/note"))
        .expect("the stored entry is listed");
    assert_eq!(
        note.1, DT_REG,
        "a stored row is authoritative about its own type, not the directory a deeper row implies"
    );
}

#[test]
fn deriving_parents_invents_nothing() {
    let (k, _ctx) = boot();
    // An empty directory still lists empty: membership is derived from rows that
    // exist, so a directory with nothing beneath it has no children to imply.
    mkdir(&k, "/empty");
    assert!(
        names(&k, "/empty").is_empty(),
        "an empty directory lists nothing"
    );
}
