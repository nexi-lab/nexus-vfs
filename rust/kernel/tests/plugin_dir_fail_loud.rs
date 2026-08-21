//! `load_plugin_dir` must FAIL LOUD, not silently skip.
//!
//! A file with a plugin extension (`.so`/`.dylib`/`.dll`) inside a
//! `--plugin-dir` is an INTENDED, TRUSTED plugin. If it can't be loaded — most
//! importantly when its detached `.sig` is missing/stale/invalid (the exact
//! shape of a plugin that was rebuilt but not re-signed) — the daemon must
//! refuse to boot rather than log a warning and carry on short a plugin the
//! operator asked for. The old behaviour swallowed the failure as
//! `warn! "skip plugin"`, so the daemon booted "healthy" and the missing plugin
//! only surfaced far downstream as a mystery "service not found". This guards
//! the loader change that turned that skip into a hard error.
//!
//! Signature verification runs BEFORE `dlopen` (so unverified code never runs),
//! so an unsigned junk file fails at the signature gate — the test needs no
//! real dylib, only a plugin-extension file with no sibling `.sig`.

use std::sync::Arc;

use kernel::kernel::Kernel;

fn plugin_ext() -> &'static str {
    if cfg!(target_os = "windows") {
        "dll"
    } else if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    }
}

#[test]
fn unsigned_plugin_in_dir_fails_the_dir_load_loud() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A plugin-extension file with NO sibling `.sig` — a rebuilt-but-unsigned
    // plugin, or a stray dll in the trusted dir. Either MUST fail loud.
    let fake = tmp.path().join(format!("pretend_plugin.{}", plugin_ext()));
    std::fs::write(&fake, b"unsigned bytes; never reaches dlopen").expect("write fake plugin");

    let kernel = Arc::new(Kernel::new());
    let err = kernel
        .load_plugin_dir(tmp.path())
        .expect_err("an unsigned plugin file must fail the dir load loud, not be skipped");

    assert!(
        err.contains("pretend_plugin"),
        "the error must name the offending plugin, got: {err}"
    );
    assert!(
        err.to_lowercase().contains("signature"),
        "the error must attribute the failure to the missing signature, got: {err}"
    );
}

#[test]
fn empty_plugin_dir_is_ok() {
    // An empty (or plugin-free) dir loads zero plugins without error — fail-loud
    // is about files that LOOK like plugins but can't load, not about the
    // absence of any.
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("notes.txt"), b"not a plugin").expect("write non-plugin file");

    let kernel = Arc::new(Kernel::new());
    let loaded = kernel
        .load_plugin_dir(tmp.path())
        .expect("a dir with no plugin-extension files loads cleanly");
    assert!(
        loaded.is_empty(),
        "no plugins should load from a plugin-free dir"
    );
}
