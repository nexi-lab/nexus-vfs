//! VFS discovery and traversal shared by glob, grep and indexing.

use crate::kernel_io::{self, DirEntry, KernelIoError, DT_DIR, DT_REG, DT_STREAM};
use crate::search_proto::{DiscoveryFiles, GrepMatch};
const GREP_MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
use nexus_plugin_abi::KernelHandle;

/// Enumerate a validated working set without walking unrelated directories.
/// The gRPC host owns path validation, scope and permission checks.
fn visit_candidates(
    handle: &KernelHandle,
    root: &str,
    files: Option<&DiscoveryFiles>,
    visit: &mut dyn FnMut(&str, u8, Option<i64>) -> WalkAction,
) -> Result<(), KernelIoError> {
    match files {
        None => walk_recursive(handle, root, &mut |path, kind| {
            if ignored_discovery_path(path) {
                WalkAction::SkipSubtree
            } else {
                visit(path, kind, None)
            }
        }),
        Some(files) => {
            for path in &files.paths {
                match kernel_io::sys_stat(handle, path) {
                    Ok(stat) => {
                        if visit(path, stat.entry_type, stat.modified_at_ms) == WalkAction::Stop {
                            break;
                        }
                    }
                    Err(KernelIoError::NotFound) => {}
                    Err(error) => tracing::warn!(%path, ?error, "discovery: cannot stat candidate"),
                }
            }
            Ok(())
        }
    }
}

/// Recursive discovery skips build artifacts; working sets name exact candidates.
fn ignored_discovery_path(path: &str) -> bool {
    path.split('/').any(|part| {
        matches!(
            part,
            ".git"
                | ".svn"
                | ".hg"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | "__pycache__"
                | ".tox"
                | ".nox"
                | "dist"
                | "build"
                | ".next"
                | ".nuxt"
                | "target"
                | ".idea"
                | ".vscode"
                | ".DS_Store"
                | "Thumbs.db"
                | ".cache"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".ruff_cache"
                | "coverage"
                | ".coverage"
                | "htmlcov"
                | "logs"
        ) || [".swp", ".swo", ".pyc", ".pyo", ".log"]
            .iter()
            .any(|suffix| part.ends_with(suffix))
    })
}

pub(crate) fn do_glob(
    handle: &KernelHandle,
    root: &str,
    request: &crate::search_proto::GlobRequest,
    cap: usize,
) -> Result<(Vec<String>, bool), String> {
    let matcher = compile_glob(&request.pattern)?;
    let mut paths = Vec::new();
    let mut truncated = false;
    // The largest heap item is the oldest result, with later encounter
    // order breaking ties. Retain only the newest `cap` paths in memory.
    let mut newest = std::collections::BinaryHeap::new();
    let mut order = 0usize;
    visit_candidates(
        handle,
        root,
        request.files.as_ref(),
        &mut |path, kind, mtime| {
            if kind == DT_DIR || !glob_matches(&matcher, strip_root(root, path)) {
                return WalkAction::Continue;
            }
            if request.sort_recency {
                let mtime = if request.files.is_some() {
                    mtime
                } else {
                    kernel_io::sys_stat(handle, path)
                        .ok()
                        .and_then(|stat| stat.modified_at_ms)
                };
                let item = (std::cmp::Reverse(mtime), order, path.to_owned());
                order += 1;
                if newest.len() < cap {
                    newest.push(item);
                } else {
                    truncated = true;
                    if newest.peek().is_some_and(|worst| &item < worst) {
                        newest.pop();
                        newest.push(item);
                    }
                }
            } else {
                if paths.len() == cap {
                    truncated = true;
                    return WalkAction::Stop;
                }
                paths.push(path.to_owned());
            }
            WalkAction::Continue
        },
    )
    .map_err(walk_err_to_string)?;
    if request.sort_recency {
        paths = newest
            .into_sorted_vec()
            .into_iter()
            .map(|(_, _, path)| path)
            .collect();
    }
    Ok((paths, truncated))
}

fn compile_glob(pattern: &str) -> Result<Option<globset::GlobMatcher>, String> {
    if pattern.is_empty() {
        return Ok(None);
    }
    globset::Glob::new(pattern)
        .map(|glob| Some(glob.compile_matcher()))
        .map_err(|error| format!("invalid glob pattern {pattern:?}: {error}"))
}

fn glob_matches(matcher: &Option<globset::GlobMatcher>, relative: &str) -> bool {
    matcher
        .as_ref()
        .is_none_or(|matcher| matcher.is_match(relative))
}

pub(crate) fn do_grep(
    handle: &KernelHandle,
    root: &str,
    request: &crate::search_proto::GrepRequest,
    cap: usize,
    filter: &nexus_search_common::discovery::StructuralFilter,
) -> Result<(Vec<GrepMatch>, bool), String> {
    if request.pattern.is_empty() {
        return Err("grep pattern must not be empty".into());
    }
    let regex = regex::RegexBuilder::new(&request.pattern)
        .case_insensitive(request.ignore_case)
        .build()
        .map_err(|error| format!("invalid regex {:?}: {error}", request.pattern))?;
    let matcher = compile_glob(&request.file_pattern)?;
    let mut matches = Vec::new();
    let mut truncated = false;
    let options = ScanOptions {
        before_context: request.before_context as usize,
        after_context: request.after_context as usize,
        invert_match: request.invert_match,
        max_results: cap,
    };
    let mut scan = |path: &str| {
        match kernel_io::sys_read(handle, path) {
            Ok(bytes) if bytes.len() <= GREP_MAX_FILE_BYTES => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    let selection = crate::markdown::select_lines(path, text, filter);
                    truncated = grep_scan(
                        text,
                        path,
                        &regex,
                        options,
                        selection.as_ref(),
                        &mut matches,
                    );
                }
            }
            Ok(_) | Err(KernelIoError::NotFound) => {}
            Err(error) => tracing::warn!(%path, ?error, "grep: cannot read candidate"),
        }
        if truncated {
            WalkAction::Stop
        } else {
            WalkAction::Continue
        }
    };
    if request.sort_recency {
        // Sort file candidates before reading their content. This avoids
        // collecting all matching lines and keeps result memory O(cap).
        let mut candidates = Vec::new();
        visit_candidates(
            handle,
            root,
            request.files.as_ref(),
            &mut |path, kind, mtime| {
                if searchable_content_type(kind) && glob_matches(&matcher, strip_root(root, path)) {
                    let mtime = if request.files.is_some() {
                        mtime
                    } else {
                        kernel_io::sys_stat(handle, path)
                            .ok()
                            .and_then(|stat| stat.modified_at_ms)
                    };
                    candidates.push((std::cmp::Reverse(mtime), path.to_owned()));
                }
                WalkAction::Continue
            },
        )
        .map_err(walk_err_to_string)?;
        candidates.sort_by_key(|(mtime, _)| *mtime);
        for (_, path) in candidates {
            if scan(&path) == WalkAction::Stop {
                break;
            }
        }
    } else {
        visit_candidates(
            handle,
            root,
            request.files.as_ref(),
            &mut |path, kind, _mtime| {
                if searchable_content_type(kind) && glob_matches(&matcher, strip_root(root, path)) {
                    scan(path)
                } else {
                    WalkAction::Continue
                }
            },
        )
        .map_err(walk_err_to_string)?;
    }
    Ok((matches, truncated))
}

#[derive(Clone, Copy)]
pub(crate) struct ScanOptions {
    pub before_context: usize,
    pub after_context: usize,
    pub invert_match: bool,
    pub max_results: usize,
}

/// Append matching lines, returning true only when a further hit exceeds the cap.
pub(crate) fn grep_scan(
    text: &str,
    path: &str,
    regex: &regex::Regex,
    options: ScanOptions,
    selection: Option<&crate::markdown::LineSelection>,
    out: &mut Vec<GrepMatch>,
) -> bool {
    if selection.is_some_and(crate::markdown::LineSelection::is_empty) {
        return false;
    }
    // The common context-free path streams lines without a per-file line table.
    let context: Option<Vec<&str>> =
        (options.before_context != 0 || options.after_context != 0).then(|| text.lines().collect());
    for (idx, line) in text.lines().enumerate() {
        if selection.is_some_and(|selection| !selection.contains(idx)) {
            continue;
        }
        if regex.is_match(line) == options.invert_match {
            continue;
        }
        if out.len() >= options.max_results {
            return true;
        }
        let (before, after) = match &context {
            Some(lines) => {
                let start = idx.saturating_sub(options.before_context);
                let end = idx
                    .saturating_add(1)
                    .saturating_add(options.after_context)
                    .min(lines.len());
                (
                    lines[start..idx]
                        .iter()
                        .map(|line| (*line).to_owned())
                        .collect(),
                    lines[idx + 1..end]
                        .iter()
                        .map(|line| (*line).to_owned())
                        .collect(),
                )
            }
            None => (Vec::new(), Vec::new()),
        };
        out.push(GrepMatch {
            path: path.into(),
            line_number: idx as u32 + 1,
            line: line.into(),
            before,
            after,
            section: selection.and_then(|selection| selection.section.clone()),
        });
    }
    false
}

// ── Recursive walker (sync, uses KernelHandle FFI) ────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkAction {
    Continue,
    SkipSubtree,
    Stop,
}

/// Recursively walk `root_path` via `sys_readdir`; invoke `visit` on
/// every entry (files AND dirs) with its full VFS path + entry_type.
///
/// The walker is DFS pre-order (yield entry, then recurse if it's a
/// dir).  Errors on a specific sub-tree are logged and the walker
/// continues — a permission-denied sub-dir does not abort the whole
/// walk.  A `NotFound` on `root_path` itself is bubbled up.
pub(crate) fn walk_recursive(
    handle: &KernelHandle,
    root_path: &str,
    visit: &mut dyn FnMut(&str, u8) -> WalkAction,
) -> Result<(), KernelIoError> {
    let mut skipped_subtrees = 0u32;
    walk_recursive_tracked(handle, root_path, visit, &mut skipped_subtrees)
}

/// Like [`walk_recursive`] but also counts subtrees SKIPPED because
/// a nested `sys_readdir` failed transiently (#4628 review R9).
/// Refresh must know: files under a skipped subtree were not seen,
/// so "not seen" proves nothing — sweeping them as deleted would
/// erase live index data on a transient permission/mount error.
pub(crate) fn walk_recursive_tracked(
    handle: &KernelHandle,
    root_path: &str,
    visit: &mut dyn FnMut(&str, u8) -> WalkAction,
    skipped_subtrees: &mut u32,
) -> Result<(), KernelIoError> {
    // Root-level readdir has to succeed OR we bubble the error.  A
    // NotFound here means the caller pointed us at nothing.
    let root_entries = kernel_io::sys_readdir(handle, root_path)?;
    walk_entries(handle, root_path, root_entries, visit, skipped_subtrees);
    Ok(())
}

fn walk_entries(
    handle: &KernelHandle,
    parent: &str,
    entries: Vec<DirEntry>,
    visit: &mut dyn FnMut(&str, u8) -> WalkAction,
    skipped_subtrees: &mut u32,
) -> WalkAction {
    for entry in entries {
        let child_path = kernel_io::join_vfs_path(parent, &entry.name);
        match visit(&child_path, entry.entry_type) {
            WalkAction::Stop => return WalkAction::Stop,
            WalkAction::SkipSubtree => continue,
            WalkAction::Continue => {}
        }
        // Recurse into DT_DIR + DT_MOUNT (we walk THROUGH mounts
        // per the filesystem invariant that a mount replaces the
        // directory's contents; from the search plugin's view a
        // mount is a container of children just like a dir).
        if entry.entry_type == DT_DIR || entry.entry_type == kernel_io::DT_MOUNT {
            match kernel_io::sys_readdir(handle, &child_path) {
                Ok(child_entries) => {
                    if walk_entries(handle, &child_path, child_entries, visit, skipped_subtrees)
                        == WalkAction::Stop
                    {
                        return WalkAction::Stop;
                    }
                }
                Err(KernelIoError::NotFound) => {
                    // Race with a concurrent unlink / unmount — the
                    // subtree is genuinely GONE, so its cached files
                    // legitimately sweep as deleted.  Not counted.
                }
                Err(e) => {
                    *skipped_subtrees += 1;
                    tracing::warn!(
                        path = %child_path,
                        err = ?e,
                        "walk: sys_readdir failed — skipping subtree",
                    );
                }
            }
        }
    }
    WalkAction::Continue
}

pub(crate) fn strip_root<'a>(root: &str, path: &'a str) -> &'a str {
    let trimmed = root.trim_end_matches('/');
    if let Some(rest) = path.strip_prefix(trimmed) {
        rest.trim_start_matches('/')
    } else {
        path.trim_start_matches('/')
    }
}

/// Which VFS entry types carry searchable content — the SSOT for grep AND index
/// walks (both keyword and semantic). A DT_REG file and a DT_STREAM log both read
/// as one path-addressed document via `kernel_io::sys_read` (the host returns a
/// stream's whole collected log), so both are searched; DT_DIR / DT_MOUNT are
/// containers (`walk_recursive` descends them) and DT_PIPE is ephemeral, so
/// neither is a document.
pub(crate) fn searchable_content_type(entry_type: u8) -> bool {
    entry_type == DT_REG || entry_type == DT_STREAM
}

pub(crate) fn walk_err_to_string(e: KernelIoError) -> String {
    match e {
        KernelIoError::NotFound => "root_path not found".into(),
        other => format!("kernel io: {other:?}"),
    }
}
