//! Node-bound peer address book persistence.
//!
//! `identity.json` at a platform-native user-data location persists
//! the raft transport peer address book so `<NEXUS_DATA_DIR>` cleanup
//! (Windows Storage Sense, antivirus, ops scripts scanning
//! `.nexus-vfs/`) does not force the operator to re-specify `--peers`
//! on the next boot.
//!
//! ### Scope
//!
//! Identity persists ONLY the peer list, not `node_id`.  Raft's
//! per-`Progress` heartbeat commit invariant
//! ([`test_handle_heartbeat_on_empty_follower_with_stale_commit_panics`](../raft/storage.rs))
//! requires wipe-rejoin to rotate `node_id` — reusing the old id
//! against a leader that still remembers `Progress[old_id].matched > 0`
//! trips `RaftLog::commit_to` on the fresh follower (`last_index=0`).
//! Node identity therefore stays at `<data_dir>/.node_id` with its
//! rotate-on-wipe lifecycle, and identity's role is narrowly the
//! *transport address book*.
//!
//! ### File layout and boot flow
//!
//! Schema and boot integration are documented in
//! `docs/federation-architecture.md` § 6.3.1.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// On-disk filename inside [`default_identity_dir`].
pub const IDENTITY_FILE: &str = "identity.json";

/// Current identity schema version.  Bump on any breaking field
/// rename / removal; add-only field extensions can be handled with
/// `#[serde(default)]`.
pub const SCHEMA_VERSION: u32 = 1;

/// On-disk shape of `identity.json`.  Intentionally narrow: peer
/// address book only.  Anything derivable from raft state (ConfState,
/// log, snapshots) belongs in the replicated SSOT.  `node_id` is
/// deliberately NOT here — see module docs for why.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Identity {
    pub schema_version: u32,
    /// Raft peer address book — `"id@host:port"` strings, same schema
    /// as CLI `--peers` / `NEXUS_PEERS` and hashicorp/raft's
    /// `peers.json`.  Transport seed only, NOT a `ConfState` shadow.
    /// Persisted so cold-boot after `<NEXUS_DATA_DIR>` loss can still
    /// contact known nodes without operator re-specifying.
    #[serde(default)]
    pub peers: Vec<String>,
}

/// Default `identity_dir` per platform-native user-data conventions:
///
/// | Platform | Path |
/// |---|---|
/// | Windows | `%LOCALAPPDATA%\Nexus` (non-roaming — identity is node-bound) |
/// | macOS   | `~/Library/Application Support/Nexus` |
/// | Linux   | `$XDG_DATA_HOME/nexus` (default `~/.local/share/nexus`) |
///
/// Fallbacks: environment vars missing → derive from `HOME` /
/// `USERPROFILE` with the same subdir tail.  Last-resort fallback
/// (`.`) means the identity file lands next to the daemon's CWD;
/// caller is expected to log this and it surfaces immediately since
/// the file will not survive typical CWD-relative cleanup.
pub fn default_identity_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|home| PathBuf::from(home).join("AppData").join("Local"))
            })
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Nexus")
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library")
            .join("Application Support")
            .join("Nexus")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".local").join("share"))
            })
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nexus")
    }
}

/// Load `identity.json` from `identity_dir`, returning an empty
/// identity when the file is absent.  Boot's contract is
/// "peer set = identity ∪ CLI"; a missing identity file is the
/// first-boot case and yields `Identity::default()`.
///
/// # Errors
///
/// - File present but not valid JSON — refuses to boot (operator
///   inspects + repairs or deletes).
/// - `schema_version` does not match [`SCHEMA_VERSION`] — refuses to
///   boot rather than silently downgrading.
pub fn load(identity_dir: &Path) -> Result<Identity, String> {
    let path = identity_dir.join(IDENTITY_FILE);
    match fs::read(&path) {
        Ok(bytes) => {
            let ident: Identity = serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse identity file '{}': {e}", path.display()))?;
            if ident.schema_version != SCHEMA_VERSION {
                return Err(format!(
                    "identity file '{}' schema_version={} does not match \
                     supported version {SCHEMA_VERSION}",
                    path.display(),
                    ident.schema_version,
                ));
            }
            tracing::info!(
                identity_path = %path.display(),
                persisted_peers = ident.peers.len(),
                "identity loaded from disk",
            );
            Ok(ident)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Identity {
            schema_version: SCHEMA_VERSION,
            peers: Vec::new(),
        }),
        Err(e) => Err(format!("read identity '{}': {e}", path.display())),
    }
}

/// Rewrite `identity.json` with the union of `existing` + `additions`,
/// preserving insertion order.  No-op when the merged peer set equals
/// the existing set — avoids gratuitous disk writes on every boot.
///
/// Used by boot when CLI `--peers` widens the transport seed: the
/// identity's `peers[]` tracks reachable peers monotonically so
/// subsequent cold boots have the widened list.
///
/// Returns the resulting (possibly unchanged) identity.
pub fn persist_peers(
    identity_dir: &Path,
    existing: &Identity,
    additions: &[String],
) -> Result<Identity, String> {
    let mut merged = existing.peers.clone();
    for peer in additions {
        if !peer.is_empty() && !merged.iter().any(|p| p == peer) {
            merged.push(peer.clone());
        }
    }
    if merged == existing.peers && identity_dir.join(IDENTITY_FILE).exists() {
        return Ok(existing.clone());
    }
    let updated = Identity {
        schema_version: SCHEMA_VERSION,
        peers: merged,
    };
    let path = identity_dir.join(IDENTITY_FILE);
    atomic_write(&path, &updated)?;
    tracing::info!(
        identity_path = %path.display(),
        peers = updated.peers.len(),
        "identity peers persisted",
    );
    Ok(updated)
}

fn atomic_write(path: &Path, ident: &Identity) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create identity dir '{}': {e}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(ident)
        .map_err(|e| format!("serialize identity '{}': {e}", path.display()))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| format!("create tmp identity '{}': {e}", tmp.display()))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write tmp identity '{}': {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("sync tmp identity '{}': {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        format!(
            "rename '{}' -> '{}': {e}",
            tmp.display(),
            path.display(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_missing_returns_empty_identity() {
        let dir = tempdir().unwrap();
        let ident = load(dir.path()).unwrap();
        assert_eq!(ident.schema_version, SCHEMA_VERSION);
        assert!(ident.peers.is_empty());
        assert!(
            !dir.path().join(IDENTITY_FILE).exists(),
            "load must not create the file"
        );
    }

    #[test]
    fn persist_then_load_roundtrips() {
        let dir = tempdir().unwrap();
        let seed = vec!["1@host-a:2126".to_string(), "2@host-b:2126".to_string()];
        let empty = load(dir.path()).unwrap();
        let persisted = persist_peers(dir.path(), &empty, &seed).unwrap();
        assert_eq!(persisted.peers, seed);

        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.peers, seed);
        assert_eq!(reloaded.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn schema_mismatch_refuses_to_boot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        fs::write(&path, br#"{"schema_version":99,"peers":[]}"#).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(err.contains("schema_version=99"), "err={err}");
    }

    #[test]
    fn persist_peers_widens_monotonically_and_dedups() {
        let dir = tempdir().unwrap();
        let ident = persist_peers(
            dir.path(),
            &load(dir.path()).unwrap(),
            &["1@a:2126".to_string()],
        )
        .unwrap();
        let widened = persist_peers(
            dir.path(),
            &ident,
            &["1@a:2126".to_string(), "2@b:2126".to_string()],
        )
        .unwrap();
        assert_eq!(widened.peers, vec!["1@a:2126", "2@b:2126"]);

        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.peers, widened.peers);
    }

    #[test]
    fn persist_peers_noop_when_set_unchanged() {
        let dir = tempdir().unwrap();
        let seed = vec!["1@a:2126".to_string()];
        let ident = persist_peers(dir.path(), &load(dir.path()).unwrap(), &seed).unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        let mtime_before = fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let same = persist_peers(dir.path(), &ident, &seed).unwrap();
        assert_eq!(same.peers, ident.peers);
        let mtime_after = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "no-op must not rewrite file");
    }

    #[test]
    fn persist_peers_drops_empty_strings() {
        let dir = tempdir().unwrap();
        let ident = persist_peers(
            dir.path(),
            &load(dir.path()).unwrap(),
            &["".to_string(), "1@a:2126".to_string(), " ".to_string()],
        )
        .unwrap();
        assert_eq!(ident.peers, vec!["1@a:2126", " "]);
        // Empty string is skipped; whitespace-only is preserved because
        // trimming is a caller-side concern.  Callers today feed peers
        // parsed via `NodeAddress::parse_peer_list` which trims before
        // calling `to_raft_peer_str`, so whitespace does not reach us
        // in practice — assertion pins the current schema behaviour.
    }

    #[test]
    fn default_identity_dir_is_platform_native() {
        let dir = default_identity_dir();
        #[cfg(target_os = "windows")]
        assert!(
            dir.ends_with("Nexus"),
            "windows path should end with Nexus: {dir:?}"
        );
        #[cfg(target_os = "macos")]
        assert!(
            dir.ends_with("Nexus"),
            "macos path should end with Nexus: {dir:?}"
        );
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(
            dir.ends_with("nexus"),
            "linux path should end with nexus: {dir:?}"
        );
    }
}
