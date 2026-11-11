//! Node-bound operator intent: seed addresses and per-zone role intent.
//!
//! `identity.json` at a platform-native user-data location persists
//! the operator's seed addresses and the role this node asked for in each
//! zone, so `<NEXUS_DATA_DIR>` cleanup (Windows Storage Sense, antivirus,
//! ops scripts scanning `.nexus-vfs/`) does not force the operator to
//! re-specify `--peers` or re-join on the next boot.
//!
//! ### Scope
//!
//! Identity persists local intent only — never replicated state (member
//! addresses live in each zone's state machine) and not `node_id`.  Raft's
//! per-`Progress` heartbeat commit invariant
//! ([`test_handle_heartbeat_on_empty_follower_with_stale_commit_panics`](../raft/storage.rs))
//! requires wipe-rejoin to rotate `node_id` — reusing the old id
//! against a leader that still remembers `Progress[old_id].matched > 0`
//! trips `RaftLog::commit_to` on the fresh follower (`last_index=0`).
//! Node identity therefore stays at `<data_dir>/.node_id` with its
//! rotate-on-wipe lifecycle.
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
///
/// Version history:
///   * v1 (PR #106): peers only.
///   * v2 (S3 完全体 Phase B): adds `zones` — per-zone role intent for
///     auto-reconnect after `data_dir` wipe.
///
/// Load rule: any version `<= SCHEMA_VERSION` is accepted; missing
/// fields default (e.g. v1 files load with `zones = []`) and fields this
/// build does not know are ignored.  Persist always writes the current
/// version, upgrading files in place on the next write.  Files with
/// `schema_version > SCHEMA_VERSION` refuse to load — forward-incompatible
/// schemas are never silently downgraded.
pub const SCHEMA_VERSION: u32 = 2;

/// On-disk shape of `identity.json`.  Narrow by design: seed addresses +
/// per-zone role intent.  Anything derivable from raft state (ConfState,
/// member addresses, log, snapshots) belongs in the replicated SSOT.
/// `node_id` is deliberately NOT here — see module docs; Phase C
/// reconsiders after the raft-rs Progress reset work.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub schema_version: u32,
    /// Operator seed addresses — `"host:port"` strings, same schema as
    /// CLI `--peers` / `NEXUS_PEERS`.  RPC targets (JoinZone,
    /// DiscoverZones, member-address registration), NOT a `ConfState`
    /// shadow and never zone routes.  Persisted so cold-boot after
    /// `<NEXUS_DATA_DIR>` loss can still contact known nodes without
    /// operator re-specifying.  Peer node_ids are not encoded.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Zones this node participates in, with the role it asked for —
    /// written when a zone is set up here, so a boot with a wiped
    /// `data_dir` still knows which zones' JoinZone to dispatch.  See
    /// [`IdentityZone`].
    ///
    /// v1 files load with an empty `zones` vec via `#[serde(default)]`;
    /// the next persist upgrades the file to v2 on disk.
    #[serde(default)]
    pub zones: Vec<IdentityZone>,
}

/// Per-zone entry in [`Identity::zones`].
///
/// `as_role` is this node's DURABLE role INTENT for the zone — the role
/// it *wants* (voter/learner), as declared at join and written once by
/// [`persist_zone_intent`].  Boot reads it to reissue JoinZone with the
/// right role.  It is NOT the achieved role: that is ephemeral,
/// ConfState-derived runtime state (a would-be-voter is transiently a
/// learner mid-promote), and is deliberately never persisted — doing so
/// stranded a mid-promote node as a permanent learner.  The old PR #57
/// deadlock (a not-caught-up node counting toward quorum) is now
/// prevented at the source by the learner-then-promote JoinZone (the
/// leader adds a learner and promotes only once caught up), so recording
/// intent here is safe.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityZone {
    pub zone_id: String,
    /// The role this node asked for in the zone.
    #[serde(default)]
    pub as_role: IdentityZoneRole,
}

/// The role this node asks for in a zone.
/// Wire form is lowercase JSON — `"voter"` / `"learner"`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityZoneRole {
    #[default]
    Voter,
    Learner,
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
            if ident.schema_version > SCHEMA_VERSION {
                return Err(format!(
                    "identity file '{}' schema_version={} is newer than the \
                     supported version {SCHEMA_VERSION} — refusing to silently \
                     downgrade (a forward-incompatible schema exists on disk; \
                     inspect + upgrade the daemon, or remove the file if you \
                     know what you're doing)",
                    path.display(),
                    ident.schema_version,
                ));
            }
            if ident.schema_version < SCHEMA_VERSION {
                // Leave the returned struct at the on-disk version so
                // `persist_peers` / `persist_zone_intent` see the gap
                // and force a rewrite even if the peer set is unchanged.
                // A boot that only reads (`share`/`join` audit paths)
                // never rewrites the file; a boot that touches identity
                // upgrades in place.
                tracing::info!(
                    identity_path = %path.display(),
                    from_version = ident.schema_version,
                    to_version = SCHEMA_VERSION,
                    "identity schema is older than current — upgrade lands on next persist",
                );
            }
            tracing::info!(
                identity_path = %path.display(),
                on_disk_version = ident.schema_version,
                persisted_peers = ident.peers.len(),
                persisted_zones = ident.zones.len(),
                "identity loaded from disk",
            );
            Ok(ident)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Identity {
            schema_version: SCHEMA_VERSION,
            peers: Vec::new(),
            zones: Vec::new(),
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
    // No-op if peer set unchanged AND the on-disk file already carries
    // the current SCHEMA_VERSION.  A v1 file that survived without
    // widening still needs a write to upgrade to v2 — otherwise a fresh
    // `data_dir` wipe would find a v1 file with no zones, take the
    // JoinFederationZones no-op branch, and never fill zones.
    let on_disk_matches = merged == existing.peers
        && identity_dir.join(IDENTITY_FILE).exists()
        && existing.schema_version == SCHEMA_VERSION;
    if on_disk_matches {
        return Ok(existing.clone());
    }
    let updated = Identity {
        schema_version: SCHEMA_VERSION,
        peers: merged,
        zones: existing.zones.clone(),
    };
    let path = identity_dir.join(IDENTITY_FILE);
    atomic_write(&path, &updated)?;
    tracing::info!(
        identity_path = %path.display(),
        peers = updated.peers.len(),
        zones = updated.zones.len(),
        "identity peers persisted",
    );
    Ok(updated)
}

/// Record this node's DURABLE role INTENT for a zone (voter/learner as the
/// operator declared at join) into `identity.json`.  This is the SSOT for
/// "what role do I want to be", read at boot to reissue JoinZone with the
/// right role; the ACHIEVED role is derived at runtime from ConfState and
/// is never persisted (persisting it strands a mid-promote would-be-voter
/// as a permanent learner).  Called once at zone setup
/// ([`crate::raft::ZoneRaftRegistry`] `setup_zone`).  Idempotent: a no-op
/// when the recorded intent already matches.
pub fn persist_zone_intent(
    identity_dir: &Path,
    existing: &Identity,
    zone_id: &str,
    desired_role: IdentityZoneRole,
) -> Result<Identity, String> {
    let mut zones = existing.zones.clone();
    match zones.iter_mut().find(|z| z.zone_id == zone_id) {
        Some(slot) => {
            if slot.as_role == desired_role && existing.schema_version == SCHEMA_VERSION {
                return Ok(existing.clone());
            }
            slot.as_role = desired_role;
        }
        None => zones.push(IdentityZone {
            zone_id: zone_id.to_string(),
            as_role: desired_role,
        }),
    }
    let updated = Identity {
        schema_version: SCHEMA_VERSION,
        peers: existing.peers.clone(),
        zones,
    };
    let path = identity_dir.join(IDENTITY_FILE);
    atomic_write(&path, &updated)?;
    tracing::info!(
        identity_path = %path.display(),
        zone = %zone_id,
        desired_role = ?desired_role,
        "identity zone role intent persisted",
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
    lib::file_durability::replace_file(&tmp, path)
        .map_err(|e| format!("rename '{}' -> '{}': {e}", tmp.display(), path.display(),))
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
        let seed = vec!["host-a:2126".to_string(), "host-b:2126".to_string()];
        let empty = load(dir.path()).unwrap();
        let persisted = persist_peers(dir.path(), &empty, &seed).unwrap();
        assert_eq!(persisted.peers, seed);

        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.peers, seed);
        assert_eq!(reloaded.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn forward_incompatible_schema_refuses_to_boot() {
        // schema_version > SCHEMA_VERSION means the file was written by
        // a newer daemon.  Never silently downgrade — the newer daemon
        // may rely on fields this build cannot serialize back.
        let dir = tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        fs::write(&path, br#"{"schema_version":99,"peers":[]}"#).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(err.contains("schema_version=99"), "err={err}");
    }

    #[test]
    fn v1_file_loads_with_empty_zones_and_reports_on_disk_version() {
        // Backward-compat: a v1 identity file (schema_version=1, no
        // zones field) must load cleanly with zones defaulted to [].
        // The returned struct preserves the on-disk schema_version so
        // downstream persist calls can detect the gap and force a
        // rewrite (schema upgrade).  On-disk file is untouched by
        // load itself.
        let dir = tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        fs::write(&path, br#"{"schema_version":1,"peers":["a:2126"]}"#).unwrap();

        let ident = load(dir.path()).unwrap();
        assert_eq!(ident.schema_version, 1, "load reports on-disk version");
        assert_eq!(ident.peers, vec!["a:2126"]);
        assert!(ident.zones.is_empty(), "v1 file loads with empty zones");

        // File on disk is unchanged.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains(r#""schema_version":1"#),
            "load MUST NOT rewrite; raw={raw}",
        );
    }

    #[test]
    fn v1_file_upgrades_on_disk_on_next_persist() {
        // Follow-up to the load-only test: persist_peers should upgrade
        // the on-disk schema_version to SCHEMA_VERSION even if peer set
        // is unchanged (the v1 -> v2 upgrade IS a material change).
        let dir = tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE);
        fs::write(&path, br#"{"schema_version":1,"peers":["a:2126"]}"#).unwrap();

        let loaded = load(dir.path()).unwrap();
        let same_peers = vec!["a:2126".to_string()];
        let persisted = persist_peers(dir.path(), &loaded, &same_peers).unwrap();
        assert_eq!(persisted.schema_version, SCHEMA_VERSION);
        assert!(persisted.zones.is_empty());

        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains(r#""schema_version": 2"#) || raw.contains(r#""schema_version":2"#),
            "v1 -> v2 upgrade must land on disk; raw={raw}",
        );
        // Round-trip: reload sees v2 with same peers.
        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.schema_version, SCHEMA_VERSION);
        assert_eq!(reloaded.peers, same_peers);
        assert!(reloaded.zones.is_empty());
    }

    #[test]
    fn persist_zone_intent_records_each_zone_once_and_flips_material_changes() {
        let dir = tempdir().unwrap();
        let ident = load(dir.path()).unwrap();

        let a =
            persist_zone_intent(dir.path(), &ident, "sharedzone", IdentityZoneRole::Voter).unwrap();
        assert_eq!(
            a.zones,
            vec![IdentityZone {
                zone_id: "sharedzone".into(),
                as_role: IdentityZoneRole::Voter,
            }]
        );
        let b = persist_zone_intent(dir.path(), &a, "corp-eng", IdentityZoneRole::Learner).unwrap();
        assert_eq!(b.zones.len(), 2);

        // Flipping the intent (voter -> learner) is a material change.
        let c =
            persist_zone_intent(dir.path(), &b, "sharedzone", IdentityZoneRole::Learner).unwrap();
        assert_eq!(c.zones.len(), 2, "same zone_id must not duplicate");
        assert_eq!(c.zones[0].as_role, IdentityZoneRole::Learner);

        // Idempotent: same intent again is a no-op and leaves the file alone.
        let path = dir.path().join(IDENTITY_FILE);
        let mtime_before = fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let d =
            persist_zone_intent(dir.path(), &c, "sharedzone", IdentityZoneRole::Learner).unwrap();
        assert_eq!(d, c);
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            mtime_before
        );
        assert_eq!(load(dir.path()).unwrap().zones, c.zones);
    }

    #[test]
    fn fields_older_versions_wrote_under_zones_load_and_are_ignored() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(IDENTITY_FILE),
            br#"{"schema_version":2,"peers":["a:2126"],"zones":[{"zone_id":"sharedzone",
                "members":["a:2126","b:2126"],"as_role":"learner",
                "last_confirmed_unix_secs":1700000000}]}"#,
        )
        .unwrap();
        let ident = load(dir.path()).unwrap();
        assert_eq!(ident.peers, vec!["a:2126"]);
        assert_eq!(
            ident.zones,
            vec![IdentityZone {
                zone_id: "sharedzone".into(),
                as_role: IdentityZoneRole::Learner,
            }]
        );
        // The next write carries only the current fields.
        let rewritten =
            persist_zone_intent(dir.path(), &ident, "corp-eng", IdentityZoneRole::Voter).unwrap();
        let raw = fs::read_to_string(dir.path().join(IDENTITY_FILE)).unwrap();
        assert!(
            !raw.contains("members") && !raw.contains("last_confirmed"),
            "{raw}"
        );
        assert_eq!(load(dir.path()).unwrap(), rewritten);
    }

    #[test]
    fn persist_peers_widens_monotonically_and_dedups() {
        let dir = tempdir().unwrap();
        let ident = persist_peers(
            dir.path(),
            &load(dir.path()).unwrap(),
            &["a:2126".to_string()],
        )
        .unwrap();
        let widened = persist_peers(
            dir.path(),
            &ident,
            &["a:2126".to_string(), "b:2126".to_string()],
        )
        .unwrap();
        assert_eq!(widened.peers, vec!["a:2126", "b:2126"]);

        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.peers, widened.peers);
    }

    #[test]
    fn persist_peers_noop_when_set_unchanged() {
        let dir = tempdir().unwrap();
        let seed = vec!["a:2126".to_string()];
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
            &["".to_string(), "a:2126".to_string(), " ".to_string()],
        )
        .unwrap();
        assert_eq!(ident.peers, vec!["a:2126", " "]);
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
