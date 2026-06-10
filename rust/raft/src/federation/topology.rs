//! Static Day-1 federation topology — env-var parsers.
//!
//! The cluster binary (rust/cluster/) reads these at startup and
//! feeds the result into [`crate::ZoneManager::bootstrap_static`] +
//! [`crate::ZoneManager::apply_topology`].
//!
//! Mirrors the contract Python `nexus.raft.federation` used to expose
//! before deletion: every node in the federation reads the same
//! environment and converges on the same topology.

use std::collections::BTreeMap;

/// Variable name carrying the comma-separated list of non-root zone
/// ids to create (e.g. `"corp,corp-eng,family"`).
pub const ENV_FEDERATION_ZONES: &str = "NEXUS_FEDERATION_ZONES";

/// Variable name carrying the global path → zone id mount map
/// (e.g. `"/corp=corp,/corp/eng=corp-eng,/home/family=family"`).
pub const ENV_FEDERATION_MOUNTS: &str = "NEXUS_FEDERATION_MOUNTS";

/// Parse `NEXUS_FEDERATION_ZONES` into a deduplicated, order-preserving
/// list of zone ids. Empty / unset → empty list.
pub fn parse_zones_env() -> Vec<String> {
    parse_zones_str(&std::env::var(ENV_FEDERATION_ZONES).unwrap_or_default())
}

fn parse_zones_str(csv: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.to_string()))
        .map(str::to_string)
        .collect()
}

/// One `NEXUS_FEDERATION_MOUNTS` entry the parser refused, plus the
/// reason.  Surfaced so the cluster binary can ERROR (not silently
/// drop) when an operator clearly intended a mount but the parser ate
/// it — e.g. Windows MSYS Git Bash converting `/shared` into
/// `C:/Program Files/Git/shared` before `nexusd-cluster` ever sees the
/// env var.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedMount {
    pub raw: String,
    pub reason: &'static str,
}

/// Full result of parsing `NEXUS_FEDERATION_MOUNTS`.
///
/// `mounts` is the resolved `path → zone_id` map (what the substrate
/// consumes).  `dropped` is one entry per invalid input segment with
/// a static-string reason — caller decides whether to ERROR (e.g. all
/// inputs were rejected ⇒ operator intent lost) or just WARN
/// (some inputs rejected, others landed).
#[derive(Debug)]
pub struct MountsParse {
    pub mounts: BTreeMap<String, String>,
    pub dropped: Vec<DroppedMount>,
    /// True iff the raw input had at least one non-empty entry
    /// between commas.  Distinguishes "operator intended nothing"
    /// (`raw_was_nonempty=false` ⇒ silently empty map is fine) from
    /// "operator intended something but parser ate it"
    /// (`raw_was_nonempty=true && mounts.is_empty()` ⇒ ERROR).
    pub raw_was_nonempty: bool,
}

impl MountsParse {
    /// `true` when the raw input had content but nothing survived the
    /// parser.  The cluster binary refuses to start in this state — a
    /// silent zero-mount federation has been an 8-hour debugging
    /// trap.
    pub fn is_silent_dropall(&self) -> bool {
        self.raw_was_nonempty && self.mounts.is_empty()
    }
}

/// Parse `NEXUS_FEDERATION_MOUNTS` into a [`MountsParse`].
///
/// Accepted format: comma-separated `<global_path>=<zone_id>` pairs.
/// Whitespace around segments is trimmed.  Entries are dropped — and
/// recorded in [`MountsParse::dropped`] — if any of these hold:
///
/// * the entry has no `=` separator
/// * the path before `=` is empty
/// * the zone id after `=` is empty
/// * the path does not start with `/` (Windows MSYS path conversion
///   surfaces here — `/shared` becomes `C:/Program Files/Git/shared`
///   silently, and the cluster binary then has nothing to mount)
pub fn parse_mounts_env() -> MountsParse {
    parse_mounts_str(&std::env::var(ENV_FEDERATION_MOUNTS).unwrap_or_default())
}

fn parse_mounts_str(csv: &str) -> MountsParse {
    let mut mounts = BTreeMap::new();
    let mut dropped = Vec::new();
    let mut raw_was_nonempty = false;
    for entry in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        raw_was_nonempty = true;
        match parse_one_mount(entry) {
            Ok((path, zone)) => {
                mounts.insert(path, zone);
            }
            Err(reason) => {
                dropped.push(DroppedMount {
                    raw: entry.to_string(),
                    reason,
                });
            }
        }
    }
    MountsParse {
        mounts,
        dropped,
        raw_was_nonempty,
    }
}

fn parse_one_mount(entry: &str) -> Result<(String, String), &'static str> {
    let Some((path, zone)) = entry.split_once('=') else {
        return Err("missing '=' separator between path and zone id");
    };
    let path = path.trim();
    let zone = zone.trim();
    if path.is_empty() {
        return Err("empty path before '='");
    }
    if zone.is_empty() {
        return Err("empty zone id after '='");
    }
    if !path.starts_with('/') {
        return Err(
            "path does not start with '/' — on Windows MSYS / Git Bash the shell rewrites \
             absolute Unix paths into Windows paths before exec; set MSYS_NO_PATHCONV=1 or \
             single-quote the env value",
        );
    }
    Ok((path.to_string(), zone.to_string()))
}

/// Full result of [`parse_federation_env`] — pair of the two env
/// parsers' outputs.
#[derive(Debug)]
pub struct FederationParse {
    pub zones: Vec<String>,
    pub mounts: MountsParse,
}

/// Convenience: read both env vars in one call.
pub fn parse_federation_env() -> FederationParse {
    FederationParse {
        zones: parse_zones_env(),
        mounts: parse_mounts_env(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zones_parses_comma_separated() {
        assert_eq!(parse_zones_str("corp,family"), vec!["corp", "family"]);
    }

    #[test]
    fn zones_trims_whitespace_and_dedupes() {
        assert_eq!(
            parse_zones_str("  corp , corp ,family,  "),
            vec!["corp", "family"]
        );
    }

    #[test]
    fn zones_empty_input_returns_empty() {
        assert!(parse_zones_str("").is_empty());
        assert!(parse_zones_str(",,").is_empty());
    }

    #[test]
    fn mounts_parses_path_zone_pairs() {
        let p = parse_mounts_str("/corp=corp,/family=family");
        assert_eq!(p.mounts.get("/corp"), Some(&"corp".to_string()));
        assert_eq!(p.mounts.get("/family"), Some(&"family".to_string()));
        assert_eq!(p.mounts.len(), 2);
        assert!(p.dropped.is_empty());
        assert!(p.raw_was_nonempty);
        assert!(!p.is_silent_dropall());
    }

    #[test]
    fn mounts_records_dropped_entries() {
        // No '=', empty path, empty zone, non-absolute path
        let p = parse_mounts_str("/ok=z,broken,=z,/p=,relative=z");
        assert_eq!(p.mounts.len(), 1);
        assert_eq!(p.mounts.get("/ok"), Some(&"z".to_string()));
        // Four entries were dropped, each with a distinct reason.
        assert_eq!(p.dropped.len(), 4);
        let reasons: Vec<&str> = p.dropped.iter().map(|d| d.reason).collect();
        assert!(reasons.iter().any(|r| r.contains("missing '='")));
        assert!(reasons.iter().any(|r| r.contains("empty path")));
        assert!(reasons.iter().any(|r| r.contains("empty zone")));
        assert!(reasons
            .iter()
            .any(|r| r.contains("does not start with '/'")));
        // SOME valid entry survived, so this is NOT a silent dropall.
        assert!(!p.is_silent_dropall());
    }

    #[test]
    fn mounts_btreemap_orders_by_path() {
        let p = parse_mounts_str("/corp/eng=eng,/corp=corp,/family=family");
        let keys: Vec<&str> = p.mounts.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["/corp", "/corp/eng", "/family"]);
    }

    #[test]
    fn mounts_trims_whitespace() {
        let p = parse_mounts_str("  /corp = corp ,  /eng = eng  ");
        assert_eq!(p.mounts.get("/corp"), Some(&"corp".to_string()));
        assert_eq!(p.mounts.get("/eng"), Some(&"eng".to_string()));
    }

    #[test]
    fn mounts_empty_input_is_not_dropall() {
        let p = parse_mounts_str("");
        assert!(p.mounts.is_empty());
        assert!(p.dropped.is_empty());
        assert!(!p.raw_was_nonempty);
        assert!(!p.is_silent_dropall());
    }

    #[test]
    fn mounts_only_blanks_is_not_dropall() {
        let p = parse_mounts_str(",,  ,");
        assert!(p.mounts.is_empty());
        assert!(p.dropped.is_empty());
        assert!(!p.raw_was_nonempty);
        assert!(!p.is_silent_dropall());
    }

    /// Regression for the Mac↔Win L1 smoke wedge: MSYS Git Bash on
    /// Windows expands `/shared` in an env value to
    /// `C:/Program Files/Git/shared` before exec.  The cluster binary
    /// then sees the mangled string, drops it (no leading `/`), and
    /// boots with `mount_count=0` — leaving the `/shared` namespace
    /// silently un-federated.  Operators spent 8 h tracing the
    /// downstream "raft step error: cannot step as peer not found"
    /// floods to this single root cause.  After this commit the
    /// parser surfaces the dropped entry and the cluster binary
    /// refuses to boot in the silent-dropall state.
    #[test]
    fn mounts_msys_path_conversion_lands_in_dropall() {
        let p = parse_mounts_str("C:/Program Files/Git/shared=sharedzone");
        assert!(p.mounts.is_empty());
        assert_eq!(p.dropped.len(), 1);
        assert!(p.dropped[0].reason.contains("does not start with '/'"));
        assert!(p.dropped[0].reason.contains("MSYS"));
        assert!(p.is_silent_dropall());
    }
}
