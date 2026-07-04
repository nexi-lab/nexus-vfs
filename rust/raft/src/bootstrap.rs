//! Daemon boot decision layer for the unified bring-up (S3 完全体).
//!
//! Purpose: replace the unconditional `bootstrap_static_async` call at
//! the federation branch of `run_daemon` (in `rust/profiles/cluster/
//! src/main.rs`) with a typed decision matrix.  Before this module the
//! operator had to hand-script founder vs joiner semantics via three
//! separate env-var / CLI combinations across two entry points
//! (`daemon` and offline `join` sidecar); after, the daemon reads the
//! combined `(identity.peers, --peers, NEXUS_FEDERATION_ZONES)` triple
//! and dispatches deterministically.
//!
//! This is a **pure decision layer**.  No I/O, no env access, no
//! ZoneManager coupling.  Callers (the cluster binary) parse env vars,
//! load identity, resolve peer addresses — and then hand the resulting
//! [`BootConfig`] to [`plan_boot_action`].  The returned [`BootAction`]
//! carries all payload the caller needs to drive the corresponding
//! existing primitive (`bootstrap_static_async`,
//! `bootstrap_or_join_zone`, or `std::process::exit(1)`).
//!
//! The decision function itself never returns an error — its output
//! `FailLoud` variant is the diagnostic path.  Callers surface the
//! reason + hint to stderr and exit non-zero rather than propagating a
//! `Result`; boot-time misconfig is not recoverable.
//!
//! ### Decision matrix
//!
//! | identity.peers | CLI --peers | NEXUS_FEDERATION_ZONES | Action |
//! |---|---|---|---|
//! | empty | empty | set | [`BootAction::StaticFounder`] — auto-create SOLO |
//! | empty | empty | unset | [`BootAction::RootlessDynamic`] — daemon up, no zone auto-boot |
//! | empty | non-empty | unset | [`BootAction::JoinFederationZones`] — joiner (fresh) |
//! | non-empty | any | unset | [`BootAction::JoinFederationZones`] — joiner (return) |
//! | non-empty | any | set | [`BootAction::FailLoud`] — split-brain trap (existing PR #112 guard) |
//! | empty | non-empty | set | [`BootAction::FailLoud`] — ambiguous (NEW guard) |
//!
//! ### Symmetric-boot race
//!
//! Two fresh nodes with `--peers` pointed at each other + neither
//! declares `NEXUS_FEDERATION_ZONES` both hit row 3.  Each retries
//! `bootstrap_or_join_zone` up to `max_attempts=Some(15)` against a
//! peer that itself has no zones (JoinZone RPC fails until a founder
//! exists).  After ~2 min both fail loud.  This is intentional — the
//! operator must break symmetry by declaring which node is the
//! founder (row 1) via `NEXUS_FEDERATION_ZONES`.  No tie-breaker in
//! this layer; fail-loud is the tie-breaker.

use std::collections::BTreeMap;

use crate::transport::NodeAddress;

/// Boot-time configuration the cluster binary hands to
/// [`plan_boot_action`].  Every field is *derived from* an operator
/// input (env var, CLI arg, on-disk file) but this struct itself is
/// I/O-free; the parsing happens upstream in `main.rs` so this crate
/// stays env-var-agnostic.
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// Peer address book previously persisted to `identity.json`.
    /// One string per peer in the operator-facing bare `"host:port"`
    /// form (identity's on-disk schema).  Non-empty means this node
    /// has seen peers on a prior boot and should treat itself as a
    /// returning member unless the operator has explicitly changed
    /// role via `NEXUS_FEDERATION_ZONES`.
    pub identity_persisted_peers: Vec<String>,

    /// CLI `--peers` / `NEXUS_PEERS` parsed via
    /// `NodeAddress::parse_peer_list_operator`.  Empty when the
    /// operator did not pass any.  This is the CLI-only view; it is
    /// NOT the identity ∪ CLI union (that is
    /// `identity_persisted_peers` which was rewritten to the union at
    /// `open_zone_manager` time).  Kept as `NodeAddress` so
    /// [`BootAction::JoinFederationZones`] can forward the parsed
    /// entries into `bootstrap_or_join_zone` without a re-parse.
    pub cli_peer_addrs: Vec<NodeAddress>,

    /// `NEXUS_FEDERATION_ZONES` parsed into a deduped, ordered list of
    /// zone ids.  Empty when unset.
    pub federation_zones: Vec<String>,

    /// `NEXUS_FEDERATION_MOUNTS` parsed into `global_path → zone_id`.
    /// Empty when unset.  Passed through verbatim in the founder /
    /// joiner action so callers can call the same downstream primitive
    /// they used pre-refactor.
    pub federation_mounts: BTreeMap<String, String>,

    /// `NEXUS_BOOTSTRAP_NEW` toggle.  Not consumed by the matrix
    /// directly — it participates in the ROOT-zone bootstrap decision
    /// (existing `bootstrap_or_join_zone` for zone `"root"`), which
    /// runs *before* the federation branch this module owns.  Retained
    /// on `BootConfig` so future revisions of the matrix (e.g. Phase B
    /// identity.zones) have it in hand.
    pub bootstrap_new: bool,

    /// `<data_dir>/root/raft/` exists on disk — i.e. this is a
    /// restart, not a fresh bootstrap.  Same signal
    /// `validate_bootstrap_mode` uses at ROOT bootstrap.  Not consumed
    /// by the matrix in Phase A (all rows are federation-branch, which
    /// runs after ROOT bootstrap has already resolved restart vs new);
    /// carried for symmetry with `bootstrap_new` and forward
    /// compatibility.
    pub has_disk_state: bool,
}

/// What the daemon should do at the federation branch of boot,
/// given a resolved [`BootConfig`].
#[derive(Debug, Clone)]
pub enum BootAction {
    /// Founder path — this node auto-creates each declared zone as a
    /// SOLO 1-voter cluster and installs the DT_MOUNT entries.
    /// Corresponds to the pre-refactor call to
    /// `ZoneManager::bootstrap_static_async(zones, peers_for_ha,
    /// mounts)`.
    ///
    /// `peers_for_ha` is the CLI `--peers` list projected into the
    /// raft-internal `"id@host:port"` form (via
    /// `NodeAddress::to_raft_peer_str`) — forwarded to
    /// `bootstrap_static_async` verbatim so the founder's local
    /// transport peer map is seeded with future HA members even though
    /// the initial ConfState is `[self]` only.
    StaticFounder {
        zones: Vec<String>,
        mounts: BTreeMap<String, String>,
        peers_for_ha: Vec<String>,
    },

    /// Nothing to do at the federation branch.  Daemon comes up with
    /// ROOT (already bootstrapped in the prior branch), and any zone
    /// join happens via the offline `nexusd-cluster join` sidecar or a
    /// runtime API call.  Matches the pre-refactor "federation env
    /// vars unset → skip bootstrap_static" behaviour.
    RootlessDynamic,

    /// Joiner path — this node dispatches a per-zone
    /// `bootstrap_or_join_zone(..., max_attempts=Some(15),
    /// as_learner=false)` against `peers` for each zone in `zones`.
    /// Reuses the same primitive `run_join` calls.
    ///
    /// Phase A: `zones` is always empty in practice (matrix rows 3 + 4
    /// have `NEXUS_FEDERATION_ZONES` UNSET).  The dispatcher in
    /// `run_daemon` treats an empty `zones` list as a no-op (daemon
    /// stays up, root bootstrapped, operator continues to use the
    /// offline `join` CLI).  Phase B populates `zones` from
    /// `identity.zones` for automatic re-connect.
    JoinFederationZones {
        peers: Vec<NodeAddress>,
        zones: Vec<String>,
        mounts: BTreeMap<String, String>,
    },

    /// Boot-time misconfig the daemon refuses to recover from.
    /// Caller surfaces `reason` + `hint` and exits non-zero.
    ///
    /// `reason` is a short `&'static str` category (used in exit-code
    /// grep, telemetry, tests).  `hint` is an operator-actionable
    /// paragraph including the offending values so the log line is
    /// self-contained.
    FailLoud { reason: &'static str, hint: String },
}

/// Reason tag for the identity ∪ zones-set split-brain trap
/// (existing PR #112 guard — replayed here so both the guard and this
/// decision layer surface the same tag in logs / tests).
pub const REASON_SPLIT_BRAIN_IDENTITY_AND_ZONES: &str = "split_brain_identity_and_zones";

/// Reason tag for the NEW ambiguous-boot trap: empty identity +
/// non-empty CLI peers + `NEXUS_FEDERATION_ZONES` set.  The operator
/// declared both "I am a founder" (via `NEXUS_FEDERATION_ZONES`) and
/// "here are other nodes to talk to" (via `--peers`) with no persisted
/// history to disambiguate.  Racing with another fresh founder on
/// those peers deterministically produces two disjoint SOLO clusters
/// sharing zone names.  Refuse rather than roll dice.
pub const REASON_AMBIGUOUS_FRESH_FOUNDER_WITH_PEERS: &str = "ambiguous_fresh_founder_with_peers";

/// Decide what the daemon should do at the federation branch of boot.
///
/// Total function — no `Result` return; misconfig is surfaced via
/// [`BootAction::FailLoud`] so callers uniformly funnel through one
/// exit-code path.
///
/// ### Decision matrix
///
/// | # | identity.peers | CLI --peers | `NEXUS_FEDERATION_ZONES` | Action |
/// |---|---|---|---|---|
/// | 1 | empty     | empty     | set     | [`BootAction::StaticFounder`] — auto-create SOLO |
/// | 2 | empty     | empty     | unset   | [`BootAction::RootlessDynamic`] — daemon up, no zone auto-boot |
/// | 3 | empty     | non-empty | unset   | [`BootAction::JoinFederationZones`] — joiner (fresh) |
/// | 4 | non-empty | any       | unset   | [`BootAction::JoinFederationZones`] — joiner (return) |
/// | 5 | non-empty | any       | set     | [`BootAction::FailLoud`] — split-brain trap (PR #112) |
/// | 6 | empty     | non-empty | set     | [`BootAction::FailLoud`] — ambiguous (NEW) |
///
/// Precedence: rows are evaluated top-to-bottom on the guard clauses,
/// but the layout above matches how the function reads: rows 5 + 6
/// fire first (fail-loud), then row 1 (founder), then rows 3/4
/// (joiner), then row 2 (dynamic fallback).  Row 5 vs row 6: when
/// both identity peers AND CLI peers exist alongside zones, row 5
/// wins — see [`row5_precedence_when_both_identity_and_cli_have_peers`]
/// (in the tests module).
///
/// `NEXUS_FEDERATION_MOUNTS` counts as "zones set" for the matrix
/// (either env var triggers the founder / trap semantics — the
/// federation branch acts uniformly on the union).
pub fn plan_boot_action(cfg: &BootConfig) -> BootAction {
    let identity_has_peers = !cfg.identity_persisted_peers.is_empty();
    let cli_has_peers = !cfg.cli_peer_addrs.is_empty();
    let zones_set = !cfg.federation_zones.is_empty() || !cfg.federation_mounts.is_empty();

    // Row 5: identity already knows peers AND operator declared
    // founder intent.  Matches PR #112's split-brain guard verbatim —
    // that guard remains in `run_daemon` as defense-in-depth, this
    // arm just funnels the same class through the same fail-loud
    // dispatch used by the new row-6 case.
    if identity_has_peers && zones_set {
        return BootAction::FailLoud {
            reason: REASON_SPLIT_BRAIN_IDENTITY_AND_ZONES,
            hint: format!(
                "identity.json already lists peers ({:?}) but NEXUS_FEDERATION_ZONES \
                 is set (zones={:?}).  This is the both-founder misconfig: a node \
                 that already knows peers must join them, not auto-create.  \
                 Either (a) FOUNDER: rm the identity file and re-run, or \
                 (b) JOINER: unset NEXUS_FEDERATION_ZONES / NEXUS_FEDERATION_MOUNTS \
                 and let the daemon join via identity peers.",
                cfg.identity_persisted_peers, cfg.federation_zones,
            ),
        };
    }

    // Row 6 (NEW): fresh disk (no identity peers) but operator passed
    // BOTH `--peers` AND `NEXUS_FEDERATION_ZONES`.  Two contradictory
    // role declarations with no history to break the tie.
    if !identity_has_peers && cli_has_peers && zones_set {
        let peer_strs: Vec<String> = cfg
            .cli_peer_addrs
            .iter()
            .map(NodeAddress::to_operator_str)
            .collect();
        return BootAction::FailLoud {
            reason: REASON_AMBIGUOUS_FRESH_FOUNDER_WITH_PEERS,
            hint: format!(
                "empty identity + --peers={:?} + NEXUS_FEDERATION_ZONES={:?} is \
                 ambiguous.  --peers declares 'I am a joiner, contact these \
                 nodes'; NEXUS_FEDERATION_ZONES declares 'I am a founder, \
                 auto-create these zones'.  Two fresh nodes both booting this \
                 way would deterministically produce a split-brain.  Choose one: \
                 (a) FOUNDER — drop --peers, keep NEXUS_FEDERATION_ZONES, or \
                 (b) JOINER — drop NEXUS_FEDERATION_ZONES / \
                 NEXUS_FEDERATION_MOUNTS, keep --peers.",
                peer_strs, cfg.federation_zones,
            ),
        };
    }

    // Row 1: pure founder — no peers on either side, zones declared.
    if zones_set {
        let peers_for_ha = cfg
            .cli_peer_addrs
            .iter()
            .map(NodeAddress::to_raft_peer_str)
            .collect();
        return BootAction::StaticFounder {
            zones: cfg.federation_zones.clone(),
            mounts: cfg.federation_mounts.clone(),
            peers_for_ha,
        };
    }

    // Rows 3 + 4: peers known (identity, CLI, or both) + no zones
    // declared → joiner path.  Phase A: `zones` list is empty; the
    // dispatcher treats this as "no auto-join at boot" and the offline
    // `nexusd-cluster join` sidecar remains the mechanism for zone
    // joining.  Phase B populates `zones` from `identity.zones`.
    if identity_has_peers || cli_has_peers {
        return BootAction::JoinFederationZones {
            peers: cfg.cli_peer_addrs.clone(),
            zones: cfg.federation_zones.clone(),
            mounts: cfg.federation_mounts.clone(),
        };
    }

    // Row 2: nothing declared at all.  Root already bootstrapped in
    // the caller's ROOT branch; here we just return the "no extra
    // federation work" signal.
    BootAction::RootlessDynamic
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_peer(host: &str, port: u16) -> NodeAddress {
        NodeAddress::new(0, format!("http://{host}:{port}"))
    }

    fn cfg_with(
        identity: Vec<&str>,
        cli: Vec<NodeAddress>,
        zones: Vec<&str>,
        mounts: BTreeMap<String, String>,
    ) -> BootConfig {
        BootConfig {
            identity_persisted_peers: identity.into_iter().map(str::to_string).collect(),
            cli_peer_addrs: cli,
            federation_zones: zones.into_iter().map(str::to_string).collect(),
            federation_mounts: mounts,
            bootstrap_new: false,
            has_disk_state: false,
        }
    }

    fn mount(path: &str, zone: &str) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(path.to_string(), zone.to_string());
        m
    }

    // ── Row 1 ─────────────────────────────────────────────────────────
    #[test]
    fn row1_pure_founder_returns_static_founder() {
        let cfg = cfg_with(
            vec![],
            vec![],
            vec!["sharedzone"],
            mount("/shared", "sharedzone"),
        );
        match plan_boot_action(&cfg) {
            BootAction::StaticFounder {
                zones,
                mounts,
                peers_for_ha,
            } => {
                assert_eq!(zones, vec!["sharedzone".to_string()]);
                assert_eq!(
                    mounts.get("/shared").map(String::as_str),
                    Some("sharedzone")
                );
                assert!(peers_for_ha.is_empty(), "no CLI peers → empty HA seed");
            }
            other => panic!("expected StaticFounder, got {other:?}"),
        }
    }

    #[test]
    fn row1_founder_with_only_mounts_and_no_zones_env_still_founds() {
        // NEXUS_FEDERATION_MOUNTS alone (without NEXUS_FEDERATION_ZONES)
        // is treated as founder intent — the existing `bootstrap_static`
        // path in run_daemon fires whenever either env var is set.
        let cfg = cfg_with(vec![], vec![], vec![], mount("/shared", "sharedzone"));
        assert!(matches!(
            plan_boot_action(&cfg),
            BootAction::StaticFounder { .. }
        ));
    }

    // ── Row 2 ─────────────────────────────────────────────────────────
    #[test]
    fn row2_no_peers_no_zones_returns_rootless_dynamic() {
        let cfg = cfg_with(vec![], vec![], vec![], BTreeMap::new());
        assert!(matches!(
            plan_boot_action(&cfg),
            BootAction::RootlessDynamic
        ));
    }

    // ── Row 3 ─────────────────────────────────────────────────────────
    #[test]
    fn row3_fresh_joiner_with_cli_peers_returns_join_federation_zones() {
        let cfg = cfg_with(
            vec![],
            vec![cli_peer("100.64.0.21", 2126)],
            vec![],
            BTreeMap::new(),
        );
        match plan_boot_action(&cfg) {
            BootAction::JoinFederationZones {
                peers,
                zones,
                mounts,
            } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].endpoint, "http://100.64.0.21:2126");
                assert!(
                    zones.is_empty(),
                    "phase A joiner path — no zones auto-declared"
                );
                assert!(mounts.is_empty());
            }
            other => panic!("expected JoinFederationZones, got {other:?}"),
        }
    }

    // ── Row 4 ─────────────────────────────────────────────────────────
    #[test]
    fn row4_returning_joiner_with_identity_peers_returns_join_federation_zones() {
        let cfg = cfg_with(vec!["100.64.0.21:2126"], vec![], vec![], BTreeMap::new());
        assert!(matches!(
            plan_boot_action(&cfg),
            BootAction::JoinFederationZones { .. }
        ));
    }

    #[test]
    fn row4_returning_joiner_with_identity_and_cli_still_joins() {
        // Identity dominates — CLI-only-not-yet-persisted is fine; the
        // union already lives in `identity_persisted_peers` (rewritten
        // at open_zone_manager).  Both non-empty is the S3 reconnect
        // pattern (identity remembers, CLI widens).
        let cfg = cfg_with(
            vec!["100.64.0.21:2126"],
            vec![cli_peer("100.64.0.22", 2126)],
            vec![],
            BTreeMap::new(),
        );
        assert!(matches!(
            plan_boot_action(&cfg),
            BootAction::JoinFederationZones { .. }
        ));
    }

    // ── Row 5 (existing PR #112 guard) ────────────────────────────────
    #[test]
    fn row5_identity_peers_plus_zones_returns_fail_loud() {
        let cfg = cfg_with(
            vec!["100.64.0.21:2126"],
            vec![],
            vec!["sharedzone"],
            mount("/shared", "sharedzone"),
        );
        match plan_boot_action(&cfg) {
            BootAction::FailLoud { reason, hint } => {
                assert_eq!(reason, REASON_SPLIT_BRAIN_IDENTITY_AND_ZONES);
                assert!(
                    hint.contains("100.64.0.21:2126") && hint.contains("sharedzone"),
                    "hint must include the offending values, got: {hint}",
                );
            }
            other => panic!("expected FailLoud, got {other:?}"),
        }
    }

    #[test]
    fn row5_identity_plus_mounts_only_still_fails_loud() {
        // The federation branch fires when EITHER zones OR mounts is
        // set — the split-brain trap applies to the mounts-only shape
        // too.
        let cfg = cfg_with(
            vec!["100.64.0.21:2126"],
            vec![],
            vec![],
            mount("/shared", "sharedzone"),
        );
        assert!(matches!(
            plan_boot_action(&cfg),
            BootAction::FailLoud { .. }
        ));
    }

    // ── Row 6 (NEW guard) ─────────────────────────────────────────────
    #[test]
    fn row6_fresh_founder_with_cli_peers_returns_fail_loud() {
        let cfg = cfg_with(
            vec![],
            vec![cli_peer("100.64.0.21", 2126)],
            vec!["sharedzone"],
            mount("/shared", "sharedzone"),
        );
        match plan_boot_action(&cfg) {
            BootAction::FailLoud { reason, hint } => {
                assert_eq!(reason, REASON_AMBIGUOUS_FRESH_FOUNDER_WITH_PEERS);
                assert!(
                    hint.contains("100.64.0.21:2126"),
                    "hint must surface the CLI peer: {hint}",
                );
                assert!(
                    hint.contains("sharedzone"),
                    "hint must surface the declared zones: {hint}",
                );
            }
            other => panic!("expected FailLoud, got {other:?}"),
        }
    }

    // ── Precedence: row 5 dominates row 6 when identity is populated ─
    #[test]
    fn row5_precedence_when_both_identity_and_cli_have_peers() {
        // Row 5 (identity + zones) is checked before row 6 (fresh + CLI
        // + zones).  When BOTH conditions match (identity non-empty AND
        // CLI non-empty AND zones set), we report the identity-driven
        // reason — because identity is the persistent signal and the
        // hint's remediation targets it.
        let cfg = cfg_with(
            vec!["100.64.0.21:2126"],
            vec![cli_peer("100.64.0.22", 2126)],
            vec!["sharedzone"],
            BTreeMap::new(),
        );
        match plan_boot_action(&cfg) {
            BootAction::FailLoud { reason, .. } => {
                assert_eq!(reason, REASON_SPLIT_BRAIN_IDENTITY_AND_ZONES);
            }
            other => panic!("expected FailLoud, got {other:?}"),
        }
    }

    // NOTE: no "row 1 with CLI peers" test — that shape (empty identity
    // + non-empty CLI + zones set) is caught by row 6 as FailLoud.  The
    // `peers_for_ha` field on `StaticFounder` is therefore unreachable
    // as non-empty under the current matrix; it is retained for
    // forward-compat with Phase B (identity.zones may seed HA members
    // without triggering row 6) and to preserve the shape of the
    // pre-refactor `bootstrap_static_async(zones, peers, mounts)` call.
    // Row 1's empty-peers pass-through is pinned by
    // `row1_pure_founder_returns_static_founder`.
}
