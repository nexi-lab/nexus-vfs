//! Egress content gate — the enforcement point for "data does not leave
//! this node".
//!
//! # The problem this solves
//!
//! An appliance deployed at a customer site promises that their data stays
//! on it. Path-level containment already holds the inbound direction: a
//! foreign agent can only reach its own mailbox. But containment answers
//! *where may this caller write*, and the promise being made here is about
//! *what is in the bytes* — a message an authorised agent is perfectly
//! entitled to send can still carry a customer's identity numbers in its
//! body. No amount of path authorization sees that.
//!
//! # Why it is a write hook and not a permission provider
//!
//! The kernel has exactly one `PermissionProvider` slot, it is a path gate,
//! and it short-circuits on `is_system == true`. Content is not in its
//! question. `Kernel::apply_mutating_write_hooks` is the right seam for
//! three reasons:
//!
//! * it is the **single** seam every write syscall funnels through —
//!   `sys_write` / `write_batch` (DT_FILE), `stream_write_nowait`
//!   (DT_STREAM), `pipe_write_nowait` (DT_PIPE) — so the gate cannot be
//!   bypassed by choosing a different RPC;
//! * `Err` from a pre-hook aborts the write, so refusal is expressible;
//! * `HookOutcome::Replace` is honoured on every one of those paths, so
//!   **redaction** is expressible too, not just refusal — including on the
//!   replicated A2A transcript, which is a DT_STREAM.
//!
//! # Shape
//!
//! Detection is a procurement decision with a short lifetime; enforcement
//! is a kernel seam with a long one. So they are separated, but **not**
//! into two hooks — see [`hook`] for why one invocation does both.
//!
//! * [`EgressClassifier`] — the swappable detector. One in-tree
//!   implementation ([`DeterministicRules`]), and the same trait fits an
//!   external DLP or a local analyzer service.
//! * [`GatePolicy`] — what a verdict means for the write. Fail-closed by
//!   default.
//! * [`EgressContentHook`] — the registered hook.
//!
//! # Install
//!
//! ```ignore
//! // Default: in-tree rules, redact on a finding, deny if the detector fails.
//! kernel.bring_up_services(vec![egress_gate::service_decl_deterministic()])?;
//!
//! // Or with a different detector / posture / set of planes:
//! egress_gate::install_egress_content_gate(
//!     &kernel,
//!     Arc::new(my_classifier),
//!     GatePolicy::deny_on_finding(),
//!     EgressPlane::a2a_transcripts(),
//! )?;
//! ```
//!
//! Not armed by default. A gate that rewrites or refuses writes is a
//! deployment decision, and a daemon that has no egress promise to keep
//! should not be paying for one — the cluster profile puts it behind a
//! Cargo feature, and reads its deployment settings with
//! [`GateConfig::from_env`].

pub mod classifier;
pub mod combine;
pub mod credentials;
pub mod enforce;
pub mod hook;
mod json_layout;
#[cfg(feature = "presidio")]
pub mod presidio;
pub mod rules;

pub use classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};
pub use combine::AllOf;
pub use credentials::CredentialRules;
pub use enforce::{redact, Action, GatePolicy, Redacted};
pub use hook::{EgressContentHook, EgressPlane, DEFAULT_EGRESS_SUFFIXES};
pub use rules::DeterministicRules;

use std::sync::Arc;

use kernel::kernel::{Kernel, ServiceDecl};

/// Service name the hook is owned by.
const SERVICE_NAME: &str = "egress_gate";

/// Env var naming the gate's posture: `redact` (default), `deny`, or
/// `observe`.
pub const ENV_POLICY: &str = "NEXUS_EGRESS_GATE_POLICY";
/// Env var listing, comma-separated, the model mounts whose prompts leave
/// the node. Unset or empty = the model plane is not gated.
pub const ENV_MODEL_MOUNTS: &str = "NEXUS_EGRESS_GATE_MODEL_MOUNTS";
/// Env var listing, comma-separated, the mounts under which A2A
/// conversation transcripts leave the node. Unset or empty = no transcript
/// is gated.
///
/// Opt-in and scoped for the same reason the model plane is: a managed
/// session's turns are themselves an A2A conversation (`a2a::session`), so
/// gating every transcript would redact what a user tells the agent on
/// their own node — the private-data path the local runtime exists for.
/// Only conversations that cross to another domain are egress, and that is
/// a deployment fact the daemon cannot infer from a path.
pub const ENV_A2A_MOUNTS: &str = "NEXUS_EGRESS_GATE_A2A_MOUNTS";
/// Env var naming a local Presidio analyzer (`http://127.0.0.1:<port>`).
/// Set = contextual detection runs alongside the deterministic rules.
pub const ENV_PRESIDIO_URL: &str = "NEXUS_EGRESS_GATE_PRESIDIO_URL";
/// Presidio language code. Default `zh`.
pub const ENV_PRESIDIO_LANGUAGE: &str = "NEXUS_EGRESS_GATE_PRESIDIO_LANGUAGE";
/// Minimum Presidio score reported. Default `0.5`.
pub const ENV_PRESIDIO_THRESHOLD: &str = "NEXUS_EGRESS_GATE_PRESIDIO_THRESHOLD";
/// Comma-separated Presidio entity types to ask for. Default: all.
pub const ENV_PRESIDIO_ENTITIES: &str = "NEXUS_EGRESS_GATE_PRESIDIO_ENTITIES";
/// Per-write deadline for the analyzer, in milliseconds. Default `2000`.
pub const ENV_PRESIDIO_TIMEOUT_MS: &str = "NEXUS_EGRESS_GATE_PRESIDIO_TIMEOUT_MS";

/// A deployment's gate settings.
///
/// Read from the environment because they are per-deployment facts the
/// composition cannot know: which mounts lead off the box, which detector
/// runs, and whether the gate is live yet or still being brought up
/// against real traffic.
#[derive(Debug, Clone)]
pub struct GateConfig {
    pub policy: GatePolicy,
    /// Mount points whose `.prompt` writes reach a model outside the node.
    pub model_mounts: Vec<String>,
    /// Mount points under which conversation transcripts are shared with
    /// another domain.
    pub a2a_mounts: Vec<String>,
    /// A local Presidio analyzer to run alongside the deterministic rules.
    pub presidio: Option<PresidioSettings>,
}

/// Where and how to ask a Presidio analyzer. Parsed whether or not this
/// build can use it, so a build without the provider can refuse a
/// deployment that asked for one.
#[derive(Debug, Clone)]
pub struct PresidioSettings {
    pub url: String,
    pub language: String,
    pub score_threshold: f64,
    pub entities: Vec<String>,
    pub timeout: std::time::Duration,
}

impl GateConfig {
    /// Read the `NEXUS_EGRESS_GATE_*` variables.
    ///
    /// # Errors
    ///
    /// Any value that does not parse. Not defaulted: a typo in a setting
    /// whose job is to decide what may leave the node has to stop the
    /// daemon, not quietly fall back to some posture the operator did not
    /// write down. The install surfaces it, and a failed install aborts
    /// boot.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(|k| std::env::var(k).ok())
    }

    fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let set = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let list = |k: &str| -> Vec<String> {
            set(k)
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };
        let policy = match set(ENV_POLICY).as_deref() {
            None | Some("redact") => GatePolicy::default(),
            Some("deny") => GatePolicy::deny_on_finding(),
            Some("observe") => GatePolicy::observe_only(),
            Some(other) => {
                return Err(format!(
                    "{ENV_POLICY}={other:?}: expected one of redact, deny, observe"
                ))
            }
        };
        let presidio = match set(ENV_PRESIDIO_URL) {
            None => None,
            Some(url) => {
                let score_threshold = match set(ENV_PRESIDIO_THRESHOLD) {
                    None => 0.5,
                    Some(v) => v
                        .parse::<f64>()
                        .ok()
                        .filter(|t| (0.0..=1.0).contains(t))
                        .ok_or_else(|| {
                            format!("{ENV_PRESIDIO_THRESHOLD}={v:?}: expected a number in 0..=1")
                        })?,
                };
                let timeout_ms = match set(ENV_PRESIDIO_TIMEOUT_MS) {
                    None => 2000,
                    Some(v) => v.parse::<u64>().ok().filter(|ms| *ms > 0).ok_or_else(|| {
                        format!("{ENV_PRESIDIO_TIMEOUT_MS}={v:?}: expected milliseconds > 0")
                    })?,
                };
                Some(PresidioSettings {
                    url,
                    language: set(ENV_PRESIDIO_LANGUAGE).unwrap_or_else(|| "zh".to_string()),
                    score_threshold,
                    entities: list(ENV_PRESIDIO_ENTITIES),
                    timeout: std::time::Duration::from_millis(timeout_ms),
                })
            }
        };
        Ok(Self {
            policy,
            model_mounts: list(ENV_MODEL_MOUNTS),
            a2a_mounts: list(ENV_A2A_MOUNTS),
            presidio,
        })
    }

    /// The planes these settings name: transcripts under the A2A mounts,
    /// and `prompt_suffix` (the LLM mount request leaf, `None` in a build
    /// without the model driver) under the model mounts.
    ///
    /// # Errors
    ///
    /// A mount that is not an absolute path below the root, or model mounts
    /// named on a build without the model driver — that deployment believes
    /// its prompts are gated, and no prompt can reach the gate.
    pub fn planes(&self, prompt_suffix: Option<&'static str>) -> Result<Vec<EgressPlane>, String> {
        let mut planes = Vec::new();
        if !self.a2a_mounts.is_empty() {
            for leaf in DEFAULT_EGRESS_SUFFIXES {
                planes.push(EgressPlane::under(leaf, &self.a2a_mounts)?);
            }
        }
        if !self.model_mounts.is_empty() {
            let Some(suffix) = prompt_suffix else {
                return Err(format!(
                    "{ENV_MODEL_MOUNTS} names {:?}, but this build has no LLM mount \
                     driver, so no prompt can reach a model through it",
                    self.model_mounts
                ));
            };
            planes.push(EgressPlane::under(suffix, &self.model_mounts)?);
        }
        Ok(planes)
    }

    /// The classifier these settings call for: the deterministic rules,
    /// joined by a Presidio analyzer when one is configured.
    ///
    /// # Errors
    ///
    /// An analyzer configured on a build without the `presidio` feature —
    /// that deployment believes contextual detection is running, and it is
    /// not — or an analyzer URL the provider refuses (not loopback).
    pub fn classifier(&self) -> Result<Arc<dyn EgressClassifier>, String> {
        let rules: Arc<dyn EgressClassifier> = deterministic();
        let Some(p) = &self.presidio else {
            return Ok(rules);
        };
        #[cfg(feature = "presidio")]
        {
            let analyzer = presidio::PresidioAnalyzer::new(presidio::PresidioConfig {
                url: p.url.clone(),
                language: p.language.clone(),
                score_threshold: p.score_threshold,
                entities: p.entities.clone(),
                timeout: p.timeout,
            })?;
            // Rules first: they are microseconds, the analyzer is a round trip.
            Ok(Arc::new(AllOf::new(vec![rules, Arc::new(analyzer)])))
        }
        #[cfg(not(feature = "presidio"))]
        {
            Err(format!(
                "{ENV_PRESIDIO_URL}={:?} is set, but this build has no Presidio provider \
                 (feature `presidio`), so no contextual detection would run",
                p.url
            ))
        }
    }
}

/// The in-tree detectors together: provable PRC identifiers and
/// credentials. Both are deterministic and need no network, so every
/// configuration runs them.
fn deterministic() -> Arc<dyn EgressClassifier> {
    Arc::new(AllOf::new(vec![
        Arc::new(DeterministicRules::new()),
        Arc::new(CredentialRules::new()),
    ]))
}

/// Arm the gate. Call once at daemon boot.
///
/// Enlists a hook-only service and registers [`EgressContentHook`] on it,
/// so the hook load/unloads with the service rather than being pinned
/// globally — which is what makes the classifier swappable at runtime
/// instead of only at boot.
///
/// Takes `&Kernel` rather than `Arc` because the hook captures no kernel
/// reference; it works purely on the `HookContext` it is handed.
pub fn install_egress_content_gate(
    kernel: &Kernel,
    classifier: Arc<dyn EgressClassifier>,
    policy: GatePolicy,
    planes: Vec<EgressPlane>,
) -> Result<(), String> {
    let handle = kernel.enlist_hook_only_service(SERVICE_NAME)?;
    tracing::info!(
        classifier = %classifier.name(),
        policy = ?policy,
        planes = ?planes,
        "egress gate armed"
    );
    kernel.register_service_hook(
        &handle,
        Box::new(EgressContentHook::with_policy(classifier, policy, planes)),
    );
    Ok(())
}

/// The gate as a boot declaration, with a caller-chosen classifier,
/// policy and planes.
pub fn service_decl(
    classifier: Arc<dyn EgressClassifier>,
    policy: GatePolicy,
    planes: Vec<EgressPlane>,
) -> ServiceDecl {
    ServiceDecl {
        name: SERVICE_NAME.to_string(),
        install: Box::new(move |kernel| {
            install_egress_content_gate(kernel, classifier, policy, planes)
        }),
    }
}

/// The gate with the in-tree deterministic rules and the default policy on
/// **every** A2A transcript — redact what is provable, refuse what cannot
/// be sanitised, refuse if the detector fails.
///
/// Only for a daemon whose every conversation crosses a domain boundary.
/// A daemon that hosts managed sessions must not use it: session turns are
/// conversations too, and this would redact a user's own messages to their
/// local agent. Such a daemon uses [`service_decl_from_env`] and names the
/// cross-domain mounts.
pub fn service_decl_deterministic() -> ServiceDecl {
    service_decl(
        deterministic(),
        GatePolicy::default(),
        EgressPlane::a2a_transcripts(),
    )
}

/// The gate configured from the environment: the deterministic rules (plus
/// a Presidio analyzer if one is named), the transcript plane under
/// [`GateConfig::a2a_mounts`], and the model plane on `prompt_suffix` under
/// [`GateConfig::model_mounts`]. With neither configured the gate is armed
/// and claims nothing, which the boot log says.
///
/// `prompt_suffix` is `None` in a build with no LLM mount driver. A
/// deployment that names model mounts on such a build is refused at
/// install: it believes its prompts are gated, and no prompt is ever
/// sent from that build for the gate to see — the configuration is wrong,
/// and saying so is better than arming a plane that cannot fire.
///
/// Every error here is reported by the install, so a misconfigured gate
/// stops the daemon rather than leaving it running ungated.
pub fn service_decl_from_env(prompt_suffix: Option<&'static str>) -> ServiceDecl {
    let config = GateConfig::from_env();
    ServiceDecl {
        name: SERVICE_NAME.to_string(),
        install: Box::new(move |kernel| {
            let config = config?;
            let planes = config.planes(prompt_suffix)?;
            if planes.is_empty() {
                tracing::warn!(
                    "egress gate built but no plane configured; nothing is gated (set {} and/or {})",
                    ENV_MODEL_MOUNTS, ENV_A2A_MOUNTS
                );
            }
            install_egress_content_gate(kernel, config.classifier()?, config.policy, planes)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(vars: &[(&str, &str)]) -> Result<GateConfig, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        GateConfig::parse(|k| map.get(k).cloned())
    }

    #[test]
    fn config_defaults_to_redact_rules_only_and_no_model_plane() {
        let c = parse(&[]).unwrap();
        assert_eq!(c.policy.on_finding, Action::Redact);
        assert!(c.model_mounts.is_empty());
        assert!(
            c.a2a_mounts.is_empty(),
            "no transcript is gated unless named"
        );
        assert!(c.presidio.is_none());
        assert_eq!(
            c.classifier().unwrap().name(),
            "deterministic-prc+credentials"
        );
    }

    #[test]
    fn config_reads_each_policy_word() {
        let on_finding = |w| parse(&[(ENV_POLICY, w)]).unwrap().policy.on_finding;
        assert_eq!(on_finding("redact"), Action::Redact);
        assert_eq!(on_finding("deny"), Action::Deny);
        assert_eq!(on_finding("observe"), Action::Allow);
        assert_eq!(on_finding("  "), Action::Redact, "blank is unset");
    }

    #[test]
    fn config_refuses_an_unknown_policy_word() {
        // A typo must not fall back to some posture nobody wrote down.
        let err = parse(&[(ENV_POLICY, "redcat")]).unwrap_err();
        assert!(err.contains("redcat"), "{err}");
    }

    #[test]
    fn config_splits_and_trims_model_mounts() {
        let c = parse(&[(ENV_MODEL_MOUNTS, " /cloud-model , ,/other/ ")]).unwrap();
        assert_eq!(c.model_mounts, vec!["/cloud-model", "/other/"]);
    }

    #[test]
    fn config_reads_presidio_settings_with_defaults() {
        let c = parse(&[(ENV_PRESIDIO_URL, "http://127.0.0.1:5002")]).unwrap();
        let p = c.presidio.expect("analyzer configured");
        assert_eq!(p.language, "zh");
        assert!((p.score_threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(p.timeout, std::time::Duration::from_millis(2000));
        assert!(p.entities.is_empty());
    }

    #[test]
    fn config_refuses_unparseable_presidio_numbers() {
        for (k, v) in [
            (ENV_PRESIDIO_THRESHOLD, "high"),
            (ENV_PRESIDIO_THRESHOLD, "1.5"),
            (ENV_PRESIDIO_TIMEOUT_MS, "0"),
            (ENV_PRESIDIO_TIMEOUT_MS, "2s"),
        ] {
            let err = parse(&[(ENV_PRESIDIO_URL, "http://127.0.0.1:5002"), (k, v)]).unwrap_err();
            assert!(err.contains(k), "{k}={v}: {err}");
        }
    }

    #[cfg(not(feature = "presidio"))]
    #[test]
    fn an_analyzer_on_a_build_without_the_provider_is_refused() {
        // The deployment believes contextual detection runs; it would not.
        let c = parse(&[(ENV_PRESIDIO_URL, "http://127.0.0.1:5002")]).unwrap();
        let err = c.classifier().err().expect("must refuse");
        assert!(err.contains("feature `presidio`"), "{err}");
    }

    #[cfg(feature = "presidio")]
    #[test]
    fn an_analyzer_joins_the_rules() {
        let c = parse(&[(ENV_PRESIDIO_URL, "http://127.0.0.1:5002")]).unwrap();
        assert_eq!(
            c.classifier().unwrap().name(),
            "deterministic-prc+credentials+presidio"
        );
    }

    #[cfg(feature = "presidio")]
    #[test]
    fn an_analyzer_off_loopback_is_refused_at_install() {
        let c = parse(&[(ENV_PRESIDIO_URL, "http://10.0.0.5:5002")]).unwrap();
        assert!(c.classifier().is_err());
    }
}
