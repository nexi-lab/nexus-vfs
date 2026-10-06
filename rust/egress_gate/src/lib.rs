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
pub mod enforce;
pub mod hook;
pub mod rules;

pub use classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};
pub use enforce::{redact, Action, GatePolicy};
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

/// A deployment's gate settings.
///
/// Read from the environment because they are per-deployment facts the
/// composition cannot know: which mounts lead off the box, and whether
/// the gate is live yet or still being brought up against real traffic.
#[derive(Debug, Clone)]
pub struct GateConfig {
    pub policy: GatePolicy,
    /// Mount points whose `.prompt` writes reach a model outside the node.
    pub model_mounts: Vec<String>,
}

impl GateConfig {
    /// Read [`ENV_POLICY`] and [`ENV_MODEL_MOUNTS`].
    ///
    /// # Errors
    ///
    /// An unrecognised policy word. Not defaulted: a typo in a setting
    /// whose job is to decide what may leave the node has to stop the
    /// daemon, not quietly fall back to some posture the operator did not
    /// write down. The install surfaces it, and a failed install aborts
    /// boot.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var(ENV_POLICY).ok().as_deref(),
            std::env::var(ENV_MODEL_MOUNTS).ok().as_deref(),
        )
    }

    fn parse(policy: Option<&str>, model_mounts: Option<&str>) -> Result<Self, String> {
        let policy = match policy.map(str::trim).filter(|s| !s.is_empty()) {
            None | Some("redact") => GatePolicy::default(),
            Some("deny") => GatePolicy::deny_on_finding(),
            Some("observe") => GatePolicy::observe_only(),
            Some(other) => {
                return Err(format!(
                    "{ENV_POLICY}={other:?}: expected one of redact, deny, observe"
                ))
            }
        };
        let model_mounts = model_mounts
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        Ok(Self {
            policy,
            model_mounts,
        })
    }
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

/// The gate with the in-tree deterministic rules and the default policy,
/// on the A2A transcript — redact what is provable, refuse what cannot be
/// sanitised, refuse if the detector fails.
///
/// This is the configuration that needs no procurement and no network, so
/// it is the one a build can turn on unconditionally.
pub fn service_decl_deterministic() -> ServiceDecl {
    service_decl(
        Arc::new(DeterministicRules::new()),
        GatePolicy::default(),
        EgressPlane::a2a_transcripts(),
    )
}

/// The deterministic gate configured from the environment, with the
/// model plane on `prompt_suffix` under [`GateConfig::model_mounts`].
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
            let mut planes = EgressPlane::a2a_transcripts();
            if !config.model_mounts.is_empty() {
                let Some(suffix) = prompt_suffix else {
                    return Err(format!(
                        "{ENV_MODEL_MOUNTS} names {:?}, but this build has no LLM mount \
                         driver, so no prompt can reach a model through it",
                        config.model_mounts
                    ));
                };
                planes.push(EgressPlane::under(suffix, &config.model_mounts)?);
            }
            install_egress_content_gate(
                kernel,
                Arc::new(DeterministicRules::new()),
                config.policy,
                planes,
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_redact_and_no_model_plane() {
        let c = GateConfig::parse(None, None).unwrap();
        assert_eq!(c.policy.on_finding, Action::Redact);
        assert!(c.model_mounts.is_empty());
    }

    #[test]
    fn config_reads_each_policy_word() {
        let on_finding = |w| GateConfig::parse(Some(w), None).unwrap().policy.on_finding;
        assert_eq!(on_finding("redact"), Action::Redact);
        assert_eq!(on_finding("deny"), Action::Deny);
        assert_eq!(on_finding("observe"), Action::Allow);
        assert_eq!(on_finding("  "), Action::Redact, "blank is unset");
    }

    #[test]
    fn config_refuses_an_unknown_policy_word() {
        // A typo must not fall back to some posture nobody wrote down.
        let err = GateConfig::parse(Some("redcat"), None).unwrap_err();
        assert!(err.contains("redcat"), "{err}");
    }

    #[test]
    fn config_splits_and_trims_model_mounts() {
        let c = GateConfig::parse(None, Some(" /cloud-model , ,/other/ ")).unwrap();
        assert_eq!(c.model_mounts, vec!["/cloud-model", "/other/"]);
    }
}
