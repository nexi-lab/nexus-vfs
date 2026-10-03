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
//! // Or with a different detector / posture:
//! egress_gate::install_egress_content_gate(
//!     &kernel,
//!     Arc::new(my_classifier),
//!     GatePolicy::deny_on_finding(),
//!     egress_gate::DEFAULT_EGRESS_SUFFIXES,
//! )?;
//! ```
//!
//! Not armed by default. A gate that rewrites or refuses writes is a
//! deployment decision, and a daemon that has no egress promise to keep
//! should not be paying for one — the cluster profile puts it behind a
//! Cargo feature.

pub mod classifier;
pub mod enforce;
pub mod hook;
pub mod rules;

pub use classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};
pub use enforce::{redact, Action, GatePolicy};
pub use hook::{EgressContentHook, DEFAULT_EGRESS_SUFFIXES};
pub use rules::DeterministicRules;

use std::sync::Arc;

use kernel::kernel::{Kernel, ServiceDecl};

/// Service name the hook is owned by.
const SERVICE_NAME: &str = "egress_gate";

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
    suffixes: &'static [&'static str],
) -> Result<(), String> {
    let handle = kernel.enlist_hook_only_service(SERVICE_NAME)?;
    kernel.register_service_hook(
        &handle,
        Box::new(EgressContentHook::with_policy(classifier, policy, suffixes)),
    );
    Ok(())
}

/// The gate as a boot declaration, with a caller-chosen classifier and
/// policy.
pub fn service_decl(
    classifier: Arc<dyn EgressClassifier>,
    policy: GatePolicy,
    suffixes: &'static [&'static str],
) -> ServiceDecl {
    ServiceDecl {
        name: SERVICE_NAME.to_string(),
        install: Box::new(move |kernel| {
            install_egress_content_gate(kernel, classifier, policy, suffixes)
        }),
    }
}

/// The gate with the in-tree deterministic rules and the default policy —
/// redact what is provable, refuse what cannot be sanitised, refuse if the
/// detector fails.
///
/// This is the configuration that needs no procurement and no network, so
/// it is the one a build can turn on unconditionally.
pub fn service_decl_deterministic() -> ServiceDecl {
    service_decl(
        Arc::new(DeterministicRules::new()),
        GatePolicy::default(),
        DEFAULT_EGRESS_SUFFIXES,
    )
}
