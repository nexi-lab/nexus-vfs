//! The hook — one `NativeInterceptHook` that classifies and enforces in
//! the same invocation.
//!
//! # Why one hook and not two
//!
//! Splitting "decide" from "enforce" into two registered hooks looks
//! tidier and is wrong on this seam. Each registered hook is another pass
//! over the same write, so the content is traversed twice; the verdict has
//! to be carried between the passes as state keyed by something; and
//! between the two passes there is a window in which what was classified
//! is no longer what will be written. Deciding and acting in one
//! invocation has none of those properties, and costs one hook entry
//! instead of two.
//!
//! The `mutating_path_suffixes` declaration is what keeps that cheap: the
//! dispatcher clones write content into the hook context only for paths a
//! mutating hook claims, so every other write on the node pays a suffix
//! comparison and nothing else.
//!
//! # Where it sits relative to the A2A stamp
//!
//! Both hooks claim `*/transcript`, and both can rewrite. They compose —
//! each sees the previous one's output — so the gate classifies the
//! envelope as it will actually be written, stamp included, and its
//! redaction does not discard the stamp.

use std::sync::Arc;

use contracts::is_system_path;
use kernel::core::dispatch::{HookContext, HookOutcome, NativeInterceptHook};

use crate::classifier::{EgressClassifier, EgressRequest};
use crate::enforce::{redact, Action, GatePolicy};

/// Paths the gate claims by default: the A2A conversation transcript.
///
/// This is the plane the collaboration discipline is written against — a
/// message leaving the node is the one crossing that it is supposed to be
/// possible to assert about. Taken from `a2a` rather than spelled here so
/// a rename of the leaf reaches the gate.
pub const DEFAULT_EGRESS_SUFFIXES: &[&str] = a2a::MAILBOX_WRITE_SUFFIXES;

/// Classify-and-enforce on the kernel write seam.
pub struct EgressContentHook {
    classifier: Arc<dyn EgressClassifier>,
    policy: GatePolicy,
    suffixes: &'static [&'static str],
}

impl EgressContentHook {
    /// Gate [`DEFAULT_EGRESS_SUFFIXES`] with the default policy (redact
    /// on a finding, deny when the classifier fails).
    #[must_use]
    pub fn new(classifier: Arc<dyn EgressClassifier>) -> Self {
        Self::with_policy(classifier, GatePolicy::default(), DEFAULT_EGRESS_SUFFIXES)
    }

    /// Full control over policy and claimed paths.
    ///
    /// `suffixes` is `&'static` because the kernel's clone gate reads it
    /// from the registered hook. Widening it is how the gate grows to
    /// cover another egress plane — the model-call leaf of an LLM mount,
    /// say — without the hook itself changing: a composition decision, not
    /// a code change here.
    #[must_use]
    pub fn with_policy(
        classifier: Arc<dyn EgressClassifier>,
        policy: GatePolicy,
        suffixes: &'static [&'static str],
    ) -> Self {
        Self {
            classifier,
            policy,
            suffixes,
        }
    }

    /// Whether this hook claims `path`.
    ///
    /// Required, not defensive: the clone gate is global, so content is
    /// cloned into the context whenever *any* registered mutating hook's
    /// suffix matches. Without this check the gate would classify writes
    /// on paths it was never installed for.
    fn claims(&self, path: &str) -> bool {
        self.suffixes.iter().any(|s| path.ends_with(s))
    }
}

impl NativeInterceptHook for EgressContentHook {
    fn name(&self) -> &str {
        "egress_content_gate"
    }

    fn mutating_path_suffixes(&self) -> &'static [&'static str] {
        self.suffixes
    }

    fn on_pre(&self, ctx: &HookContext) -> Result<HookOutcome, String> {
        // Native-hook contract: never classify kernel-internal paths. The
        // gate reads nothing under `/__sys__/` today, but a classifier
        // installed into it might, and that would recurse through this
        // same hook.
        if is_system_path(ctx.path()) {
            return Ok(HookOutcome::Pass);
        }
        let HookContext::Write(c) = ctx else {
            return Ok(HookOutcome::Pass);
        };
        if !self.claims(&c.path) || c.content.is_empty() {
            return Ok(HookOutcome::Pass);
        }

        let req = EgressRequest {
            path: &c.path,
            agent_id: &c.identity.agent_id,
            zone_id: &c.identity.zone_id,
            content: &c.content,
        };
        let classification = match self.classifier.classify(&req) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(
                    path = %c.path,
                    agent_id = %c.identity.agent_id,
                    classifier = %self.classifier.name(),
                    action = ?self.policy.on_classifier_error,
                    error = %e,
                    "egress gate: classifier failed"
                );
                return match self.policy.on_classifier_error {
                    Action::Allow => Ok(HookOutcome::Pass),
                    // Nothing was classified, so there is nothing to
                    // redact — the only enforcement left is refusal.
                    Action::Redact | Action::Deny => Err(format!(
                        "egress gate: classifier {} could not answer for {}: {e}",
                        self.classifier.name(),
                        c.path
                    )),
                };
            }
        };

        let actionable = self.policy.actionable(&classification);
        if actionable.is_empty() {
            return Ok(HookOutcome::Pass);
        }

        // Audit lines carry the path, the caller and the KINDS found —
        // never the matched bytes. Logging the match would copy the
        // identifier out of the gated channel and into a log sink that has
        // none of its controls, which is the leak this hook exists to
        // prevent.
        let kinds: Vec<&str> = actionable.iter().map(|f| f.kind.tag()).collect();

        match self.policy.on_finding {
            Action::Allow => {
                tracing::info!(
                    path = %c.path, agent_id = %c.identity.agent_id,
                    classifier = %self.classifier.name(),
                    kinds = ?kinds, count = actionable.len(),
                    "egress gate: observed (policy allows)"
                );
                Ok(HookOutcome::Pass)
            }
            Action::Deny => {
                tracing::warn!(
                    path = %c.path, agent_id = %c.identity.agent_id,
                    classifier = %self.classifier.name(),
                    kinds = ?kinds, count = actionable.len(),
                    "egress gate: write denied"
                );
                Err(format!(
                    "egress gate: {} sensitive item(s) {kinds:?} may not leave this node \
                     (path {}, classifier {})",
                    actionable.len(),
                    c.path,
                    self.classifier.name()
                ))
            }
            Action::Redact => match redact(&c.content, &actionable) {
                Ok(bytes) => {
                    tracing::warn!(
                        path = %c.path, agent_id = %c.identity.agent_id,
                        classifier = %self.classifier.name(),
                        kinds = ?kinds, count = actionable.len(),
                        "egress gate: content redacted"
                    );
                    Ok(HookOutcome::Replace(bytes))
                }
                // Known-sensitive content that cannot be sanitised
                // faithfully must not be written. See `enforce::redact`.
                Err(e) => {
                    tracing::error!(
                        path = %c.path, agent_id = %c.identity.agent_id,
                        kinds = ?kinds, error = %e,
                        "egress gate: redaction failed, denying write"
                    );
                    Err(format!(
                        "egress gate: cannot redact {} sensitive item(s) {kinds:?} \
                         in {}: {e}",
                        actionable.len(),
                        c.path
                    ))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{Classification, Confidence, Finding, FindingKind};
    use crate::rules::DeterministicRules;
    use kernel::core::dispatch::{HookIdentity, ReadHookCtx, WriteHookCtx};

    const ID_OK: &str = "11010519491231002X";
    const TRANSCRIPT: &str = "/conversations/abc123/transcript";

    fn write_ctx(path: &str, content: &str) -> HookContext {
        HookContext::Write(WriteHookCtx {
            path: path.to_string(),
            identity: HookIdentity {
                user_id: "u".into(),
                zone_id: "root".into(),
                agent_id: "sudoedge-dgx-dev/agent/worker".into(),
                is_admin: false,
            },
            content: content.as_bytes().to_vec(),
            is_new_file: false,
            content_id: None,
            new_version: 0,
            size_bytes: None,
        })
    }

    fn gate(policy: GatePolicy) -> EgressContentHook {
        EgressContentHook::with_policy(
            Arc::new(DeterministicRules::new()),
            policy,
            DEFAULT_EGRESS_SUFFIXES,
        )
    }

    fn replaced(outcome: HookOutcome) -> String {
        match outcome {
            HookOutcome::Replace(b) => String::from_utf8(b).unwrap(),
            HookOutcome::Pass => panic!("expected Replace, got Pass"),
        }
    }

    /// A classifier that always fails, to exercise the fail-closed path.
    struct BrokenClassifier;
    impl EgressClassifier for BrokenClassifier {
        fn name(&self) -> &str {
            "broken"
        }
        fn classify(&self, _req: &EgressRequest<'_>) -> Result<Classification, String> {
            Err("upstream unreachable".into())
        }
    }

    /// A classifier that reports a finding it cannot locate correctly.
    struct BadSpanClassifier;
    impl EgressClassifier for BadSpanClassifier {
        fn name(&self) -> &str {
            "bad-span"
        }
        fn classify(&self, _req: &EgressRequest<'_>) -> Result<Classification, String> {
            Ok(Classification {
                findings: vec![Finding {
                    kind: FindingKind::Other("vendor-pii".into()),
                    span: 0..9999,
                    confidence: Confidence::Certain,
                }],
                label: None,
            })
        }
    }

    #[test]
    fn claims_the_transcript_leaf() {
        assert_eq!(
            gate(GatePolicy::default()).mutating_path_suffixes(),
            a2a::MAILBOX_WRITE_SUFFIXES,
            "the gate must claim the same leaf the A2A writers use, or it is \
             never handed content"
        );
    }

    #[test]
    fn redacts_an_identifier_on_a_transcript_write() {
        let body = format!(r#"{{"from":"a","to":"b","body":"身份证 {ID_OK}"}}"#);
        let out = gate(GatePolicy::default())
            .on_pre(&write_ctx(TRANSCRIPT, &body))
            .expect("redaction is not a rejection");
        let got = replaced(out);
        assert!(!got.contains(ID_OK), "identifier must be gone: {got}");
        assert!(got.contains("[REDACTED:PRC-ID]"), "{got}");
        assert!(
            got.contains(r#""from":"a""#),
            "envelope must survive: {got}"
        );
    }

    #[test]
    fn passes_clean_content_untouched() {
        let body = r#"{"from":"a","to":"b","body":"请把上季度的汇总发我"}"#;
        let out = gate(GatePolicy::default())
            .on_pre(&write_ctx(TRANSCRIPT, body))
            .unwrap();
        assert!(matches!(out, HookOutcome::Pass));
    }

    #[test]
    fn deny_policy_rejects_instead_of_rewriting() {
        let body = format!(r#"{{"body":"{ID_OK}"}}"#);
        let err = gate(GatePolicy::deny_on_finding())
            .on_pre(&write_ctx(TRANSCRIPT, &body))
            .expect_err("deny policy must reject");
        assert!(err.contains("PRC-ID"), "{err}");
        assert!(
            !err.contains(ID_OK),
            "the rejection message must not quote the identifier it found: {err}"
        );
    }

    #[test]
    fn observe_only_policy_changes_nothing() {
        let body = format!(r#"{{"body":"{ID_OK}"}}"#);
        let out = gate(GatePolicy::observe_only())
            .on_pre(&write_ctx(TRANSCRIPT, &body))
            .unwrap();
        assert!(matches!(out, HookOutcome::Pass));
    }

    #[test]
    fn ignores_paths_it_does_not_claim() {
        // The clone gate is global: another mutating hook's suffix can
        // cause content to be cloned for a path this gate never claimed.
        let body = format!(r#"{{"body":"{ID_OK}"}}"#);
        let out = gate(GatePolicy::default())
            .on_pre(&write_ctx("/workspace/notes.md", &body))
            .unwrap();
        assert!(matches!(out, HookOutcome::Pass));
    }

    #[test]
    fn ignores_system_paths() {
        let body = format!(r#"{{"body":"{ID_OK}"}}"#);
        let out = gate(GatePolicy::default())
            .on_pre(&write_ctx("/__sys__/zones/root/transcript", &body))
            .unwrap();
        assert!(matches!(out, HookOutcome::Pass));
    }

    #[test]
    fn passes_when_content_was_not_cloned() {
        let out = gate(GatePolicy::default())
            .on_pre(&write_ctx(TRANSCRIPT, ""))
            .unwrap();
        assert!(matches!(out, HookOutcome::Pass));
    }

    #[test]
    fn passes_for_non_write_contexts() {
        let ctx = HookContext::Read(ReadHookCtx {
            path: TRANSCRIPT.to_string(),
            identity: HookIdentity::default(),
            content: None,
            content_id: None,
        });
        assert!(matches!(
            gate(GatePolicy::default()).on_pre(&ctx).unwrap(),
            HookOutcome::Pass
        ));
    }

    #[test]
    fn classifier_failure_is_fail_closed_by_default() {
        let hook = EgressContentHook::new(Arc::new(BrokenClassifier));
        let err = hook
            .on_pre(&write_ctx(TRANSCRIPT, r#"{"body":"anything"}"#))
            .expect_err("an unanswerable verdict must not pass");
        assert!(err.contains("could not answer"), "{err}");
    }

    #[test]
    fn classifier_failure_can_be_configured_open() {
        let hook = EgressContentHook::with_policy(
            Arc::new(BrokenClassifier),
            GatePolicy {
                on_classifier_error: Action::Allow,
                ..GatePolicy::default()
            },
            DEFAULT_EGRESS_SUFFIXES,
        );
        let out = hook
            .on_pre(&write_ctx(TRANSCRIPT, r#"{"body":"anything"}"#))
            .unwrap();
        assert!(matches!(out, HookOutcome::Pass));
    }

    #[test]
    fn unapplicable_redaction_denies_rather_than_passing() {
        let hook = EgressContentHook::new(Arc::new(BadSpanClassifier));
        let err = hook
            .on_pre(&write_ctx(TRANSCRIPT, r#"{"body":"short"}"#))
            .expect_err("a redaction that cannot be applied must deny");
        assert!(err.contains("cannot redact"), "{err}");
    }
}
