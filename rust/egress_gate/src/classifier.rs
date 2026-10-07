//! The detection seam — what a classifier is asked, and what it reports.
//!
//! This module holds no detection logic. It exists so that **who decides
//! whether content is sensitive** is swappable without touching the hook
//! that enforces the decision. The two jobs have different lifetimes: the
//! enforcement point is a kernel write seam that must not change, while
//! the detector is a procurement decision (an in-tree rule set today, a
//! vendor DLP or a local Presidio-style service later).
//!
//! # One call, two provider shapes
//!
//! [`EgressClassifier::classify`] is deliberately a single method, and it
//! covers both shapes a detector comes in:
//!
//! * **inline classification** — the provider scans
//!   [`EgressRequest::content`] and reports spans.
//! * **label lookup** — the provider ignores the content, resolves a
//!   sensitivity label for [`EgressRequest::path`] (or for the calling
//!   agent), and reports it as [`Classification::label`].
//!
//! Both answer the same question at the same moment, so they get the same
//! signature. Splitting them into two trait methods — or worse, two hooks —
//! would mean traversing one write twice and handing state between the
//! passes, which opens a window where the content that was classified is
//! not the content that gets written.

use std::ops::Range;

/// How the classifier knows.
///
/// This records the *kind of evidence*, not a probability. A caller that
/// wants to act only on checksum-backed findings can filter on it; see
/// [`crate::GatePolicy::act_on_probable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// A checksum (or an equivalent structural proof) verified the
    /// candidate. The residual false-positive rate is whatever that
    /// checksum leaves — it is not zero, and the in-tree rules document
    /// theirs per kind.
    Certain,
    /// Shape only — the candidate looks right and there is nothing to
    /// verify it against.
    Probable,
}

/// What kind of sensitive item was found.
///
/// The named variants are the ones the in-tree rules can prove. `Other`
/// exists because an external provider reports its own taxonomy and the
/// gate must be able to carry a verdict it does not have a variant for —
/// an unrecognised kind has to be enforceable, not silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    /// PRC resident identity card (居民身份证), 18 characters.
    PrcIdCard,
    /// Payment card number (Luhn-valid, recognised issuer prefix).
    BankCard,
    /// PRC mainland mobile number, 11 digits.
    PrcMobile,
    /// PRC unified social credit identifier (统一社会信用代码), 18
    /// characters.
    UnifiedSocialCreditId,
    /// A kind reported by an external provider.
    Other(String),
}

impl FindingKind {
    /// Short tag used in the redaction marker and in audit log lines.
    ///
    /// Not sanitised here — the marker builder in [`crate::enforce`] is
    /// what splices this into content and is responsible for keeping the
    /// result safe, because only it knows the surrounding syntax.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::PrcIdCard => "PRC-ID",
            Self::BankCard => "BANK-CARD",
            Self::PrcMobile => "PRC-MOBILE",
            Self::UnifiedSocialCreditId => "PRC-USCI",
            Self::Other(s) => s,
        }
    }
}

/// One sensitive item, located in the bytes that were classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    /// Byte range into [`EgressRequest::content`].
    ///
    /// A provider that cannot locate what it found (a whole-document
    /// label, say) reports it through [`Classification::label`] instead —
    /// a span that does not correspond to the finding would redact the
    /// wrong bytes, so there is no "unknown span" encoding on purpose.
    pub span: Range<usize>,
    pub confidence: Confidence,
}

/// A classifier's answer about one write.
#[derive(Debug, Clone, Default)]
pub struct Classification {
    /// Located items. Spans may arrive in any order and may overlap;
    /// [`crate::enforce`] normalises them.
    pub findings: Vec<Finding>,
    /// Whole-content sensitivity label, for providers that answer by
    /// lookup rather than by scan. `None` = no label known.
    ///
    /// A label is not self-interpreting: the gate cannot know whether
    /// some vendor's `"L3"` is releasable. A provider that wants a label
    /// to block must say so by also reporting a finding, or the
    /// composition must install a policy that understands that
    /// provider's vocabulary.
    pub label: Option<String>,
}

impl Classification {
    /// Nothing sensitive — the common answer.
    #[must_use]
    pub fn clean() -> Self {
        Self::default()
    }
}

/// One candidate write, as the classifier sees it.
#[derive(Debug)]
pub struct EgressRequest<'a> {
    /// VFS path being written. For the A2A case this is the conversation
    /// transcript, so it identifies the conversation but not the peer.
    pub path: &'a str,
    /// Authenticated caller, empty under a NoAuth bring-up.
    pub agent_id: &'a str,
    /// Zone the write lands in.
    pub zone_id: &'a str,
    /// The bytes about to be written. Already the output of any earlier
    /// mutating hook in the chain, so what is classified is what would be
    /// written.
    pub content: &'a [u8],
}

/// Decides whether content may leave.
///
/// Implementors must be cheap and must not block: `classify` runs inside
/// `Kernel::apply_mutating_write_hooks`, synchronously, on the write path.
/// A provider that needs to call out to a service is responsible for its
/// own timeout, and should return `Err` when it expires rather than
/// stalling the write — `Err` lands on
/// [`GatePolicy::on_classifier_error`](crate::GatePolicy::on_classifier_error),
/// which is fail-closed by default.
pub trait EgressClassifier: Send + Sync {
    /// Stable name, for audit lines and for telling two installed
    /// providers apart.
    fn name(&self) -> &str;

    /// Classify one candidate write.
    ///
    /// `Err` means *the classifier could not answer* — not "clean". The
    /// distinction is the whole point of the return type: a gate that
    /// treated an unreachable detector as a clean verdict would fail open
    /// exactly when it is least safe to.
    fn classify(&self, req: &EgressRequest<'_>) -> Result<Classification, String>;
}
