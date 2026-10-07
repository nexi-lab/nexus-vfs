//! Running several classifiers as one.
//!
//! The deterministic rules and a contextual detector answer different
//! questions — "is this a provable identifier" and "is this a person's
//! name" — and a deployment that wants both wants both on every write. The
//! hook takes one classifier, so they are combined here rather than
//! registered as two hooks: two hooks would traverse the write twice and
//! open the window between classifying and writing that the single-hook
//! design exists to close.

use std::sync::Arc;

use crate::classifier::{Classification, EgressClassifier, EgressRequest};

/// Every member classifies every write; their findings are unioned.
///
/// Any member's `Err` is the combination's `Err`. A partial answer is not
/// a clean one: if the contextual detector is down, the write must not be
/// waved through on the strength of the provable rules alone, because the
/// whole reason the contextual detector is installed is that the provable
/// rules miss things.
///
/// Overlapping findings from different members are left as they are;
/// [`crate::redact`] already merges overlapping spans into one marker.
pub struct AllOf {
    name: String,
    members: Vec<Arc<dyn EgressClassifier>>,
}

impl AllOf {
    /// Combine `members`, run in the given order — cheapest first, so a
    /// failure in an expensive one is not reached by a write that an
    /// earlier one already settled. (All members still run on a clean or
    /// redactable write: the verdict needs every member's findings.)
    #[must_use]
    pub fn new(members: Vec<Arc<dyn EgressClassifier>>) -> Self {
        let name = members
            .iter()
            .map(|m| m.name())
            .collect::<Vec<_>>()
            .join("+");
        Self { name, members }
    }
}

impl EgressClassifier for AllOf {
    fn name(&self) -> &str {
        &self.name
    }

    fn classify(&self, req: &EgressRequest<'_>) -> Result<Classification, String> {
        let mut out = Classification::clean();
        for member in &self.members {
            let c = member
                .classify(req)
                .map_err(|e| format!("{}: {e}", member.name()))?;
            out.findings.extend(c.findings);
            if out.label.is_none() {
                out.label = c.label;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{Confidence, Finding, FindingKind};

    struct Fixed(&'static str, Result<Vec<Finding>, String>);
    impl EgressClassifier for Fixed {
        fn name(&self) -> &str {
            self.0
        }
        fn classify(&self, _req: &EgressRequest<'_>) -> Result<Classification, String> {
            self.1.clone().map(|findings| Classification {
                findings,
                label: None,
            })
        }
    }

    fn finding(kind: &str, span: std::ops::Range<usize>) -> Finding {
        Finding {
            kind: FindingKind::Other(kind.into()),
            span,
            confidence: Confidence::Probable,
        }
    }

    fn req() -> EgressRequest<'static> {
        EgressRequest {
            path: "/conversations/x/transcript",
            agent_id: "a",
            zone_id: "root",
            content: b"0123456789",
        }
    }

    #[test]
    fn unions_every_members_findings() {
        let all = AllOf::new(vec![
            Arc::new(Fixed("a", Ok(vec![finding("A", 0..2)]))),
            Arc::new(Fixed("b", Ok(vec![finding("B", 4..6)]))),
        ]);
        let got = all.classify(&req()).unwrap();
        assert_eq!(got.findings.len(), 2);
        assert_eq!(all.name(), "a+b");
    }

    #[test]
    fn one_failing_member_fails_the_whole_verdict() {
        // The provable rules found nothing, but the contextual detector
        // could not answer: that is not a clean write.
        let all = AllOf::new(vec![
            Arc::new(Fixed("rules", Ok(vec![]))),
            Arc::new(Fixed("ner", Err("connection refused".into()))),
        ]);
        let err = all.classify(&req()).unwrap_err();
        assert!(err.starts_with("ner: "), "{err}");
    }
}
