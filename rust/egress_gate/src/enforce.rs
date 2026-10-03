//! Enforcement — turning a [`Classification`] into a write outcome, and
//! splicing redactions into content.
//!
//! Detection is swappable; this is not. Whatever the provider is, the
//! answers it can produce are "let it through", "let a rewritten version
//! through", and "refuse" — and which one a verdict maps to is a
//! deployment's decision, not the detector's.

use crate::classifier::{Classification, Confidence, Finding};

/// What the gate does about a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Write the content as-is. Findings, if any, are logged only.
    Allow,
    /// Replace each located finding with a marker and write the result.
    /// Falls back to [`Action::Deny`] when the findings cannot be applied
    /// — see [`redact`].
    Redact,
    /// Refuse the write. Surfaces to the caller as a permission error.
    Deny,
}

/// How the gate reacts to what the classifier says.
#[derive(Debug, Clone, Copy)]
pub struct GatePolicy {
    /// Applied when the classifier reports at least one actionable
    /// finding.
    pub on_finding: Action,
    /// Applied when the classifier itself fails — unreachable service,
    /// timeout, malformed response.
    ///
    /// Defaults to [`Action::Deny`]. A gate that let writes through while
    /// its detector was down would be open exactly when it is least
    /// observable, and the failure would look like a clean verdict in
    /// every log.
    pub on_classifier_error: Action,
    /// Whether [`Confidence::Probable`] findings count as actionable.
    ///
    /// Defaults to `true`. A shape-only match on something that looks
    /// exactly like a phone number is still the thing this gate exists to
    /// stop; a deployment that would rather accept the leak than the
    /// occasional mangled message turns this off.
    pub act_on_probable: bool,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            on_finding: Action::Redact,
            on_classifier_error: Action::Deny,
            act_on_probable: true,
        }
    }
}

impl GatePolicy {
    /// Refuse the whole write rather than rewriting it.
    ///
    /// The right posture where the content is a protocol message whose
    /// shape matters more than its delivery, since a redaction marker
    /// spliced into a field can be worse than no message at all.
    #[must_use]
    pub fn deny_on_finding() -> Self {
        Self {
            on_finding: Action::Deny,
            ..Self::default()
        }
    }

    /// Report only — classify every write, change none of them.
    ///
    /// For bringing the gate up against real traffic: the audit lines show
    /// what a live policy would have done before it does it.
    #[must_use]
    pub fn observe_only() -> Self {
        Self {
            on_finding: Action::Allow,
            on_classifier_error: Action::Allow,
            act_on_probable: true,
        }
    }

    /// Findings this policy will act on.
    pub(crate) fn actionable<'a>(&self, c: &'a Classification) -> Vec<&'a Finding> {
        c.findings
            .iter()
            .filter(|f| self.act_on_probable || f.confidence == Confidence::Certain)
            .collect()
    }
}

/// Marker spliced in place of a redacted span.
///
/// The tag is restricted to `[A-Za-z0-9_-]` on the way in. Content on this
/// seam is usually a JSON envelope, and a provider-supplied kind name
/// carrying a quote or a backslash would turn a redaction into a parse
/// error at the reader — the gate would then have corrupted the message it
/// was asked to sanitise.
fn marker(tag: &str) -> Vec<u8> {
    let safe: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("[REDACTED:{safe}]").into_bytes()
}

/// Replace every finding's span with a marker.
///
/// Spans may arrive unsorted and overlapping; they are sorted and merged
/// first. Overlapping findings collapse into one marker tagged with the
/// first kind, because two markers for one run of bytes would imply the
/// content had two separate items in it.
///
/// # Errors
///
/// Fail-closed rather than best-effort, in both cases where the findings
/// cannot be applied faithfully:
///
/// * a span outside the content — the provider is describing bytes that
///   are not there, so no part of its verdict can be trusted to point at
///   the right place;
/// * a span that would cut a multi-byte character in valid UTF-8 — the
///   result would be invalid UTF-8 the reader cannot decode, and a
///   partially-redacted identifier is still a leak.
///
/// Returning `Err` sends the write to [`Action::Deny`], which is the
/// correct answer: content known to contain something sensitive and
/// impossible to sanitise must not be written.
pub fn redact(content: &[u8], findings: &[&Finding]) -> Result<Vec<u8>, String> {
    if findings.is_empty() {
        return Ok(content.to_vec());
    }
    let text = std::str::from_utf8(content).ok();

    let mut spans: Vec<(usize, usize, &str)> = Vec::with_capacity(findings.len());
    for f in findings {
        let (s, e) = (f.span.start, f.span.end);
        if s > e || e > content.len() {
            return Err(format!(
                "classifier reported span {s}..{e} outside {}-byte content",
                content.len()
            ));
        }
        if let Some(t) = text {
            if !t.is_char_boundary(s) || !t.is_char_boundary(e) {
                return Err(format!(
                    "classifier reported span {s}..{e} that splits a character"
                ));
            }
        }
        spans.push((s, e, f.kind.tag()));
    }
    spans.sort_by_key(|&(s, e, _)| (s, e));

    let mut out = Vec::with_capacity(content.len());
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < spans.len() {
        let (start, mut end, tag) = spans[i];
        // Merge everything that overlaps or abuts this span.
        i += 1;
        while i < spans.len() && spans[i].0 <= end {
            end = end.max(spans[i].1);
            i += 1;
        }
        if start >= cursor {
            out.extend_from_slice(&content[cursor..start]);
            out.extend_from_slice(&marker(tag));
            cursor = end;
        }
    }
    out.extend_from_slice(&content[cursor..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::FindingKind;

    fn finding(span: std::ops::Range<usize>, kind: FindingKind) -> Finding {
        Finding {
            kind,
            span,
            confidence: Confidence::Certain,
        }
    }

    fn redact_owned(content: &str, findings: &[Finding]) -> Result<String, String> {
        let refs: Vec<&Finding> = findings.iter().collect();
        redact(content.as_bytes(), &refs).map(|b| String::from_utf8(b).unwrap())
    }

    #[test]
    fn replaces_a_single_span() {
        let got = redact_owned("id=12345678 end", &[finding(3..11, FindingKind::PrcIdCard)]);
        assert_eq!(got.unwrap(), "id=[REDACTED:PRC-ID] end");
    }

    #[test]
    fn replaces_multiple_spans_given_out_of_order() {
        // "a=1111 b=2222" — `1111` is 2..6, `2222` is 9..13.
        let got = redact_owned(
            "a=1111 b=2222",
            &[
                finding(9..13, FindingKind::BankCard),
                finding(2..6, FindingKind::PrcMobile),
            ],
        );
        assert_eq!(
            got.unwrap(),
            "a=[REDACTED:PRC-MOBILE] b=[REDACTED:BANK-CARD]"
        );
    }

    #[test]
    fn merges_overlapping_spans_into_one_marker() {
        let got = redact_owned(
            "xx12345678xx",
            &[
                finding(2..8, FindingKind::PrcIdCard),
                finding(5..10, FindingKind::BankCard),
            ],
        );
        assert_eq!(got.unwrap(), "xx[REDACTED:PRC-ID]xx");
    }

    #[test]
    fn preserves_json_validity() {
        let body = r#"{"from":"a","body":"card 4111111111111111 ok"}"#;
        let out = redact_owned(body, &[finding(25..41, FindingKind::BankCard)]).unwrap();
        assert!(
            out.contains(r#""body":"card [REDACTED:BANK-CARD] ok""#),
            "{out}"
        );
        assert!(!out.contains("4111111111111111"));
    }

    #[test]
    fn sanitises_a_provider_supplied_tag() {
        // A vendor kind carrying a quote would otherwise break the
        // envelope it is spliced into.
        let got = redact_owned(
            r#"{"v":"xxxx"}"#,
            &[finding(6..10, FindingKind::Other(r#"ev"il\x"#.into()))],
        )
        .unwrap();
        assert_eq!(got, r#"{"v":"[REDACTED:ev-il-x]"}"#);
        assert!(!got.contains('\\'));
    }

    #[test]
    fn rejects_a_span_past_the_end() {
        let err = redact_owned("short", &[finding(2..99, FindingKind::BankCard)]).unwrap_err();
        assert!(err.contains("outside"), "{err}");
    }

    #[test]
    fn rejects_a_span_that_splits_a_character() {
        // 身 is three bytes; cutting at 1 would emit invalid UTF-8.
        let err = redact_owned("身份证", &[finding(1..4, FindingKind::PrcIdCard)]).unwrap_err();
        assert!(err.contains("splits a character"), "{err}");
    }

    #[test]
    fn redacts_around_multibyte_text() {
        let body = "身份证 12345678 完";
        let start = body.find("12345678").unwrap();
        let got = redact_owned(body, &[finding(start..start + 8, FindingKind::PrcIdCard)]).unwrap();
        assert_eq!(got, "身份证 [REDACTED:PRC-ID] 完");
    }

    #[test]
    fn no_findings_is_a_copy() {
        assert_eq!(redact_owned("untouched", &[]).unwrap(), "untouched");
    }

    #[test]
    fn probable_findings_filtered_when_policy_says_so() {
        let c = Classification {
            findings: vec![
                finding(0..4, FindingKind::PrcIdCard),
                Finding {
                    kind: FindingKind::PrcMobile,
                    span: 5..16,
                    confidence: Confidence::Probable,
                },
            ],
            label: None,
        };
        let strict = GatePolicy {
            act_on_probable: false,
            ..GatePolicy::default()
        };
        assert_eq!(strict.actionable(&c).len(), 1);
        assert_eq!(GatePolicy::default().actionable(&c).len(), 2);
    }

    #[test]
    fn default_policy_is_fail_closed_on_classifier_error() {
        assert_eq!(
            GatePolicy::default().on_classifier_error,
            Action::Deny,
            "a gate whose detector is down must not pass writes through"
        );
    }
}
