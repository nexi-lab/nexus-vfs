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

/// What a redaction did.
#[derive(Debug)]
pub struct Redacted {
    /// The content to write.
    pub content: Vec<u8>,
    /// Kinds replaced, one per edit, in content order.
    pub applied: Vec<String>,
    /// [`Confidence::Probable`] findings dropped because they fell on JSON
    /// keys or syntax — a detector reading the schema, not the content.
    pub discarded: usize,
}

/// One byte range to replace, and whether the marker needs its own quotes
/// (it does when it replaces a whole JSON number).
struct Edit {
    range: std::ops::Range<usize>,
    quoted: bool,
    tag: String,
}

/// Replace every finding with a marker, without ever changing JSON
/// structure.
///
/// For content that is not JSON, each span is replaced as given. For JSON
/// — the usual case on these planes — a redaction may rewrite only:
///
/// * **the inside of a string value**: a span is clipped to the quotes and
///   widened so it never cuts an escape sequence; a span across several
///   values is redacted value by value;
/// * **a whole number**, replaced by a *quoted* marker, so a card number
///   sent as a JSON number becomes a string rather than a syntax error.
///
/// Keys are the protocol's vocabulary. A [`Confidence::Probable`] finding
/// on a key or on bare syntax is a detector reading the schema — NER has
/// been seen tagging the key `"to"` as a LOCATION — and is discarded. A
/// [`Confidence::Certain`] one is a provable identifier sitting where it
/// cannot be redacted without breaking the message, and is refused.
///
/// Overlapping edits collapse into one marker tagged with the first kind,
/// because two markers for one run of bytes would imply the content had
/// two separate items in it.
///
/// # Errors
///
/// Fail-closed rather than best-effort wherever the findings cannot be
/// applied faithfully: a span outside the content (the provider is
/// describing bytes that are not there), a span that would cut a UTF-8
/// character, or a provable identifier on JSON structure. `Err` sends the
/// write to [`Action::Deny`] — content known to hold something sensitive
/// and impossible to sanitise must not be written.
pub fn redact(content: &[u8], findings: &[&Finding]) -> Result<Redacted, String> {
    let text = std::str::from_utf8(content).ok();
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
    }

    let mut discarded = 0;
    let mut edits: Vec<Edit> = Vec::new();
    match crate::json_layout::layout(content) {
        None => edits.extend(findings.iter().map(|f| Edit {
            range: f.span.clone(),
            quoted: false,
            tag: f.kind.tag().to_string(),
        })),
        Some(layout) => {
            for f in findings {
                let before = edits.len();
                let on_structure = json_edits(&layout, f, &mut edits);
                if on_structure && f.confidence == Confidence::Certain {
                    return Err(format!(
                        "a provable {} at {}..{} sits on JSON structure; it cannot be \
                         redacted without breaking the message",
                        f.kind.tag(),
                        f.span.start,
                        f.span.end
                    ));
                }
                if edits.len() == before {
                    discarded += 1;
                }
            }
        }
    }
    Ok(apply(content, edits, discarded))
}

/// The edits one finding calls for under a JSON layout. Returns whether
/// any part of the span fell on a key or on bare syntax.
fn json_edits(layout: &crate::json_layout::Layout, f: &Finding, edits: &mut Vec<Edit>) -> bool {
    let (s, e) = (f.span.start, f.span.end);
    let overlaps = |r: &std::ops::Range<usize>| r.start < e && s < r.end;
    let mut covered = 0usize;
    let mut on_key = false;
    for lit in layout.strings.iter().filter(|l| overlaps(&l.raw)) {
        let mut clip = s.max(lit.raw.start)..e.min(lit.raw.end);
        covered += clip.len();
        if lit.is_key {
            on_key = true;
            continue;
        }
        for esc in layout.escapes.iter().filter(|x| overlaps(x)) {
            if esc.start < clip.start && clip.start < esc.end {
                clip.start = esc.start;
            }
            if esc.start < clip.end && clip.end < esc.end {
                clip.end = esc.end;
            }
        }
        edits.push(Edit {
            range: clip,
            quoted: false,
            tag: f.kind.tag().to_string(),
        });
    }
    for num in layout.numbers.iter().filter(|n| overlaps(n)) {
        covered += e.min(num.end) - s.max(num.start);
        edits.push(Edit {
            range: num.clone(),
            quoted: true,
            tag: f.kind.tag().to_string(),
        });
    }
    // Anything in the span that is not inside a string or a number is
    // quotes, separators or a key: structure.
    on_key || covered < e - s
}

fn apply(content: &[u8], mut edits: Vec<Edit>, discarded: usize) -> Redacted {
    edits.sort_by_key(|x| (x.range.start, x.range.end));
    let mut out = Vec::with_capacity(content.len());
    let mut applied = Vec::new();
    let mut cursor = 0usize;
    let mut i = 0usize;
    while i < edits.len() {
        let start = edits[i].range.start;
        let mut end = edits[i].range.end;
        let quoted = edits[i].quoted;
        let tag = edits[i].tag.clone();
        // Merge everything that overlaps or abuts this edit.
        i += 1;
        while i < edits.len() && edits[i].range.start <= end {
            end = end.max(edits[i].range.end);
            i += 1;
        }
        if start >= cursor {
            out.extend_from_slice(&content[cursor..start]);
            if quoted {
                out.push(b'"');
            }
            out.extend_from_slice(&marker(&tag));
            if quoted {
                out.push(b'"');
            }
            applied.push(tag);
            cursor = end;
        }
    }
    out.extend_from_slice(&content[cursor..]);
    Redacted {
        content: out,
        applied,
        discarded,
    }
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
        redact(content.as_bytes(), &refs).map(|r| String::from_utf8(r.content).unwrap())
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

    // ── JSON structure is never changed ─────────────────────────────────

    fn probable(span: std::ops::Range<usize>, kind: &str) -> Finding {
        Finding {
            kind: FindingKind::Other(kind.into()),
            span,
            confidence: Confidence::Probable,
        }
    }

    fn at(doc: &str, needle: &str) -> std::ops::Range<usize> {
        let i = doc.find(needle).expect("needle in doc");
        i..i + needle.len()
    }

    fn parses(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("redaction broke the JSON ({e}): {s}"))
    }

    #[test]
    fn a_detector_reading_a_key_is_discarded_and_the_message_survives() {
        // The case a real analyzer produced: NER tagged the key "to",
        // quotes included, as a LOCATION.
        let doc = r#"{"from":"edge-agent","to":"cloud-agent","body":"客户张三你好"}"#;
        let refs = [
            &probable(at(doc, r#""to""#), "LOCATION"),
            &probable(at(doc, "张三"), "PERSON"),
        ];
        let r = redact(doc.as_bytes(), &refs).unwrap();
        let v = parses(std::str::from_utf8(&r.content).unwrap());
        assert_eq!(v["to"], "cloud-agent", "the key and its value are schema");
        assert_eq!(v["body"], "客户[REDACTED:PERSON]你好");
        assert_eq!(r.applied, vec!["PERSON"]);
        assert_eq!(r.discarded, 1);
    }

    #[test]
    fn a_provable_identifier_on_a_key_is_refused() {
        let doc = r#"{"4111111111111111":"x"}"#;
        let err = redact(
            doc.as_bytes(),
            &[&finding(at(doc, "4111111111111111"), FindingKind::BankCard)],
        )
        .unwrap_err();
        assert!(err.contains("JSON structure"), "{err}");
    }

    #[test]
    fn a_number_is_replaced_by_a_quoted_marker() {
        let doc = r#"{"card":4111111111111111,"n":1}"#;
        let got = redact_owned(
            doc,
            &[finding(at(doc, "4111111111111111"), FindingKind::BankCard)],
        )
        .unwrap();
        let v = parses(&got);
        assert_eq!(v["card"], "[REDACTED:BANK-CARD]");
        assert_eq!(v["n"], 1);
    }

    #[test]
    fn a_span_that_includes_the_quotes_is_clipped_to_the_value() {
        let doc = r#"{"b":"张三"}"#;
        let got = redact_owned(doc, &[probable(at(doc, r#""张三""#), "PERSON")]).unwrap();
        assert_eq!(got, r#"{"b":"[REDACTED:PERSON]"}"#);
    }

    #[test]
    fn a_span_across_two_values_is_redacted_value_by_value() {
        let doc = r#"{"a":"甲乙","b":"丙丁"}"#;
        let s = doc.find('乙').unwrap();
        let e = doc.find('丙').unwrap() + '丙'.len_utf8();
        let got = redact_owned(doc, &[probable(s..e, "PERSON")]).unwrap();
        let v = parses(&got);
        assert_eq!(v["a"], "甲[REDACTED:PERSON]");
        assert_eq!(v["b"], "[REDACTED:PERSON]丁");
    }

    #[test]
    fn an_escape_sequence_is_never_cut() {
        // A span that starts on the quote of `\"` would leave a dangling
        // backslash that escapes the marker's first byte.
        let doc = r#"{"b":"x\"y"}"#;
        let q = doc.find(r#"\""#).unwrap() + 1;
        let got = redact_owned(doc, &[probable(q..q + 2, "X")]).unwrap();
        let v = parses(&got);
        assert_eq!(v["b"], "x[REDACTED:X]");
    }

    #[test]
    fn non_json_content_is_redacted_as_given() {
        let got = redact_owned(
            "not json: 4111111111111111.",
            &[finding(10..26, FindingKind::BankCard)],
        );
        assert_eq!(got.unwrap(), "not json: [REDACTED:BANK-CARD].");
    }

    #[test]
    fn no_span_anywhere_can_break_the_json() {
        // Property: whatever span a detector reports, a redaction either
        // keeps the document parseable or refuses. Exercised over every
        // char-aligned span of a document with keys, escapes, numbers,
        // nesting and multi-byte text.
        let esc = format!("{}u5f20", '\\');
        let doc = format!(
            r#"{{"from":"a","to":"b","n":-12.5e2,"card":4111111111111111,"body":"q\"t\\ {esc}三 中文 x","list":[1,"张三",{{"k":"李四"}}],"t":true}}"#
        );
        assert!(serde_json::from_str::<serde_json::Value>(&doc).is_ok());
        let bounds: Vec<usize> = (0..=doc.len())
            .filter(|&i| doc.is_char_boundary(i))
            .collect();
        let mut checked = 0;
        for (i, &s) in bounds.iter().enumerate() {
            for &e in &bounds[i + 1..] {
                for conf in [Confidence::Probable, Confidence::Certain] {
                    let f = Finding {
                        kind: FindingKind::Other("X".into()),
                        span: s..e,
                        confidence: conf,
                    };
                    if let Ok(r) = redact(doc.as_bytes(), &[&f]) {
                        let out = String::from_utf8(r.content).expect("still UTF-8");
                        assert!(
                            serde_json::from_str::<serde_json::Value>(&out).is_ok(),
                            "span {s}..{e} ({conf:?}) broke the JSON: {out}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(
            checked > 1000,
            "the property must actually be exercised ({checked})"
        );
    }
}
