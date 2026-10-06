//! The in-tree deterministic classifier — the gate's first provider and
//! its regression baseline.
//!
//! Every kind here is **verifiable**: a PRC identity card, a payment card
//! and a unified social credit identifier all carry a check digit, so a
//! candidate can be proved rather than guessed. That is the whole
//! selection criterion. It buys three properties a model-based detector
//! cannot offer:
//!
//! * **no dependency and no network** — it ships inside the daemon, which
//!   matters for an appliance that may be deployed air-gapped;
//! * **latency that does not need measuring** — a few hundred
//!   multiply-adds per write, on a seam that is synchronous;
//! * **a stable expected output** — so it can be the baseline any richer
//!   provider is diffed against. A provider that misses what this one
//!   proves is a regression, with no judgement call involved.
//!
//! It is deliberately NOT a complete DLP. It knows four kinds, all PRC,
//! all structured. Names, addresses, account descriptions, contract terms
//! — anything whose sensitivity is contextual — are out of its reach by
//! construction, and are what a richer [`EgressClassifier`] is for.
//!
//! # Scanning model
//!
//! The content is split into maximal runs of ASCII alphanumerics, and
//! each run is scanned. Within a run:
//!
//! * **checksum-backed kinds slide a window** (widths 19 down to 13,
//!   longest first), so an identifier embedded in a longer token is still
//!   found. Sliding is safe here precisely because each window must pass
//!   a checksum to be reported.
//! * **shape-only kinds require the whole run** — a mobile number has
//!   nothing to verify it with, so sliding an 11-digit shape window
//!   across arbitrary digits would report mostly noise.
//!
//! The consequence, stated plainly: a mobile number glued to adjacent
//! alphanumerics (`tel13912345678end`) is missed. That is the honest cost
//! of refusing to guess, and it is the kind of gap the richer provider
//! closes.

use crate::classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};

/// Narrowest checksum-backed candidate considered (shortest payment card).
const MIN_WINDOW: usize = 13;
/// Widest checksum-backed candidate considered (longest payment card).
const MAX_WINDOW: usize = 19;
/// PRC identity cards and unified social credit identifiers are both this
/// wide.
const ID_WIDTH: usize = 18;
/// Mainland mobile numbers.
const MOBILE_WIDTH: usize = 11;

/// Deterministic, checksum-backed detection of structured PRC identifiers.
///
/// Stateless — one instance serves every write.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicRules;

impl DeterministicRules {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl EgressClassifier for DeterministicRules {
    fn name(&self) -> &str {
        "deterministic-prc"
    }

    fn classify(&self, req: &EgressRequest<'_>) -> Result<Classification, String> {
        // Infallible: there is no external dependency that could fail, so
        // this provider never exercises the `on_classifier_error` policy.
        Ok(Classification {
            findings: scan(req.content),
            label: None,
        })
    }
}

/// Locate every provable identifier in `content`.
#[must_use]
pub fn scan(content: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut i = 0;
    while i < content.len() {
        if !content[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < content.len() && content[i].is_ascii_alphanumeric() {
            i += 1;
        }
        scan_run(content, start, i, &mut findings);
    }
    findings
}

/// Scan one maximal alphanumeric run, `content[start..end]`.
fn scan_run(content: &[u8], start: usize, end: usize, out: &mut Vec<Finding>) {
    let run = &content[start..end];

    // Shape-only kind: the whole run must be the number. Checked before
    // the sliding loop and returning early, because nothing wider than 11
    // can fit in an 11-byte run anyway.
    if run.len() == MOBILE_WIDTH && is_prc_mobile(run) {
        out.push(Finding {
            kind: FindingKind::PrcMobile,
            span: start..end,
            confidence: Confidence::Probable,
        });
        return;
    }

    let mut w = 0;
    while w < run.len() {
        let mut matched = 0;
        // Longest first, so a 19-digit card is not reported as a shorter
        // Luhn-valid prefix of itself.
        for width in (MIN_WINDOW..=MAX_WINDOW).rev() {
            if w + width > run.len() {
                continue;
            }
            if let Some(kind) = classify_window(&run[w..w + width]) {
                out.push(Finding {
                    kind,
                    span: start + w..start + w + width,
                    confidence: Confidence::Certain,
                });
                matched = width;
                break;
            }
        }
        w += if matched > 0 { matched } else { 1 };
    }
}

/// Identify one fixed-width candidate, or `None`.
///
/// Order matters and is fixed: an 18-digit run can in principle satisfy
/// both the identity-card and the social-credit checksum, so the card is
/// tried first — its birth-date plausibility gate makes it the more
/// specific of the two.
fn classify_window(c: &[u8]) -> Option<FindingKind> {
    if c.len() == ID_WIDTH {
        if is_prc_id_card(c) {
            return Some(FindingKind::PrcIdCard);
        }
        if is_usci(c) {
            return Some(FindingKind::UnifiedSocialCreditId);
        }
    }
    if is_bank_card(c) {
        return Some(FindingKind::BankCard);
    }
    None
}

// ── PRC resident identity card (GB 11643-1999) ──────────────────────────

/// ISO 7064 MOD 11-2 weights over the first 17 digits.
const ID_WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
/// Check character for each residue of the weighted sum mod 11.
const ID_CHECK: &[u8; 11] = b"10X98765432";

/// 18-character PRC identity card: 17 digits plus a MOD 11-2 check
/// character (`X` for residue 2).
///
/// Three independent gates, which is what keeps this precise: the check
/// character (1 in 11 by chance), a plausible administrative division
/// code, and a plausible birth date. A random 18-digit run clears all
/// three about 1 time in 2000.
fn is_prc_id_card(c: &[u8]) -> bool {
    if c.len() != ID_WIDTH || !c[..17].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> u32 {
        c[r].iter().fold(0, |acc, b| acc * 10 + u32::from(b - b'0'))
    };
    // Administrative division: 11..=82 are the assigned province-level
    // codes, 91 is "abroad".
    let division = num(0..2);
    if !(11..=82).contains(&division) && division != 91 {
        return false;
    }
    let (year, month, day) = (num(6..10), num(10..12), num(12..14));
    // The year floor is loose on purpose. Almost all of the suppression
    // here comes from month and day (12/100 and 31/100 of random digit
    // pairs); the year contributes a couple of percent, so buying that
    // with a tight floor would trade real recall for almost nothing. 1880
    // is below the oldest plausible holder — the GB 11643 worked example
    // itself carries an 1880 birth date.
    if !(1880..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    let sum: u32 = c[..17]
        .iter()
        .zip(ID_WEIGHTS)
        .map(|(b, w)| u32::from(b - b'0') * w)
        .sum();
    let expected = ID_CHECK[(sum % 11) as usize];
    c[17] == expected || (expected == b'X' && c[17] == b'x')
}

// ── PRC unified social credit identifier (GB 32100-2015) ────────────────

/// The 31-character alphabet. `I`, `O`, `S`, `V` and `Z` are excluded by
/// the standard to avoid confusion with digits and with each other.
const USCI_ALPHABET: &[u8; 31] = b"0123456789ABCDEFGHJKLMNPQRTUWXY";
/// ISO 7064 MOD 31-3 weights over the first 17 characters.
const USCI_WEIGHTS: [u32; 17] = [
    1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
];

fn usci_value(b: u8) -> Option<u32> {
    USCI_ALPHABET.iter().position(|&c| c == b).map(|p| p as u32)
}

/// 18-character unified social credit identifier, MOD 31-3 checked.
///
/// Upper case only — the standard specifies upper case, and accepting
/// lower case would widen the alphabet for no real recall.
fn is_usci(c: &[u8]) -> bool {
    if c.len() != ID_WIDTH {
        return false;
    }
    let mut sum = 0u32;
    for (&b, w) in c[..17].iter().zip(USCI_WEIGHTS) {
        let Some(v) = usci_value(b) else {
            return false;
        };
        sum += v * w;
    }
    let Some(check) = usci_value(c[17]) else {
        return false;
    };
    (31 - (sum % 31)) % 31 == check
}

// ── Payment card ────────────────────────────────────────────────────────

/// 13–19 digits, a recognised issuer prefix, and Luhn-valid.
///
/// The issuer prefix is not decoration. Luhn alone passes 1 random run in
/// 10, which over the digit runs in ordinary machine output (ids,
/// concatenated timestamps) is far too loose; requiring a real IIN range
/// as well brings a random-run false positive to roughly 1 in 50. That is
/// still not zero, and a gate configured to redact will occasionally mask
/// a long number that was never a card — the deliberate trade, since the
/// opposite error leaks one.
fn is_bank_card(c: &[u8]) -> bool {
    if !(MIN_WINDOW..=MAX_WINDOW).contains(&c.len()) || !c.iter().all(u8::is_ascii_digit) {
        return false;
    }
    has_known_iin(c) && luhn_ok(c)
}

fn has_known_iin(c: &[u8]) -> bool {
    let d = |i: usize| u32::from(c[i] - b'0');
    let two = d(0) * 10 + d(1);
    let four = two * 100 + d(2) * 10 + d(3);
    d(0) == 4                                // Visa
        || (51..=55).contains(&two)          // Mastercard
        || (2221..=2720).contains(&four)     // Mastercard 2-series
        || two == 34
        || two == 37                         // Amex
        || two == 62
        || two == 81                         // UnionPay / 中国银联
        || two == 35                         // JCB
        || two == 36
        || two == 38 // Diners
}

fn luhn_ok(c: &[u8]) -> bool {
    let sum: u32 = c
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                if d > 4 {
                    d * 2 - 9
                } else {
                    d * 2
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

// ── Mainland mobile ─────────────────────────────────────────────────────

/// 11 digits, `1` then `3`–`9`. No checksum exists, hence
/// [`Confidence::Probable`] and the maximal-run requirement.
fn is_prc_mobile(c: &[u8]) -> bool {
    c.len() == MOBILE_WIDTH
        && c[0] == b'1'
        && (b'3'..=b'9').contains(&c[1])
        && c.iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Published specimen identity numbers — valid by checksum, not
    /// issued to anyone. Taken from the GB 11643 worked examples.
    const ID_OK: &str = "11010519491231002X";
    const ID_OK_2: &str = "440524188001010014";
    /// Same digits, check character bumped off `X`.
    const ID_BAD_CHECK: &str = "110105194912310021";
    /// Checksum-VALID (verified) but month 19 — so this fixture isolates
    /// the date gate. A fixture that failed the checksum too would make
    /// the assertion below vacuous.
    const ID_BAD_DATE: &str = "110105194919310022";

    /// Test card numbers published by the networks for exactly this use.
    const VISA_OK: &str = "4111111111111111";
    const MC_OK: &str = "5500005555555559";
    const UNIONPAY_OK: &str = "6212345678901232";
    /// Luhn-valid (verified) but no issuer owns a `9` prefix.
    const UNKNOWN_IIN: &str = "9111111111111110";

    /// Synthetic: Beijing enterprise prefix plus a filler body, check
    /// character computed to satisfy MOD 31-3. Not a real registration.
    const USCI_OK: &str = "91110000MA0ABCDEFX";

    fn kinds(s: &str) -> Vec<FindingKind> {
        scan(s.as_bytes()).into_iter().map(|f| f.kind).collect()
    }

    #[test]
    fn luhn_accepts_published_test_cards() {
        for n in [VISA_OK, MC_OK, UNIONPAY_OK] {
            assert!(luhn_ok(n.as_bytes()), "{n} must be Luhn-valid");
            assert!(is_bank_card(n.as_bytes()), "{n} must classify as a card");
        }
    }

    #[test]
    fn card_requires_a_real_issuer_prefix() {
        assert!(
            luhn_ok(UNKNOWN_IIN.as_bytes()),
            "fixture must be Luhn-valid, else it tests nothing"
        );
        assert!(
            !is_bank_card(UNKNOWN_IIN.as_bytes()),
            "Luhn alone must not be enough — the IIN gate is what holds the \
             false-positive rate down"
        );
    }

    #[test]
    fn id_card_checksum_and_date_both_gate() {
        assert!(is_prc_id_card(ID_OK.as_bytes()));
        assert!(is_prc_id_card(ID_OK_2.as_bytes()));
        assert!(!is_prc_id_card(ID_BAD_CHECK.as_bytes()), "check char");

        // Self-check before the real assertion: the bad-date fixture must
        // itself be checksum-valid, otherwise the rejection below would
        // prove nothing about the date gate.
        let b = ID_BAD_DATE.as_bytes();
        let sum: u32 = b[..17]
            .iter()
            .zip(ID_WEIGHTS)
            .map(|(d, w)| u32::from(d - b'0') * w)
            .sum();
        assert_eq!(
            ID_CHECK[(sum % 11) as usize],
            b[17],
            "bad-date fixture must pass the checksum, else this test is vacuous"
        );
        assert!(!is_prc_id_card(b), "month 19 must be rejected");
    }

    #[test]
    fn usci_checksum_gates() {
        assert!(is_usci(USCI_OK.as_bytes()));
        let mut bad = USCI_OK.as_bytes().to_vec();
        bad[17] = b'Y';
        assert!(!is_usci(&bad));
        // `I` is not in the alphabet, so a lookalike must be refused.
        let mut illegal = USCI_OK.as_bytes().to_vec();
        illegal[8] = b'I';
        assert!(!is_usci(&illegal));
    }

    #[test]
    fn finds_identifiers_inside_a_json_envelope() {
        let body =
            format!(r#"{{"from":"a","body":"身份证 {ID_OK}，卡号 {VISA_OK}，电话 13912345678"}}"#);
        let got = kinds(&body);
        assert!(got.contains(&FindingKind::PrcIdCard), "{got:?}");
        assert!(got.contains(&FindingKind::BankCard), "{got:?}");
        assert!(got.contains(&FindingKind::PrcMobile), "{got:?}");
    }

    #[test]
    fn spans_point_at_the_identifier() {
        let body = format!("id={ID_OK} end");
        let f = scan(body.as_bytes());
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(&body[f[0].span.clone()], ID_OK);
    }

    #[test]
    fn checksum_kinds_are_found_inside_a_longer_token() {
        // The sliding window is what makes this work; it is safe because
        // every reported window had to pass a checksum.
        let body = format!("userid{ID_OK}suffix");
        assert_eq!(kinds(&body), vec![FindingKind::PrcIdCard]);
    }

    #[test]
    fn mobile_requires_a_maximal_run() {
        assert_eq!(kinds("13912345678"), vec![FindingKind::PrcMobile]);
        assert_eq!(kinds("tel: 13912345678."), vec![FindingKind::PrcMobile]);
        // Documented gap, pinned so a future change to it is a decision
        // rather than an accident: glued to other alphanumerics there is
        // no checksum to justify a sliding window, so it is missed.
        assert!(kinds("tel13912345678end").is_empty());
    }

    #[test]
    fn ordinary_text_and_machine_output_stay_clean() {
        for s in [
            "deploy finished in 1234 ms",
            "blake3:9f2c4a1b8e7d6c5f4a3b2c1d0e9f8a7b",
            "2026-10-02T11:22:33.123456Z",
            "请把上季度的汇总发我",
            "",
        ] {
            assert!(scan(s.as_bytes()).is_empty(), "false positive on {s:?}");
        }
    }

    #[test]
    fn overlapping_candidates_do_not_double_report() {
        let body = format!("{ID_OK}{VISA_OK}");
        let f = scan(body.as_bytes());
        for pair in f.windows(2) {
            assert!(
                pair[0].span.end <= pair[1].span.start,
                "spans must not overlap: {f:?}"
            );
        }
    }

    #[test]
    fn classifier_trait_surface_reports_findings() {
        let rules = DeterministicRules::new();
        let body = format!("id {ID_OK}");
        let out = rules
            .classify(&EgressRequest {
                path: "/conversations/x/transcript",
                agent_id: "a",
                zone_id: "root",
                content: body.as_bytes(),
            })
            .expect("in-tree rules are infallible");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].confidence, Confidence::Certain);
        assert!(out.label.is_none());
    }
}
