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
//! Every numeric identifier is anchored on a **digit boundary**: the whole
//! maximal run of digits must be the identifier, never a window inside a
//! longer one.
//!
//! That rule is load-bearing, and it is measured rather than assumed. An
//! earlier version slid a 13–19 wide window across each run so an
//! identifier embedded in a longer token would still be found. Sliding
//! multiplies the candidates a long number offers — a 19-digit snowflake
//! id holds 28 card-width windows — and over 20,000 random samples it
//! reported **49.4% of snowflake ids and 33% of nanosecond timestamps** as
//! bank cards. Anchored, with per-brand card lengths, those fall to 0.14%
//! and 0%. A gate on a channel that carries machine output cannot afford
//! the first number.
//!
//! The anchor is a digit boundary, not a word boundary, so letters do not
//! break it: `userid11010519491231002Xsuffix` and `tel13912345678end` are
//! both found.
//!
//! * PRC identity card — an 18-digit run, or 17 digits then `X`/`x`.
//! * Payment card — a 13–19 digit run, or the same digits in display
//!   grouping (`6222 0212 3456 7890`, `4111-1111-1111-1111`).
//! * Mainland mobile — an 11-digit run in a real carrier segment.
//! * Unified social credit identifier — a maximal upper-case alphanumeric
//!   run of 18.
//!
//! The anchoring rule, the per-brand card lengths, the carrier-segment
//! table and the grouped display format are borrowed from shellward
//! (`jnMetaCode/shellward`, Apache-2.0, `src/rules/sensitive-patterns.ts`).
//! The rules, not the code.

use crate::classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};

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

/// Locate every provable identifier in `content`, in content order.
#[must_use]
pub fn scan(content: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    scan_digit_runs(content, &mut findings);
    scan_usci_runs(content, &mut findings);
    findings.sort_by_key(|f| f.span.start);
    findings
}

fn digit_run_end(c: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < c.len() && c[end].is_ascii_digit() {
        end += 1;
    }
    end
}

fn scan_digit_runs(c: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < c.len() {
        if !c[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let end = digit_run_end(c, start);
        if let Some(group_end) = grouped_card(c, start, end) {
            out.push(Finding {
                kind: FindingKind::BankCard,
                span: start..group_end,
                confidence: Confidence::Certain,
            });
            i = group_end;
            continue;
        }
        if let Some((kind, span_end, confidence)) = classify_digit_run(c, start, end) {
            out.push(Finding {
                kind,
                span: start..span_end,
                confidence,
            });
            i = span_end;
            continue;
        }
        i = end;
    }
}

/// Identify the maximal digit run `c[start..end]`, returning the kind and
/// where its span ends (one past `end` when an identity card's `X` check
/// character is included).
///
/// Order matters: an identity card is tried before a card number because
/// its date and division gates make it the more specific of the two.
fn classify_digit_run(
    c: &[u8],
    start: usize,
    end: usize,
) -> Option<(FindingKind, usize, Confidence)> {
    let run = &c[start..end];
    // The `X` check character ends the identifier; the 17-digit run before
    // it is already maximal, so whatever follows the `X` cannot make this a
    // window inside a longer number.
    if run.len() == ID_WIDTH - 1
        && matches!(c.get(end), Some(b'X' | b'x'))
        && is_prc_id_card(&c[start..=end])
    {
        return Some((FindingKind::PrcIdCard, end + 1, Confidence::Certain));
    }
    if run.len() == ID_WIDTH && is_prc_id_card(run) {
        return Some((FindingKind::PrcIdCard, end, Confidence::Certain));
    }
    if is_bank_card(run) {
        return Some((FindingKind::BankCard, end, Confidence::Certain));
    }
    if is_prc_mobile(run) {
        return Some((FindingKind::PrcMobile, end, Confidence::Probable));
    }
    None
}

/// A card number in display grouping, starting at the digit run
/// `c[start..end]`: three or more groups of 3–6 digits joined by one
/// consistent single separator (space or hyphen). Returns the end of the
/// last group when the joined digits are a card.
///
/// Three groups minimum, so a date (`2026-10-02`) or a spaced phone number
/// (`139 1234 5678`, 11 digits) can never qualify — the joined digits must
/// still pass the same brand, length and Luhn gates as an ungrouped card.
fn grouped_card(c: &[u8], start: usize, end: usize) -> Option<usize> {
    const GROUP: std::ops::RangeInclusive<usize> = 3..=6;
    if !GROUP.contains(&(end - start)) {
        return None;
    }
    let sep = *c.get(end)?;
    if sep != b' ' && sep != b'-' {
        return None;
    }
    let mut digits = c[start..end].to_vec();
    let mut groups = 1;
    let mut cursor = end;
    while c.get(cursor) == Some(&sep) {
        let g_start = cursor + 1;
        let g_end = digit_run_end(c, g_start);
        if !GROUP.contains(&(g_end - g_start)) {
            break;
        }
        digits.extend_from_slice(&c[g_start..g_end]);
        groups += 1;
        cursor = g_end;
        if digits.len() > 19 {
            return None;
        }
    }
    (groups >= 3 && is_bank_card(&digits)).then_some(cursor)
}

/// Unified social credit identifiers are alphanumeric, so they are found
/// on their own boundary: a maximal run of `[0-9A-Z]` exactly 18 long.
/// A span the digit pass already claimed (an 18-digit identity card) is
/// not reported twice.
fn scan_usci_runs(c: &[u8], out: &mut Vec<Finding>) {
    let upper_alnum = |b: u8| b.is_ascii_digit() || b.is_ascii_uppercase();
    let mut i = 0;
    while i < c.len() {
        if !upper_alnum(c[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < c.len() && upper_alnum(c[i]) {
            i += 1;
        }
        if i - start == ID_WIDTH
            && is_usci(&c[start..i])
            && !out.iter().any(|f| f.span.start < i && start < f.span.end)
        {
            out.push(Finding {
                kind: FindingKind::UnifiedSocialCreditId,
                span: start..i,
                confidence: Confidence::Certain,
            });
        }
    }
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

/// 18-character unified social credit identifier: MOD 31-3 over the whole,
/// and GB 11714 over the organization code it embeds.
///
/// Two checks, because one is not enough at 18 characters. MOD 31-3 alone
/// passes a random 18-digit run 1 time in 31 (3.24% measured), which is
/// the same "machine ids get flagged" failure the digit anchor exists to
/// prevent. GB 32100 places the organization code (组织机构代码, GB 11714)
/// at positions 9–17, and that code carries its own check character;
/// requiring both brings a random run to 0.314%. Verified against real
/// identifiers before relying on it — both checks hold on registered
/// codes, so the second gate costs no recall on real data.
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
    (31 - (sum % 31)) % 31 == check && is_org_code(&c[8..17])
}

/// GB 11714 weights over the organization code's 8 body characters.
const ORG_WEIGHTS: [u32; 8] = [3, 7, 9, 10, 5, 8, 4, 2];

/// 9-character organization code: 8 body characters (digits, or letters
/// valued `A`=10 … `Z`=35) and a MOD 11 check character, `X` for 10 and
/// `0` for 11.
fn is_org_code(c: &[u8]) -> bool {
    let value = |b: u8| -> Option<u32> {
        match b {
            b'0'..=b'9' => Some(u32::from(b - b'0')),
            b'A'..=b'Z' => Some(u32::from(b - b'A') + 10),
            _ => None,
        }
    };
    let mut sum = 0u32;
    for (&b, w) in c[..8].iter().zip(ORG_WEIGHTS) {
        let Some(v) = value(b) else {
            return false;
        };
        sum += v * w;
    }
    let expected = match 11 - sum % 11 {
        10 => b'X',
        11 => b'0',
        r => b'0' + r as u8,
    };
    c[8] == expected
}

// ── Payment card ────────────────────────────────────────────────────────

/// A recognised brand at that brand's length, and Luhn-valid.
///
/// Neither gate is decoration. Luhn alone passes 1 random run in 10. An
/// issuer prefix without its length still flags 3.19% of 19-digit ids —
/// a Visa prefix is one digit, and nothing stopped a 19-digit run starting
/// with `4`. Pinning each brand to the lengths it actually issues brings
/// that to 0.14% while every published test card still passes. What
/// remains (2.41% of random 16-digit numbers) is not reducible: a 16-digit
/// Luhn-valid number with a Visa prefix *is* a card as far as any detector
/// can tell.
fn is_bank_card(c: &[u8]) -> bool {
    if !(13..=19).contains(&c.len()) || !c.iter().all(u8::is_ascii_digit) {
        return false;
    }
    brand_length_ok(c) && luhn_ok(c)
}

fn brand_length_ok(c: &[u8]) -> bool {
    let d = |i: usize| u32::from(c[i] - b'0');
    let two = d(0) * 10 + d(1);
    let four = two * 100 + d(2) * 10 + d(3);
    let n = c.len();
    if d(0) == 4 {
        return n == 13 || n == 16; // Visa
    }
    if (51..=55).contains(&two) || (2221..=2720).contains(&four) {
        return n == 16; // Mastercard
    }
    match two {
        34 | 37 => n == 15,                             // Amex
        62 => (16..=19).contains(&n),                   // UnionPay / 中国银联
        81 => n == 16,                                  // UnionPay 81 range
        35 => (3528..=3589).contains(&four) && n == 16, // JCB
        36 | 38 | 30 => n == 14,                        // Diners
        _ => false,
    }
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

/// 11 digits in an allocated carrier segment. No checksum exists, hence
/// [`Confidence::Probable`] and the digit-boundary requirement.
///
/// The segment table (second and third digit) is what keeps arbitrary
/// 11-digit numbers — order numbers, truncated timestamps — out: `1[3-9]`
/// alone admits segments no carrier issues (`142`, `154`, `160`, `179`, `194`, …).
fn is_prc_mobile(c: &[u8]) -> bool {
    if c.len() != MOBILE_WIDTH || c[0] != b'1' || !c.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let third = c[2] - b'0';
    match c[1] {
        b'3' | b'8' => true,
        b'4' => matches!(third, 0 | 1 | 4..=9),
        b'5' => third != 4,
        b'6' => matches!(third, 2 | 5 | 6 | 7),
        b'7' => third <= 8,
        b'9' => third != 4,
        _ => false,
    }
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
    /// Luhn-valid (verified) with a Visa prefix, but 19 digits — a length
    /// Visa does not issue at, so only the length gate can reject it.
    const VISA_PREFIX_19: &str = "4111111111111111110";

    /// Synthetic: Beijing enterprise prefix and an organization code, both
    /// check characters computed (MOD 31-3 and GB 11714) and verified. Not
    /// a real registration.
    const USCI_OK: &str = "91110000MA0ABCDE62";
    /// Passes MOD 31-3 (verified) but its embedded organization code fails
    /// GB 11714 — isolates the second gate.
    const USCI_BAD_ORG: &str = "91110000MA0ABCD001";

    /// Machine ids the earlier sliding-window scanner reported as bank
    /// cards. Found by sampling, not constructed, so they are what real
    /// traffic looks like: 19-digit snowflake ids and nanosecond
    /// timestamps.
    const SNOWFLAKE_FLAGGED_BEFORE: [&str; 3] = [
        "8903166252872187431",
        "8205464747235938445",
        "5167417605511239617",
    ];
    const NS_TS_FLAGGED_BEFORE: [&str; 3] = [
        "1754735533894457906",
        "1753660912485173331",
        "1855267831258558245",
    ];

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
    fn usci_requires_a_valid_embedded_organization_code() {
        // Self-check: the fixture must pass MOD 31-3 on its own, or the
        // rejection below would prove nothing about the second gate.
        let b = USCI_BAD_ORG.as_bytes();
        let sum: u32 = b[..17]
            .iter()
            .zip(USCI_WEIGHTS)
            .map(|(&c, w)| usci_value(c).unwrap() * w)
            .sum();
        assert_eq!(
            (31 - (sum % 31)) % 31,
            usci_value(b[17]).unwrap(),
            "fixture must pass MOD 31-3, else this test is vacuous"
        );
        assert!(!is_org_code(&b[8..17]));
        assert!(
            !is_usci(b),
            "MOD 31-3 alone passes 1 random run in 31; the organization code \
             check is what holds machine ids out"
        );
    }

    #[test]
    fn finds_a_usci_on_its_own_boundary() {
        assert_eq!(
            kinds(&format!("统一社会信用代码：{USCI_OK}。")),
            vec![FindingKind::UnifiedSocialCreditId]
        );
        // Lower-case letters are not in the USCI alphabet, so they bound it.
        assert_eq!(
            kinds(&format!("code{USCI_OK}")),
            vec![FindingKind::UnifiedSocialCreditId]
        );
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
    fn identifiers_glued_to_letters_are_found() {
        // The anchor is a digit boundary, not a word boundary.
        assert_eq!(
            kinds(&format!("userid{ID_OK}suffix")),
            vec![FindingKind::PrcIdCard]
        );
        assert_eq!(kinds("tel13912345678end"), vec![FindingKind::PrcMobile]);
    }

    #[test]
    fn an_identifier_inside_a_longer_digit_run_is_not_reported() {
        // The rule that holds machine ids out: a checksum-valid window
        // inside a longer number is not an identifier, it is part of the
        // number.
        assert!(kinds(&format!("99{ID_OK_2}99")).is_empty());
        assert!(kinds(&format!("7{VISA_OK}")).is_empty());
    }

    #[test]
    fn machine_ids_the_sliding_scanner_flagged_stay_clean() {
        for s in SNOWFLAKE_FLAGGED_BEFORE
            .iter()
            .chain(NS_TS_FLAGGED_BEFORE.iter())
        {
            assert!(scan(s.as_bytes()).is_empty(), "false positive on {s}");
        }
    }

    #[test]
    fn card_length_is_checked_per_brand() {
        assert!(
            luhn_ok(VISA_PREFIX_19.as_bytes()),
            "fixture must be Luhn-valid, else it tests nothing"
        );
        assert!(
            !is_bank_card(VISA_PREFIX_19.as_bytes()),
            "Visa does not issue 19-digit numbers; a prefix alone is not a brand"
        );
    }

    #[test]
    fn grouped_card_display_is_found_and_spans_the_separators() {
        for (body, card) in [
            ("卡号 6212 3456 7890 1232 已绑定", "6212 3456 7890 1232"),
            ("card: 4111-1111-1111-1111.", "4111-1111-1111-1111"),
        ] {
            let f = scan(body.as_bytes());
            assert_eq!(f.len(), 1, "{body}: {f:?}");
            assert_eq!(f[0].kind, FindingKind::BankCard);
            assert_eq!(&body[f[0].span.clone()], card);
        }
    }

    #[test]
    fn grouped_shapes_that_are_not_cards_stay_clean() {
        for s in [
            "2026-10-02",
            "139 1234 5678",
            "4111 1111-1111 1111", // inconsistent separator
            "1234 5678 9012 3456", // grouped, but no brand owns `1`
        ] {
            assert!(scan(s.as_bytes()).is_empty(), "false positive on {s:?}");
        }
    }

    #[test]
    fn mobile_requires_an_allocated_carrier_segment() {
        assert_eq!(kinds("13912345678"), vec![FindingKind::PrcMobile]);
        assert_eq!(kinds("tel: 13912345678."), vec![FindingKind::PrcMobile]);
        for unallocated in ["15412345678", "16012345678", "17912345678", "19412345678"] {
            assert!(kinds(unallocated).is_empty(), "{unallocated}");
        }
        assert!(
            kinds("139123456789").is_empty(),
            "12 digits is not a mobile"
        );
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
        assert_eq!(
            f.iter().map(|x| x.kind.clone()).collect::<Vec<_>>(),
            vec![FindingKind::PrcIdCard, FindingKind::BankCard],
            "{f:?}"
        );
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
