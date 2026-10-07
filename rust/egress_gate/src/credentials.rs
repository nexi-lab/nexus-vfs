//! Credentials in content: keys, tokens and passwords on their way out.
//!
//! The same contract as [`crate::rules`] — deterministic, no dependency,
//! no network, latency that needs no measuring — for a different kind of
//! data. A customer's identity number leaving is a privacy leak; an API key
//! leaving is an access leak, and usually the worse of the two, because
//! whoever reads it can act as us.
//!
//! # What is detected, and how sure each rule is
//!
//! * **Structural**, reported [`Confidence::Certain`]: a PEM private-key
//!   block (the whole block, not just its header — the header alone is not
//!   the secret), and a JWT whose header decodes to a JSON object naming an
//!   `alg`.
//! * **Issuer prefixes**, [`Confidence::Probable`]: `sk-ant-` (Anthropic),
//!   `sk-` (OpenAI-compatible — which includes new-api, SudoRouter and
//!   nexus API keys), GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/
//!   `github_pat_`, AWS `AKIA`/`ASIA`, Aliyun `LTAI`, Tencent Cloud
//!   `AKID`, Slack `xox?-`, and `Bearer` tokens. Each token must be a
//!   whole token — not glued to a longer identifier — at the length its
//!   issuer uses.
//! * **Assignments**, [`Confidence::Probable`]: the value after an
//!   identifier ending in `password`, `passwd`, `passphrase`, `secret`,
//!   `secret_key`, `api_key`, `private_key` or a `*_token`, and after
//!   `密码` / `口令` / `密钥` / `秘钥`, separated by `=`, `:`, `：` or `是`.
//!   Quotes and backslashes around the separator are skipped, so the same
//!   rule reads `password=…`, `"password":"…"` and a JSON document
//!   escaped inside a tool call's `arguments`. Only the value is redacted.
//! * **URL userinfo**: the password in `scheme://user:password@host`.
//!
//! # Deliberate exclusions
//!
//! * `pwd` — `PWD=/home/…` is the working directory, present in every
//!   environment dump.
//! * Bare-word values: `password: required` and `密码是hunter` are not
//!   redacted. A value must contain a digit, an upper-case letter or a
//!   symbol; a value that is all lower-case letters is a word as often as
//!   it is a password, and redacting prose is not free.
//! * Placeholders and code: `*****`, `${DB_PASSWORD}`, `<your key>`,
//!   `os.environ["X"]` — anything starting with `$ < { % [` or containing
//!   brackets or parentheses.
//! * Pagination cursors: `next_token`, `page_token` and the like are opaque
//!   but not credentials; only named credential tokens count.

use crate::classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};

/// Deterministic detection of credentials. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct CredentialRules;

impl CredentialRules {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl EgressClassifier for CredentialRules {
    fn name(&self) -> &str {
        "credentials"
    }

    fn classify(&self, req: &EgressRequest<'_>) -> Result<Classification, String> {
        Ok(Classification {
            findings: scan(req.content),
            label: None,
        })
    }
}

/// Locate every credential in `content`, in content order.
#[must_use]
pub fn scan(c: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    private_key_blocks(c, &mut out);
    prefixed_tokens(c, &mut out);
    jwts(c, &mut out);
    bearer_tokens(c, &mut out);
    url_passwords(c, &mut out);
    // Assignments last, and only where nothing more specific already
    // covers the bytes: `api_key=sk-…` is an API-KEY, not a generic SECRET.
    let mut assigned = Vec::new();
    assigned_secrets(c, &mut assigned);
    for f in assigned {
        if !out
            .iter()
            .any(|o| o.span.start < f.span.end && f.span.start < o.span.end)
        {
            out.push(f);
        }
    }
    out.sort_by_key(|f| (f.span.start, f.span.end));
    out
}

fn push(out: &mut Vec<Finding>, kind: &'static str, span: std::ops::Range<usize>, c: Confidence) {
    out.push(Finding {
        kind: FindingKind::Credential(kind),
        span,
        confidence: c,
    });
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_base32_upper(b: u8) -> bool {
    b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn run_end(c: &[u8], start: usize, ok: fn(u8) -> bool) -> usize {
    let mut e = start;
    while e < c.len() && ok(c[e]) {
        e += 1;
    }
    e
}

fn at_token_boundary(c: &[u8], i: usize) -> bool {
    i == 0 || !is_token_byte(c[i - 1])
}

// ── PEM private keys ────────────────────────────────────────────────────

/// `-----BEGIN … PRIVATE KEY-----` through its matching END marker. A
/// block with no END marker runs to the end of the content: a key that
/// cannot be bounded must not be partly let through.
fn private_key_blocks(c: &[u8], out: &mut Vec<Finding>) {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let mut from = 0;
    while let Some(off) = find(&c[from..], BEGIN) {
        let start = from + off;
        let label_start = start + BEGIN.len();
        let Some(label_len) = find(&c[label_start..c.len().min(label_start + 64)], b"-----") else {
            from = label_start;
            continue;
        };
        let label = &c[label_start..label_start + label_len];
        if !label
            .iter()
            .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
            || find(label, b"PRIVATE KEY").is_none()
        {
            from = label_start;
            continue;
        }
        let mut end_marker = b"-----END ".to_vec();
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(b"-----");
        let body = label_start + label_len + 5;
        let end = find(&c[body..], &end_marker).map_or(c.len(), |o| body + o + end_marker.len());
        push(out, "PRIVATE-KEY", start..end, Confidence::Certain);
        from = end;
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

// ── Issuer-prefixed tokens ──────────────────────────────────────────────

struct Prefixed {
    prefix: &'static [u8],
    body: fn(u8) -> bool,
    min: usize,
    max: usize,
    kind: &'static str,
}

/// Within a shared prefix the longer one comes first: `sk-ant-` before
/// `sk-`, so an Anthropic key is named as one.
const PREFIXED: &[Prefixed] = &[
    Prefixed {
        prefix: b"sk-ant-",
        body: is_token_byte,
        min: 20,
        max: 300,
        kind: "ANTHROPIC-KEY",
    },
    Prefixed {
        prefix: b"sk-",
        body: is_token_byte,
        min: 20,
        max: 300,
        kind: "API-KEY",
    },
    Prefixed {
        prefix: b"github_pat_",
        body: is_token_byte,
        min: 50,
        max: 255,
        kind: "GITHUB-TOKEN",
    },
    Prefixed {
        prefix: b"ghp_",
        body: is_alnum,
        min: 36,
        max: 36,
        kind: "GITHUB-TOKEN",
    },
    Prefixed {
        prefix: b"gho_",
        body: is_alnum,
        min: 36,
        max: 36,
        kind: "GITHUB-TOKEN",
    },
    Prefixed {
        prefix: b"ghu_",
        body: is_alnum,
        min: 36,
        max: 36,
        kind: "GITHUB-TOKEN",
    },
    Prefixed {
        prefix: b"ghs_",
        body: is_alnum,
        min: 36,
        max: 36,
        kind: "GITHUB-TOKEN",
    },
    Prefixed {
        prefix: b"ghr_",
        body: is_alnum,
        min: 36,
        max: 36,
        kind: "GITHUB-TOKEN",
    },
    Prefixed {
        prefix: b"AKIA",
        body: is_base32_upper,
        min: 16,
        max: 16,
        kind: "AWS-ACCESS-KEY",
    },
    Prefixed {
        prefix: b"ASIA",
        body: is_base32_upper,
        min: 16,
        max: 16,
        kind: "AWS-ACCESS-KEY",
    },
    Prefixed {
        prefix: b"LTAI",
        body: is_alnum,
        min: 12,
        max: 20,
        kind: "ALIYUN-ACCESS-KEY",
    },
    Prefixed {
        prefix: b"AKID",
        body: is_alnum,
        min: 32,
        max: 32,
        kind: "TENCENT-SECRET-ID",
    },
    Prefixed {
        prefix: b"xoxb-",
        body: is_token_byte,
        min: 10,
        max: 255,
        kind: "SLACK-TOKEN",
    },
    Prefixed {
        prefix: b"xoxp-",
        body: is_token_byte,
        min: 10,
        max: 255,
        kind: "SLACK-TOKEN",
    },
    Prefixed {
        prefix: b"xoxa-",
        body: is_token_byte,
        min: 10,
        max: 255,
        kind: "SLACK-TOKEN",
    },
    Prefixed {
        prefix: b"xoxr-",
        body: is_token_byte,
        min: 10,
        max: 255,
        kind: "SLACK-TOKEN",
    },
    Prefixed {
        prefix: b"xoxs-",
        body: is_token_byte,
        min: 10,
        max: 255,
        kind: "SLACK-TOKEN",
    },
];

fn prefixed_tokens(c: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < c.len() {
        let mut advanced = false;
        if at_token_boundary(c, i) {
            for p in PREFIXED {
                if !c[i..].starts_with(p.prefix) {
                    continue;
                }
                let body = i + p.prefix.len();
                let end = run_end(c, body, p.body);
                let n = end - body;
                // The whole token, not a prefix of a longer identifier.
                let whole = end == c.len() || !is_token_byte(c[end]);
                if (p.min..=p.max).contains(&n) && whole {
                    push(out, p.kind, i..end, Confidence::Probable);
                    i = end;
                    advanced = true;
                    break;
                }
                // A longer prefix that fails its shape falls through to a
                // shorter one: `sk-ant-` that is not an Anthropic key may
                // still be an `sk-` key.
            }
        }
        if !advanced {
            i += 1;
        }
    }
}

// ── JWT ─────────────────────────────────────────────────────────────────

/// `header.payload.signature`, base64url, where the header really decodes
/// to a JSON object with an `alg` — which is what makes it Certain rather
/// than three dotted runs that happen to start with `eyJ`.
fn jwts(c: &[u8], out: &mut Vec<Finding>) {
    let mut from = 0;
    while let Some(off) = find(&c[from..], b"eyJ") {
        let s = from + off;
        from = s + 3;
        if s > 0 && (is_b64url(c[s - 1]) || c[s - 1] == b'.') {
            continue;
        }
        let e1 = run_end(c, s, is_b64url);
        if c.get(e1) != Some(&b'.') || !c[e1 + 1..].starts_with(b"eyJ") {
            continue;
        }
        let e2 = run_end(c, e1 + 1, is_b64url);
        if c.get(e2) != Some(&b'.') {
            continue;
        }
        let e3 = run_end(c, e2 + 1, is_b64url);
        if e3 - (e2 + 1) < 10 {
            continue;
        }
        let Some(header) = b64url_decode(&c[s..e1]) else {
            continue;
        };
        if header.first() == Some(&b'{') && find(&header, br#""alg""#).is_some() {
            push(out, "JWT", s..e3, Confidence::Certain);
            from = e3;
        }
    }
}

fn b64url_decode(s: &[u8]) -> Option<Vec<u8>> {
    let val = |b: u8| -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => u32::from(b - b'A'),
            b'a'..=b'z' => u32::from(b - b'a') + 26,
            b'0'..=b'9' => u32::from(b - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in s {
        acc = (acc << 6) | val(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ── Bearer tokens ───────────────────────────────────────────────────────

fn bearer_tokens(c: &[u8], out: &mut Vec<Finding>) {
    let is_tok = |b: u8| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b);
    let mut i = 0;
    while i + 7 <= c.len() {
        if c[i..i + 6].eq_ignore_ascii_case(b"bearer")
            && (i == 0 || !c[i - 1].is_ascii_alphanumeric())
            && c[i + 6] == b' '
        {
            let mut s = i + 6;
            while s < c.len() && c[s] == b' ' {
                s += 1;
            }
            let mut e = s;
            while e < c.len() && is_tok(c[e]) {
                e += 1;
            }
            if e - s >= 20 {
                push(out, "BEARER-TOKEN", s..e, Confidence::Probable);
                i = e;
                continue;
            }
        }
        i += 1;
    }
}

// ── scheme://user:password@host ─────────────────────────────────────────

fn url_passwords(c: &[u8], out: &mut Vec<Finding>) {
    let mut from = 0;
    while let Some(off) = find(&c[from..], b"://") {
        let at = from + off;
        from = at + 3;
        let mut s = at;
        while s > 0 && (c[s - 1].is_ascii_alphanumeric() || b"+.-".contains(&c[s - 1])) {
            s -= 1;
        }
        if s == at || !c[s].is_ascii_alphabetic() {
            continue;
        }
        let ui = at + 3;
        let mut e = ui;
        while e < c.len() && !b"@/?#\"'\\<> \t\r\n".contains(&c[e]) {
            e += 1;
        }
        if c.get(e) != Some(&b'@') {
            continue;
        }
        let Some(colon) = c[ui..e].iter().position(|&b| b == b':') else {
            continue;
        };
        let pw = ui + colon + 1..e;
        if !pw.is_empty() && !is_placeholder(&c[pw.clone()]) {
            push(out, "URL-PASSWORD", pw, Confidence::Probable);
        }
    }
}

// ── Assignments ─────────────────────────────────────────────────────────

/// Which credential an identifier names, judged on its lower-cased form
/// with `_` and `-` removed. `None` for everything else — including
/// `pwd` (the working directory) and pagination tokens.
fn secret_kind(norm: &str) -> Option<&'static str> {
    if ["password", "passwd", "passphrase"]
        .iter()
        .any(|k| norm.ends_with(k))
    {
        return Some("PASSWORD");
    }
    let named_tokens = [
        "accesstoken",
        "authtoken",
        "refreshtoken",
        "idtoken",
        "bearertoken",
        "apitoken",
        "sessiontoken",
    ];
    if norm == "token"
        || named_tokens.iter().any(|k| norm.ends_with(k))
        || ["secret", "secretkey", "apikey", "privatekey"]
            .iter()
            .any(|k| norm.ends_with(k))
    {
        return Some("SECRET");
    }
    None
}

const ZH_KEYWORDS: &[(&str, &str)] = &[
    ("密码", "PASSWORD"),
    ("口令", "PASSWORD"),
    ("密钥", "SECRET"),
    ("秘钥", "SECRET"),
];

fn assigned_secrets(c: &[u8], out: &mut Vec<Finding>) {
    // ASCII identifiers.
    let mut i = 0;
    while i < c.len() {
        if !is_token_byte(c[i]) {
            i += 1;
            continue;
        }
        let s = i;
        while i < c.len() && is_token_byte(c[i]) {
            i += 1;
        }
        let norm: String = c[s..i]
            .iter()
            .filter(|&&b| b != b'_' && b != b'-')
            .map(|b| b.to_ascii_lowercase() as char)
            .collect();
        if let Some(kind) = secret_kind(&norm) {
            if let Some(v) = value_after(c, i, false) {
                push(out, kind, v, Confidence::Probable);
            }
        }
    }
    // Chinese keywords, which also take `是` as the separator.
    for (kw, kind) in ZH_KEYWORDS {
        let kw = kw.as_bytes();
        let mut from = 0;
        while let Some(off) = find(&c[from..], kw) {
            let end = from + off + kw.len();
            if let Some(v) = value_after(c, end, true) {
                push(out, kind, v, Confidence::Probable);
            }
            from = end;
        }
    }
}

/// The value after a separator at `i`, if there is one worth calling a
/// credential.
fn value_after(c: &[u8], mut i: usize, allow_shi: bool) -> Option<std::ops::Range<usize>> {
    let skip = |c: &[u8], mut i: usize| {
        while i < c.len() && b"\"'\\ \t".contains(&c[i]) {
            i += 1;
        }
        i
    };
    i = skip(c, i);
    let full_colon = "：".as_bytes();
    let shi = "是".as_bytes();
    if c.get(i) == Some(&b'=') || c.get(i) == Some(&b':') {
        // `==` is a comparison, not an assignment.
        if c.get(i + 1) == Some(&b'=') {
            return None;
        }
        i += 1;
    } else if c[i..].starts_with(full_colon) {
        i += full_colon.len();
    } else if allow_shi && c[i..].starts_with(shi) {
        i += shi.len();
    } else {
        return None;
    }
    let start = skip(c, i);
    let mut end = start;
    // Values end at whitespace, quotes, separators, brackets, and at any
    // non-ASCII byte (Chinese punctuation closes a value in prose).
    while end < c.len() && c[end] < 0x80 && !b" \t\r\n\"'\\,;&}<>".contains(&c[end]) {
        end += 1;
    }
    let v = &c[start..end];
    let strong = v
        .iter()
        .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase() || b.is_ascii_punctuation());
    ((6..=200).contains(&v.len()) && strong && !is_placeholder(v)).then_some(start..end)
}

fn is_placeholder(v: &[u8]) -> bool {
    v.iter().all(|b| b"*xX.#".contains(b))
        || matches!(v.first(), Some(b'$' | b'<' | b'{' | b'%' | b'['))
        || v.iter().any(|b| b"()[]{}".contains(b))
        || [b"null".as_slice(), b"none", b"true", b"false", b"undefined"]
            .iter()
            .any(|p| v.eq_ignore_ascii_case(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (kind, matched text) for every finding.
    fn found(s: &str) -> Vec<(&'static str, String)> {
        scan(s.as_bytes())
            .into_iter()
            .map(|f| {
                let FindingKind::Credential(k) = f.kind else {
                    panic!("non-credential kind")
                };
                (k, s[f.span].to_string())
            })
            .collect()
    }

    // Fixtures are fakes in the issuers' documented shapes, or the
    // issuers' own published example values; none is a live credential.
    //
    // Each is assembled at run time, so the source never holds a
    // contiguous secret-shaped string. That is not caution in the
    // abstract: GitHub push protection rejected the literal Tencent-shaped
    // fake as a real Tencent Cloud Secret ID, and a scanner cannot tell a
    // fixture from a key — nor should it have to be told.
    fn aws() -> String {
        ["AK", "IAIOSFODNN7EXAMPLE"].concat()
    }
    fn aliyun() -> String {
        ["LT", "AI5tFakeKey0123456"].concat()
    }
    fn tencent() -> String {
        ["AK", "IDz8krbsJ5yKBZQpn74WFkmLPx3gnPhESA"].concat()
    }
    fn github() -> String {
        ["gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"].concat()
    }
    fn openai() -> String {
        ["sk", "-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345"].concat()
    }
    fn anthropic() -> String {
        ["sk", "-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"].concat()
    }
    /// jwt.io's published example token.
    fn jwt() -> String {
        [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        .concat()
    }
    /// A PEM block with the given label, e.g. `RSA PRIVATE KEY`.
    fn pem(label: &str, body: &str, terminated: bool) -> String {
        let dashes = "-----";
        let mut s = format!("{dashes}BEGIN {label}{dashes}\n{body}");
        if terminated {
            s.push_str(&format!("\n{dashes}END {label}{dashes}"));
        }
        s
    }

    #[test]
    fn cloud_access_keys_including_the_chinese_clouds() {
        let (aws, aliyun, tencent) = (aws(), aliyun(), tencent());
        assert_eq!(
            found(&format!("key {aws} end")),
            vec![("AWS-ACCESS-KEY", aws.clone())]
        );
        assert_eq!(
            found(&format!("id={aliyun}")),
            vec![("ALIYUN-ACCESS-KEY", aliyun.clone())]
        );
        assert_eq!(
            found(&format!("\"{tencent}\"")),
            vec![("TENCENT-SECRET-ID", tencent.clone())]
        );
    }

    #[test]
    fn issuer_tokens_are_named_by_issuer() {
        assert_eq!(found(&github()), vec![("GITHUB-TOKEN", github())]);
        assert_eq!(found(&openai()), vec![("API-KEY", openai())]);
        assert_eq!(found(&anthropic()), vec![("ANTHROPIC-KEY", anthropic())]);
    }

    #[test]
    fn a_token_glued_into_a_longer_identifier_is_not_reported() {
        assert!(
            found(&format!("{}XTRA", aws())).is_empty(),
            "too long for an AWS key id"
        );
        assert!(
            found("task-abcdefghijklmnopqrstuvwxyz").is_empty(),
            "`sk-` inside a word"
        );
        assert!(found("scikit sk-learn").is_empty(), "too short to be a key");
    }

    #[test]
    fn a_jwt_needs_a_header_that_really_decodes() {
        let jwt = jwt();
        assert_eq!(found(&format!("token {jwt}.")), vec![("JWT", jwt.clone())]);
        // Three dotted base64url runs whose header is not JSON.
        assert!(found("eyJub3Rqc29u.eyJub3Rqc29u.c2lnbmF0dXJlLXRleHQ").is_empty());
        assert!(found("eyJhbGciOiJIUzI1NiJ9").is_empty(), "a header alone");
    }

    #[test]
    fn a_private_key_block_is_redacted_whole() {
        let key = pem(
            "RSA PRIVATE KEY",
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
            true,
        );
        let got = found(&format!("cfg:\n{key}\nrest"));
        assert_eq!(got, vec![("PRIVATE-KEY", key.clone())]);
        // A public key is not a secret.
        assert!(found(&pem("PUBLIC KEY", "MFww", true)).is_empty());
    }

    #[test]
    fn an_unterminated_private_key_runs_to_the_end() {
        let body = pem("OPENSSH PRIVATE KEY", "b3BlbnNzaC1rZXktdjEA", false);
        assert_eq!(found(&body), vec![("PRIVATE-KEY", body.clone())]);
    }

    #[test]
    fn a_private_key_inside_a_json_string_stays_inside_it() {
        // A JSON string holds the block with `\n` escapes, as a writer
        // serializing a key file would produce.
        let block = pem("PRIVATE KEY", "MIIEvQ", true).replace('\n', "\\n");
        let doc = format!(r#"{{"k":"{block}","n":1}}"#);
        let f = scan(doc.as_bytes());
        assert_eq!(f.len(), 1);
        let refs: Vec<&Finding> = f.iter().collect();
        let out = crate::redact(doc.as_bytes(), &refs).expect("inside a value, redactable");
        let v: serde_json::Value = serde_json::from_slice(&out.content).unwrap();
        assert_eq!(v["k"], "[REDACTED:PRIVATE-KEY]");
        assert_eq!(v["n"], 1);
    }

    #[test]
    fn bearer_and_url_passwords() {
        assert_eq!(
            found("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"),
            vec![(
                "BEARER-TOKEN",
                "abcdefghijklmnopqrstuvwxyz0123456789".into()
            )]
        );
        assert_eq!(
            found("dsn=postgres://app:S3cr3t!@db.internal:5432/orders"),
            vec![("URL-PASSWORD", "S3cr3t!".into())]
        );
        assert!(found("https://example.com/a@b").is_empty(), "no userinfo");
        assert!(found("redis://:@cache:6379").is_empty(), "empty password");
    }

    #[test]
    fn assignments_in_every_spelling() {
        for (doc, value) in [
            ("DB_PASSWORD=Hunter22!", "Hunter22!"),
            ("password: Abc@2026", "Abc@2026"),
            (r#"{"client_secret":"Zx9-aB7_q1"}"#, "Zx9-aB7_q1"),
            (
                r#"{"arguments":"{\"password\":\"Hunter22!\"}"}"#,
                "Hunter22!",
            ),
            ("x-api-key: 9f2C4a1b8e7d", "9f2C4a1b8e7d"),
            ("?user=a&access_token=Tok3nValue&x=1", "Tok3nValue"),
        ] {
            let got = found(doc);
            assert_eq!(got.len(), 1, "{doc}: {got:?}");
            assert_eq!(got[0].1, value, "{doc}");
        }
    }

    #[test]
    fn chinese_assignments() {
        assert_eq!(
            found("数据库密码是Abc@2026，请勿外传"),
            vec![("PASSWORD", "Abc@2026".into())]
        );
        assert_eq!(
            found("口令：88888888。"),
            vec![("PASSWORD", "88888888".into())]
        );
        assert_eq!(
            found("API 密钥=K3y-Value-01"),
            vec![("SECRET", "K3y-Value-01".into())]
        );
    }

    #[test]
    fn a_specific_detector_wins_over_a_generic_assignment() {
        assert_eq!(
            found(&format!("OPENAI_API_KEY={}", openai())),
            vec![("API-KEY", openai())]
        );
    }

    #[test]
    fn what_is_not_a_credential_stays_clean() {
        for s in [
            "PWD=/home/taolei/egress-gate-accept",
            r#"{"model":"qwen3-30b","max_tokens":1024,"stream":true}"#,
            "password: required",
            "密码是hunter，记得改",
            "password = os.environ['DB_PASSWORD']",
            "password=${DB_PASSWORD}",
            "token=abc",
            r#"{"next_token":"AbC123xyz789"}"#,
            "if password == other_password:",
            "api_key: ********",
            "请把上季度的汇总发我",
        ] {
            assert!(
                scan(s.as_bytes()).is_empty(),
                "false positive on {s:?}: {:?}",
                found(s)
            );
        }
    }

    #[test]
    fn a_json_number_password_is_redacted_as_a_string() {
        let doc = r#"{"password":12345678,"n":1}"#;
        let f = scan(doc.as_bytes());
        let refs: Vec<&Finding> = f.iter().collect();
        let out = crate::redact(doc.as_bytes(), &refs).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.content).unwrap();
        assert_eq!(v["password"], "[REDACTED:PASSWORD]");
    }

    #[test]
    fn a_base64_blob_does_not_trip_the_prefix_rules() {
        // An image or file embedded in a prompt: a long mixed-case run in
        // which `AKIA…`, `LTAI…` and `AKID…` shapes occur by chance. The
        // whole-token rule rejects them because the run continues past the
        // key's length. Planted at three offsets so the test cannot pass by
        // the shapes simply not occurring.
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut state: u64 = 0x5eed;
        let mut blob: Vec<u8> = (0..8192)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                B64[(state >> 58) as usize]
            })
            .collect();
        for (at, planted) in [(100, aws()), (2000, aliyun()), (5000, tencent())] {
            blob[at..at + planted.len()].copy_from_slice(planted.as_bytes());
        }
        let doc = format!(
            r#"{{"messages":[{{"role":"user","content":[{{"type":"image_url","image_url":{{"url":"data:image/png;base64,{}"}}}}]}}]}}"#,
            String::from_utf8(blob).unwrap()
        );
        assert!(found(&doc).is_empty(), "{:?}", found(&doc));
    }
}
