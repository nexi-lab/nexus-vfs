//! Where the bytes of a JSON document are.
//!
//! Content on the gated planes is almost always JSON — an A2A envelope, a
//! chat-completion request — and the gate has to treat its structure as
//! the protocol's, not the sender's. Two consequences, both found the hard
//! way against a real analyzer:
//!
//! * **classify content, not the schema.** NER run over raw JSON tagged
//!   the key `"to"` as a LOCATION, and a writer that escapes non-ASCII
//!   (Python's `json.dumps` does by default) hides every Chinese name
//!   behind `\uXXXX`. A detector has to be handed the *decoded string
//!   values*, with keys left out.
//! * **redact without breaking the message.** Replacing that key produced
//!   `{…,[REDACTED:LOCATION]:"cloud-agent"}` — not JSON. A redaction may
//!   rewrite the inside of a string value or a whole number, and nothing
//!   else.
//!
//! This module only answers "where": which byte ranges are string-value
//! interiors, which are keys, which are numbers, where the escape
//! sequences are, and how decoded characters map back onto raw bytes.

use std::ops::Range;

/// One string literal's interior — the bytes between its quotes.
#[derive(Debug, Clone)]
pub(crate) struct StrLit {
    pub raw: Range<usize>,
    /// Followed by `:` — an object key, i.e. the schema's vocabulary.
    pub is_key: bool,
}

/// The layout of a document that parsed as JSON.
#[derive(Debug, Default)]
pub(crate) struct Layout {
    pub strings: Vec<StrLit>,
    pub numbers: Vec<Range<usize>>,
    /// Raw byte ranges of escape sequences (`\n`, `\uXXXX`, a surrogate
    /// pair counts as two). A redaction must never cut one.
    pub escapes: Vec<Range<usize>>,
}

/// The layout of `content`, or `None` if it is not JSON.
///
/// Validity is checked by a real parser first, so the scanner below can
/// assume well-formed input instead of re-implementing JSON's grammar.
pub(crate) fn layout(content: &[u8]) -> Option<Layout> {
    serde_json::from_slice::<serde::de::IgnoredAny>(content).ok()?;
    let c = content;
    let mut out = Layout::default();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            b'"' => {
                let start = i + 1;
                i = start;
                while c[i] != b'"' {
                    if c[i] == b'\\' {
                        let len = if c[i + 1] == b'u' { 6 } else { 2 };
                        out.escapes.push(i..i + len);
                        i += len;
                    } else {
                        i += 1;
                    }
                }
                let raw = start..i;
                i += 1;
                let mut j = i;
                while j < c.len() && c[j].is_ascii_whitespace() {
                    j += 1;
                }
                let is_key = c.get(j) == Some(&b':');
                out.strings.push(StrLit { raw, is_key });
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                while i < c.len() && matches!(c[i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    i += 1;
                }
                out.numbers.push(start..i);
            }
            _ => i += 1,
        }
    }
    Some(out)
}

/// Decode one string literal, returning its text and the raw byte offset
/// at which each decoded character starts (plus one entry for the end).
///
/// `None` only for an escape that does not decode — impossible after
/// [`layout`]'s parse, so callers may treat it as "not JSON".
#[cfg(any(feature = "presidio", test))]
pub(crate) fn decode(content: &[u8], lit: &StrLit) -> Option<(String, Vec<usize>)> {
    let raw = &content[lit.raw.clone()];
    let base = lit.raw.start;
    let mut text = String::with_capacity(raw.len());
    let mut at = Vec::with_capacity(raw.len() + 1);
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            let (ch, len) = match raw[i + 1] {
                b'"' => ('"', 2),
                b'\\' => ('\\', 2),
                b'/' => ('/', 2),
                b'b' => ('\u{8}', 2),
                b'f' => ('\u{c}', 2),
                b'n' => ('\n', 2),
                b'r' => ('\r', 2),
                b't' => ('\t', 2),
                b'u' => {
                    let hex = |at: usize| {
                        std::str::from_utf8(raw.get(at..at + 4)?)
                            .ok()
                            .and_then(|h| u32::from_str_radix(h, 16).ok())
                    };
                    let hi = hex(i + 2)?;
                    if (0xD800..0xDC00).contains(&hi)
                        && raw.get(i + 6) == Some(&b'\\')
                        && raw.get(i + 7) == Some(&b'u')
                    {
                        let lo = hex(i + 8)?;
                        let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                        (char::from_u32(cp)?, 12)
                    } else {
                        (char::from_u32(hi)?, 6)
                    }
                }
                _ => return None,
            };
            at.push(base + i);
            text.push(ch);
            i += len;
        } else {
            // Unescaped: copy one UTF-8 character through.
            let width = utf8_width(raw[i]);
            let s = std::str::from_utf8(raw.get(i..i + width)?).ok()?;
            at.push(base + i);
            text.push_str(s);
            i += width;
        }
    }
    at.push(lit.raw.end);
    Some((text, at))
}

#[cfg(any(feature = "presidio", test))]
fn utf8_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(doc: &str) -> Vec<(String, bool)> {
        let l = layout(doc.as_bytes()).expect("json");
        l.strings
            .iter()
            .map(|s| (doc[s.raw.clone()].to_string(), s.is_key))
            .collect()
    }

    #[test]
    fn tells_keys_from_values() {
        assert_eq!(
            strings(r#"{"to" : "cloud", "n": [ "a", "b" ]}"#),
            vec![
                ("to".into(), true),
                ("cloud".into(), false),
                ("n".into(), true),
                ("a".into(), false),
                ("b".into(), false),
            ]
        );
    }

    /// A JSON `\uXXXX` escape for one UTF-16 code unit, built rather than
    /// spelled so no tool or editor can turn the fixture back into the
    /// character it encodes — which would leave these tests testing nothing.
    fn u_hex(unit: u32) -> String {
        format!("{}u{unit:04x}", '\\')
    }

    #[test]
    fn finds_numbers_and_escapes() {
        let zhang = u_hex('张' as u32);
        let doc = format!(r#"{{"card":4111111111111111,"x":-1.5e3,"s":"a\"b{zhang}"}}"#);
        let l = layout(doc.as_bytes()).unwrap();
        let nums: Vec<&str> = l.numbers.iter().map(|r| &doc[r.clone()]).collect();
        assert_eq!(nums, vec!["4111111111111111", "-1.5e3"]);
        let esc: Vec<&str> = l.escapes.iter().map(|r| &doc[r.clone()]).collect();
        assert_eq!(esc, vec![r#"\""#, zhang.as_str()]);
    }

    #[test]
    fn not_json_is_none() {
        assert!(layout(b"plain text, not a document").is_none());
        assert!(layout(br#"{"open": "#).is_none());
    }

    #[test]
    fn decodes_escaped_chinese_and_maps_back_to_raw_bytes() {
        // What Python's json.dumps(ensure_ascii=True) writes for 张三.
        let name_raw = format!("{}{}", u_hex('张' as u32), u_hex('三' as u32));
        assert!(name_raw.is_ascii(), "fixture must really be escaped");
        let doc = format!(r#"{{"body":"客户{name_raw}好"}}"#);
        let l = layout(doc.as_bytes()).unwrap();
        let (text, at) = decode(doc.as_bytes(), &l.strings[1]).unwrap();
        assert_eq!(text, "客户张三好");
        // 张三 is decoded characters 2..4; its raw bytes are the two escapes.
        assert_eq!(&doc[at[2]..at[4]], name_raw);
        assert_eq!(at.len(), text.chars().count() + 1);
    }

    #[test]
    fn decodes_a_surrogate_pair_as_one_character() {
        let pair = format!("{}{}", u_hex(0xd83d), u_hex(0xde00));
        let doc = format!(r#"["a{pair}b"]"#);
        let l = layout(doc.as_bytes()).unwrap();
        let (text, at) = decode(doc.as_bytes(), &l.strings[0]).unwrap();
        assert_eq!(text, "a\u{1F600}b");
        assert_eq!(&doc[at[1]..at[2]], pair);
    }

    #[test]
    fn decoded_text_matches_a_real_parser() {
        let doc = r#"{"k":"tab\there \"q\" \\ \/ \n end 中文 é"}"#;
        let l = layout(doc.as_bytes()).unwrap();
        let (text, _) = decode(doc.as_bytes(), &l.strings[1]).unwrap();
        let v: serde_json::Value = serde_json::from_str(doc).unwrap();
        assert_eq!(text, v["k"].as_str().unwrap());
    }
}
