//! Presidio as a contextual detector, called over loopback HTTP.
//!
//! The deterministic rules prove structured identifiers and are blind to
//! everything contextual — a person's name, an address, an organisation.
//! Presidio's analyzer (Microsoft, MIT) covers those with NER plus pattern
//! recognizers, and runs as a local service, so the gate can use it
//! without content leaving the node.
//!
//! # Three things this module is strict about
//!
//! **The analyzer must be on loopback.** The provider sends the content it
//! is asked to classify to the analyzer, so an analyzer anywhere else
//! would make the gate itself the egress it exists to stop. The check is
//! on the *resolved* address — every address the host resolves to must be
//! loopback — not on how the URL is spelled.
//!
//! **Offsets are code points, not bytes.** Presidio is Python, and a
//! Python string offset counts code points. Chinese text is one code point
//! but three UTF-8 bytes per character, so reading Presidio's `start` as a
//! byte offset would redact the wrong bytes — leaving the name in place
//! and mangling its neighbours. Offsets are converted explicitly, and a
//! span outside the text fails the whole verdict.
//!
//! **It blocks the write, so it is bounded.** The hook is synchronous on
//! the write path; the call has a connect deadline, an overall deadline,
//! and a response-size cap. Any of them tripping is an `Err`, which the
//! gate's policy turns into a refusal by default — the analyzer being slow
//! or down is never read as "nothing sensitive here".
//!
//! # Language
//!
//! The stock analyzer image ships English models only. A Chinese
//! deployment needs a spaCy Chinese pipeline and recognizers configured
//! in the analyzer; that is deployment work on the analyzer's side, not
//! something this client can do. A language the analyzer has no
//! recognizers for comes back as an HTTP error, so a misconfigured
//! analyzer fails closed rather than quietly finding nothing.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::classifier::{
    Classification, Confidence, EgressClassifier, EgressRequest, Finding, FindingKind,
};

/// Largest analyzer response accepted. A findings list for a write the
/// gate would ever pass is a few kilobytes; anything near this is a
/// misbehaving server, not a verdict.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// How to reach and ask the analyzer.
#[derive(Debug, Clone)]
pub struct PresidioConfig {
    /// `http://<loopback host>:<port>`, optionally with a path prefix. The
    /// provider posts to `<url>/analyze`.
    pub url: String,
    /// Presidio language code, e.g. `zh` or `en`.
    pub language: String,
    /// Findings scored below this are not reported.
    pub score_threshold: f64,
    /// Entity types to ask for; empty = everything the analyzer knows.
    pub entities: Vec<String>,
    /// Applies to connecting and, separately, to the whole exchange.
    pub timeout: Duration,
}

/// Contextual classification by a local Presidio analyzer.
pub struct PresidioAnalyzer {
    addr: SocketAddr,
    host: String,
    path: String,
    language: String,
    score_threshold: f64,
    entities: Vec<String>,
    timeout: Duration,
}

impl PresidioAnalyzer {
    /// # Errors
    ///
    /// A URL that is not `http://`, that does not resolve, or that resolves
    /// to anything other than loopback.
    pub fn new(cfg: PresidioConfig) -> Result<Self, String> {
        let rest = cfg.url.strip_prefix("http://").ok_or_else(|| {
            format!(
                "presidio url {:?} must be http:// on loopback (the content travels to it)",
                cfg.url
            )
        })?;
        let (authority, prefix) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let addrs: Vec<SocketAddr> = authority
            .to_socket_addrs()
            .map_err(|e| {
                format!(
                    "presidio url {:?}: cannot resolve {authority:?}: {e}",
                    cfg.url
                )
            })?
            .collect();
        if addrs.is_empty() || !addrs.iter().all(|a| a.ip().is_loopback()) {
            return Err(format!(
                "presidio url {:?} resolves to {addrs:?}; the analyzer must be on loopback, \
                 because the content being classified is sent to it",
                cfg.url
            ));
        }
        Ok(Self {
            addr: addrs[0],
            host: authority.to_string(),
            path: format!("{prefix}/analyze"),
            language: cfg.language,
            score_threshold: cfg.score_threshold,
            entities: cfg.entities,
            timeout: cfg.timeout,
        })
    }

    fn request_body(&self, text: &str) -> Vec<u8> {
        let mut body = serde_json::json!({
            "text": text,
            "language": self.language,
            "score_threshold": self.score_threshold,
        });
        if !self.entities.is_empty() {
            body["entities"] = serde_json::json!(self.entities);
        }
        body.to_string().into_bytes()
    }

    /// One blocking `POST` with `Connection: close`, read to EOF under an
    /// overall deadline.
    fn post(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + self.timeout;
        let mut sock = TcpStream::connect_timeout(&self.addr, self.timeout)
            .map_err(|e| format!("connect {}: {e}", self.addr))?;
        sock.set_write_timeout(Some(self.timeout)).ok();
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            body.len()
        );
        sock.write_all(head.as_bytes())
            .and_then(|()| sock.write_all(body))
            .map_err(|e| format!("send to {}: {e}", self.addr))?;

        let mut buf = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!("analyzer at {} timed out", self.addr));
            }
            sock.set_read_timeout(Some(left)).ok();
            match sock.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() > MAX_RESPONSE {
                        return Err(format!("analyzer response exceeds {MAX_RESPONSE} bytes"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("read from {}: {e}", self.addr)),
            }
        }
        parse_http_response(&buf)
    }
}

/// Split a complete HTTP/1.1 response into its body, decoding chunked
/// transfer if used. Non-200 is an error carrying (a prefix of) the body,
/// which is where Presidio puts its reason.
fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Err("analyzer closed mid-headers".into()),
        Err(e) => return Err(format!("analyzer sent a malformed response: {e}")),
    };
    let status = resp.code.unwrap_or(0);
    let header = |name: &str| {
        resp.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_ascii_lowercase())
    };
    let rest = &raw[head_len..];
    let body = if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        decode_chunked(rest)?
    } else if let Some(len) = header("content-length") {
        let len: usize = len
            .parse()
            .map_err(|_| format!("analyzer sent content-length {len:?}"))?;
        if rest.len() < len {
            return Err(format!(
                "analyzer response truncated: {} of {len} bytes",
                rest.len()
            ));
        }
        rest[..len].to_vec()
    } else {
        rest.to_vec()
    };
    if status != 200 {
        let reason = String::from_utf8_lossy(&body[..body.len().min(300)]).into_owned();
        return Err(format!("analyzer returned HTTP {status}: {reason}"));
    }
    Ok(body)
}

fn decode_chunked(mut raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("analyzer chunked body: missing chunk size line")?;
        let size_str = std::str::from_utf8(&raw[..line_end])
            .map_err(|_| "analyzer chunked body: non-ascii chunk size")?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| format!("analyzer chunked body: bad chunk size {size_str:?}"))?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if raw.len() < size + 2 {
            return Err("analyzer chunked body: truncated chunk".into());
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

/// One finding as Presidio reports it. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct PresidioResult {
    entity_type: String,
    start: usize,
    end: usize,
}

/// Map Presidio's code-point spans onto `text`'s bytes.
fn to_findings(text: &str, results: Vec<PresidioResult>) -> Result<Vec<Finding>, String> {
    // byte_at[i] = byte offset of code point i; one past the end included.
    let mut byte_at: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
    byte_at.push(text.len());
    let chars = byte_at.len() - 1;
    results
        .into_iter()
        .map(|r| {
            if r.start > r.end || r.end > chars {
                return Err(format!(
                    "analyzer reported {} at {}..{} in a {chars}-character text",
                    r.entity_type, r.start, r.end
                ));
            }
            Ok(finding(&r.entity_type, byte_at[r.start]..byte_at[r.end]))
        })
        .collect()
}

impl EgressClassifier for PresidioAnalyzer {
    fn name(&self) -> &str {
        "presidio"
    }

    fn classify(&self, req: &EgressRequest<'_>) -> Result<Classification, String> {
        // The analyzer takes text. Content on the gated planes is JSON, so
        // non-UTF-8 here is unexpected — and unclassifiable, which is not
        // the same as clean.
        let text = std::str::from_utf8(req.content)
            .map_err(|_| "content is not UTF-8, so the analyzer cannot read it".to_string())?;
        let findings = match crate::json_layout::layout(req.content) {
            None => to_findings(text, self.analyze(text)?)?,
            Some(layout) => {
                let values = DecodedValues::of(req.content, &layout)?;
                if values.text.is_empty() {
                    return Ok(Classification::clean());
                }
                values.to_findings(self.analyze(&values.text)?)?
            }
        };
        Ok(Classification {
            findings,
            label: None,
        })
    }
}

impl PresidioAnalyzer {
    fn analyze(&self, text: &str) -> Result<Vec<PresidioResult>, String> {
        let body = self.post(&self.request_body(text))?;
        serde_json::from_slice(&body)
            .map_err(|e| format!("analyzer response is not a findings list: {e}"))
    }
}

/// Keys whose string values are prose — what a person or a model wrote —
/// in the payloads the gate sees: the A2A envelope's `body`; a chat
/// request's `content` and its parts' `text`; `system`, `instructions`,
/// `prompt` and `input` across the provider APIs; a tool call's
/// `arguments`.
///
/// Contextual detection runs on these and nowhere else. Every other value
/// is protocol, and NER on protocol identifiers is noise with a cost: on a
/// real request it tagged the model name `qwen3-30b` as a PERSON, and
/// redacting it made the request unroutable. The provable rules still run
/// over every byte — an identity number is a leak wherever it sits. The
/// trade is stated plainly: a name inside a structured tool parameter under
/// some other key is left to the provable rules.
const PROSE_KEYS: &[&str] = &[
    "body",
    "content",
    "text",
    "system",
    "instructions",
    "prompt",
    "input",
    "arguments",
];

/// The decoded prose values of a JSON document, joined for one analyzer
/// call, with every character's raw byte range in the document.
///
/// Prose values only: keys are the schema, and handing them to NER is how
/// the key `"to"` came back as a LOCATION; other values are protocol (see
/// [`PROSE_KEYS`]). A value with no key above it — a bare string document —
/// is prose. Decoded: a writer that escapes
/// non-ASCII (`json.dumps` does by default) would otherwise hide every
/// Chinese name behind `\uXXXX`, which NER cannot read. Values are joined
/// by a blank line so the analyzer never reads two of them as one entity.
struct DecodedValues {
    text: String,
    /// Per character of `text`: its raw byte range, or `None` for the
    /// separator between two values.
    raw: Vec<Option<(usize, usize)>>,
}

impl DecodedValues {
    fn of(content: &[u8], layout: &crate::json_layout::Layout) -> Result<Self, String> {
        let mut text = String::new();
        let mut raw = Vec::new();
        let prose = |l: &&crate::json_layout::StrLit| {
            !l.is_key && l.owner.as_deref().is_none_or(|k| PROSE_KEYS.contains(&k))
        };
        for lit in layout.strings.iter().filter(prose) {
            let (value, at) = crate::json_layout::decode(content, lit)
                .ok_or("content parsed as JSON but a string value did not decode")?;
            if value.is_empty() {
                continue;
            }
            if !text.is_empty() {
                text.push_str("\n\n");
                raw.extend([None, None]);
            }
            for (k, ch) in value.chars().enumerate() {
                text.push(ch);
                raw.push(Some((at[k], at[k + 1])));
            }
        }
        Ok(Self { text, raw })
    }

    /// Map code-point spans in the joined text onto the document's bytes.
    /// A span that runs across a separator becomes one finding per value
    /// it touches, so no finding ever covers JSON syntax.
    fn to_findings(&self, results: Vec<PresidioResult>) -> Result<Vec<Finding>, String> {
        let mut out = Vec::new();
        for r in results {
            if r.start > r.end || r.end > self.raw.len() {
                return Err(format!(
                    "analyzer reported {} at {}..{} in a {}-character text",
                    r.entity_type,
                    r.start,
                    r.end,
                    self.raw.len()
                ));
            }
            let mut run: Option<(usize, usize)> = None;
            for slot in &self.raw[r.start..r.end] {
                match (*slot, run) {
                    (Some((s, e)), Some((rs, re))) if s == re => run = Some((rs, e)),
                    (Some(span), prev) => {
                        if let Some((rs, re)) = prev {
                            out.push(finding(&r.entity_type, rs..re));
                        }
                        run = Some(span);
                    }
                    (None, prev) => {
                        if let Some((rs, re)) = prev {
                            out.push(finding(&r.entity_type, rs..re));
                        }
                        run = None;
                    }
                }
            }
            if let Some((rs, re)) = run {
                out.push(finding(&r.entity_type, rs..re));
            }
        }
        Ok(out)
    }
}

fn finding(entity_type: &str, span: std::ops::Range<usize>) -> Finding {
    Finding {
        kind: FindingKind::Other(entity_type.to_string()),
        span,
        // A model's score, not a checksum.
        confidence: Confidence::Probable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn cfg(url: &str) -> PresidioConfig {
        PresidioConfig {
            url: url.to_string(),
            language: "zh".into(),
            score_threshold: 0.5,
            entities: vec![],
            timeout: Duration::from_secs(5),
        }
    }

    /// A one-shot analyzer stand-in that answers with `response` verbatim
    /// and hands back the request it received.
    fn serve(response: Vec<u8>) -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut req = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read the head, then exactly content-length bytes.
            loop {
                let n = sock.read(&mut chunk).unwrap_or(0);
                req.extend_from_slice(&chunk[..n]);
                if n == 0 {
                    break;
                }
                if let Some(h) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&req[..h]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse().unwrap());
                    if req.len() >= h + 4 + len {
                        break;
                    }
                }
            }
            sock.write_all(&response).unwrap();
            tx.send(req).unwrap();
        });
        (url, rx)
    }

    fn ok_json(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn classify(analyzer: &PresidioAnalyzer, text: &str) -> Result<Classification, String> {
        analyzer.classify(&EgressRequest {
            path: "/conversations/x/transcript",
            agent_id: "a",
            zone_id: "root",
            content: text.as_bytes(),
        })
    }

    #[test]
    fn refuses_an_analyzer_off_loopback() {
        // The content travels to the analyzer, so a remote one would be
        // the leak the gate exists to stop.
        for url in ["http://10.0.0.5:5002", "http://192.168.1.11:5002"] {
            let err = PresidioAnalyzer::new(cfg(url)).err().expect("must refuse");
            assert!(err.contains("loopback"), "{err}");
        }
    }

    #[test]
    fn refuses_https_and_bare_hosts() {
        assert!(PresidioAnalyzer::new(cfg("https://127.0.0.1:5002")).is_err());
        assert!(PresidioAnalyzer::new(cfg("127.0.0.1:5002")).is_err());
    }

    #[test]
    fn accepts_loopback_spellings() {
        for url in [
            "http://127.0.0.1:5002",
            "http://[::1]:5002",
            "http://localhost:5002",
        ] {
            assert!(PresidioAnalyzer::new(cfg(url)).is_ok(), "{url}");
        }
    }

    #[test]
    fn maps_code_point_offsets_onto_bytes() {
        // 「张三」 is code points 3..5 but bytes 9..15 — the case a naive
        // byte reading would get wrong.
        let text = "客户：张三，好";
        let f = to_findings(
            text,
            vec![PresidioResult {
                entity_type: "PERSON".into(),
                start: 3,
                end: 5,
            }],
        )
        .unwrap();
        assert_eq!(&text[f[0].span.clone()], "张三");
        assert_eq!(f[0].kind, FindingKind::Other("PERSON".into()));
        assert_eq!(f[0].confidence, Confidence::Probable);
    }

    #[test]
    fn a_span_past_the_text_fails_the_verdict() {
        let err = to_findings(
            "短",
            vec![PresidioResult {
                entity_type: "PERSON".into(),
                start: 0,
                end: 9,
            }],
        )
        .unwrap_err();
        assert!(err.contains("1-character"), "{err}");
    }

    #[test]
    fn end_to_end_against_a_stand_in_analyzer() {
        let (url, rx) = serve(ok_json(
            r#"[{"entity_type":"PERSON","start":3,"end":5,"score":0.85,"analysis_explanation":null}]"#,
        ));
        let a = PresidioAnalyzer::new(PresidioConfig {
            entities: vec!["PERSON".into()],
            ..cfg(&url)
        })
        .unwrap();
        let text = "客户：张三，好";
        let got = classify(&a, text).unwrap();
        assert_eq!(&text[got.findings[0].span.clone()], "张三");

        let req = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(req.starts_with("POST /analyze HTTP/1.1\r\n"), "{req}");
        let body: serde_json::Value =
            serde_json::from_str(req.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["text"], text);
        assert_eq!(body["language"], "zh");
        assert_eq!(body["entities"], serde_json::json!(["PERSON"]));
    }

    #[test]
    fn a_path_prefix_is_kept() {
        let (url, rx) = serve(ok_json("[]"));
        let a = PresidioAnalyzer::new(cfg(&format!("{url}/presidio/"))).unwrap();
        classify(&a, "hi").unwrap();
        let req = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(req.starts_with("POST /presidio/analyze "), "{req}");
    }

    #[test]
    fn decodes_a_chunked_response() {
        let body = r#"[{"entity_type":"LOCATION","start":0,"end":2,"score":0.9}]"#;
        let (a, b) = body.split_at(10);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
            a.len(),
            b.len()
        );
        let (url, _rx) = serve(resp.into_bytes());
        let got = classify(&PresidioAnalyzer::new(cfg(&url)).unwrap(), "北京欢迎你").unwrap();
        assert_eq!(got.findings.len(), 1);
    }

    #[test]
    fn an_analyzer_error_is_an_error_not_a_clean_verdict() {
        // What the stock image says to a language it has no models for.
        let body = r#"{"error":"No matching recognizers were found to serve the request."}"#;
        let resp = format!(
            "HTTP/1.1 500 INTERNAL SERVER ERROR\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (url, _rx) = serve(resp.into_bytes());
        let err = classify(&PresidioAnalyzer::new(cfg(&url)).unwrap(), "x").unwrap_err();
        assert!(
            err.contains("HTTP 500") && err.contains("No matching"),
            "{err}"
        );
    }

    #[test]
    fn an_unreachable_analyzer_is_an_error() {
        // Bind then drop, so the port is very likely closed.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let a = PresidioAnalyzer::new(cfg(&format!("http://127.0.0.1:{port}"))).unwrap();
        assert!(classify(&a, "x").is_err());
    }

    #[test]
    fn a_silent_analyzer_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // Accept and never answer.
        let _hold = std::thread::spawn(move || {
            let (_s, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(5));
        });
        let a = PresidioAnalyzer::new(PresidioConfig {
            timeout: Duration::from_millis(300),
            ..cfg(&url)
        })
        .unwrap();
        let started = Instant::now();
        let err = classify(&a, "x").unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "deadline not honoured"
        );
        assert!(
            err.contains("timed out") || err.contains("read from"),
            "{err}"
        );
    }

    #[test]
    fn non_utf8_content_is_unclassifiable() {
        let a = PresidioAnalyzer::new(cfg("http://127.0.0.1:9")).unwrap();
        let err = a
            .classify(&EgressRequest {
                path: "/conversations/x/transcript",
                agent_id: "a",
                zone_id: "root",
                content: &[0xff, 0xfe],
            })
            .unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
    }

    /// `\uXXXX` for one BMP character, built rather than spelled so no
    /// tool can turn the fixture back into the character.
    fn u_esc(c: char) -> String {
        format!("{}u{:04x}", '\\', c as u32)
    }

    #[test]
    fn json_content_sends_decoded_values_only_and_maps_back_through_escapes() {
        // An envelope as Python's json.dumps writes it: the name escaped.
        let name_raw = format!("{}{}", u_esc('张'), u_esc('三'));
        let doc = format!(r#"{{"from":"a","to":"b","body":"客户{name_raw}好"}}"#);
        // Only the prose value is sent, decoded: "客户张三好" — so 张三 is
        // characters 2..4. `from` and `to` are protocol.
        let (url, rx) = serve(ok_json(
            r#"[{"entity_type":"PERSON","start":2,"end":4,"score":0.9}]"#,
        ));
        let a = PresidioAnalyzer::new(cfg(&url)).unwrap();
        let got = classify(&a, &doc).unwrap();

        let req = String::from_utf8(rx.recv().unwrap()).unwrap();
        let sent: serde_json::Value =
            serde_json::from_str(req.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(sent["text"], "客户张三好", "prose, decoded, nothing else");

        assert_eq!(got.findings.len(), 1);
        assert_eq!(&doc[got.findings[0].span.clone()], name_raw);
        let refs: Vec<&Finding> = got.findings.iter().collect();
        let out = crate::redact(doc.as_bytes(), &refs).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.content).unwrap();
        assert_eq!(v["body"], "客户[REDACTED:PERSON]好");
        assert_eq!(v["to"], "b");
    }

    #[test]
    fn a_span_across_two_values_becomes_one_finding_per_value() {
        let doc = r#"{"content":"甲乙","text":"丙丁"}"#;
        let layout = crate::json_layout::layout(doc.as_bytes()).unwrap();
        let values = DecodedValues::of(doc.as_bytes(), &layout).unwrap();
        assert_eq!(values.text, "甲乙\n\n丙丁");
        // 乙 .. 丙, across the separator.
        let f = values
            .to_findings(vec![PresidioResult {
                entity_type: "PERSON".into(),
                start: 1,
                end: 5,
            }])
            .unwrap();
        let parts: Vec<&str> = f.iter().map(|x| &doc[x.span.clone()]).collect();
        assert_eq!(parts, vec!["乙", "丙"]);
    }

    #[test]
    fn a_chat_requests_protocol_fields_never_reach_the_analyzer() {
        // On the box, NER tagged the model name as a PERSON and the
        // redacted request could not be routed.
        let doc = r#"{"model":"qwen3-30b","messages":[{"role":"user","content":"客户张三"},{"role":"assistant","content":[{"type":"text","text":"好的"}]}],"stream":true}"#;
        let layout = crate::json_layout::layout(doc.as_bytes()).unwrap();
        let values = DecodedValues::of(doc.as_bytes(), &layout).unwrap();
        assert_eq!(values.text, "客户张三\n\n好的");
        for protocol in ["qwen3-30b", "user", "assistant"] {
            assert!(!values.text.contains(protocol), "{protocol} was sent");
        }
    }

    #[test]
    fn a_bare_string_document_is_prose() {
        let doc = r#""客户张三""#;
        let layout = crate::json_layout::layout(doc.as_bytes()).unwrap();
        let values = DecodedValues::of(doc.as_bytes(), &layout).unwrap();
        assert_eq!(values.text, "客户张三");
    }
}
