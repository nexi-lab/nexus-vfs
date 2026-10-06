//! The gate with a contextual detector: deterministic rules plus a Presidio
//! analyzer, on a real kernel's transcript stream.
//!
//! Two tests. The first needs a live analyzer with Chinese NER and is
//! ignored unless `PRESIDIO_URL` names one (`sudoedge/presidio` builds it);
//! the second needs nothing and pins the property that matters most when
//! the analyzer is NOT there — the write is refused, not waved through.
#![cfg(feature = "presidio")]

use std::sync::Arc;
use std::time::Duration;

use a2a::{conversation_id, conversation_transcript_path, install_a2a_stamp_hook};
use egress_gate::presidio::{PresidioAnalyzer, PresidioConfig};
use egress_gate::{AllOf, DeterministicRules, EgressClassifier, EgressPlane, GatePolicy};
use kernel::kernel::{Kernel, OperationContext};

const ID_SPECIMEN: &str = "11010519491231002X";

fn gated_kernel(url: &str, timeout: Duration, stamp: bool) -> Arc<Kernel> {
    let analyzer = PresidioAnalyzer::new(PresidioConfig {
        url: url.to_string(),
        language: "zh".into(),
        score_threshold: 0.3,
        entities: vec!["PERSON".into(), "LOCATION".into(), "ORGANIZATION".into()],
        timeout,
    })
    .expect("loopback analyzer accepted");
    let classifier: Arc<dyn EgressClassifier> = Arc::new(AllOf::new(vec![
        Arc::new(DeterministicRules::new()),
        Arc::new(analyzer),
    ]));
    let kernel = Arc::new(Kernel::new());
    if stamp {
        install_a2a_stamp_hook(&kernel, true).expect("stamp");
    }
    egress_gate::install_egress_content_gate(
        &kernel,
        classifier,
        GatePolicy::default(),
        EgressPlane::a2a_transcripts(),
    )
    .expect("gate");
    kernel
}

fn send(kernel: &Arc<Kernel>, body: &str) -> Result<serde_json::Value, String> {
    let envelope = serde_json::json!({"from": "impostor", "to": "cloud-agent", "body": body});
    send_raw(kernel, envelope.to_string().as_bytes())
}

/// Write exactly these bytes, so a test controls how the JSON is spelled.
fn send_raw(kernel: &Arc<Kernel>, bytes: &[u8]) -> Result<serde_json::Value, String> {
    let mbox = conversation_transcript_path(&conversation_id("edge-agent", "cloud-agent"));
    kernel.create_stream(&mbox, 64 * 1024).expect("stream");
    let ctx = OperationContext::new("operator", "root", false, Some("edge-agent"), false);
    kernel
        .stream_write_nowait(&mbox, bytes, &ctx)
        .map_err(|e| format!("{e:?}"))?;
    let (data, _) = kernel.stream_read_at(&mbox, 0).unwrap().unwrap();
    Ok(serde_json::from_slice(&data).expect("still valid JSON"))
}

#[test]
#[ignore = "needs a live Presidio analyzer with Chinese NER at PRESIDIO_URL"]
fn names_and_identifiers_are_both_redacted_and_the_stamp_survives() {
    let url = std::env::var("PRESIDIO_URL").expect("PRESIDIO_URL");
    let kernel = gated_kernel(&url, Duration::from_secs(10), true);
    let out = send(
        &kernel,
        &format!("客户张三住在北京市朝阳区，身份证 {ID_SPECIMEN}，请核对后回复。"),
    )
    .expect("a redactable message is delivered");
    let body = out["body"].as_str().unwrap();
    assert_eq!(out["from"], "edge-agent", "the A2A stamp must survive");
    assert!(!body.contains("张三"), "the name must not leave: {body}");
    assert!(!body.contains(ID_SPECIMEN), "the id must not leave: {body}");
    assert!(body.contains("[REDACTED:PERSON]"), "{body}");
    assert!(body.contains("[REDACTED:PRC-ID]"), "{body}");
    assert!(
        body.contains("请核对后回复"),
        "non-sensitive text kept: {body}"
    );
}

#[test]
fn an_unreachable_analyzer_refuses_the_write() {
    // The rules alone find nothing in this body; only the contextual
    // detector could. With it down, the write must fail — a missing
    // verdict is not a clean one.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let kernel = gated_kernel(
        &format!("http://127.0.0.1:{port}"),
        Duration::from_millis(500),
        true,
    );
    let res = send(&kernel, "客户张三住在北京市朝阳区。");
    assert!(res.is_err(), "the write must be refused, got {res:?}");
}

#[test]
#[ignore = "needs a live Presidio analyzer with Chinese NER at PRESIDIO_URL"]
fn a_name_hidden_behind_unicode_escapes_is_still_found() {
    // How Python's json.dumps writes by default. No stamp hook here: it
    // re-serializes the envelope and would remove the escapes before the
    // gate saw them, and a model prompt has no stamp in front of it at all.
    let url = std::env::var("PRESIDIO_URL").expect("PRESIDIO_URL");
    let kernel = gated_kernel(&url, Duration::from_secs(10), false);
    let esc = |c: char| format!("{}u{:04x}", char::from(0x5c), c as u32);
    let body = format!("客户{}{}住在北京市朝阳区", esc('张'), esc('三'));
    assert!(!body.contains('张'), "fixture must really be escaped");
    let raw = format!(r#"{{"from":"edge-agent","to":"cloud-agent","body":"{body}"}}"#);
    let out = send_raw(&kernel, raw.as_bytes()).expect("delivered");
    let text = out["body"].as_str().unwrap();
    assert!(
        !text.contains("张三"),
        "the escaped name must not leave: {text}"
    );
    assert!(text.contains("[REDACTED:PERSON]"), "{text}");
    assert_eq!(out["to"], "cloud-agent", "keys are never redacted");
}
