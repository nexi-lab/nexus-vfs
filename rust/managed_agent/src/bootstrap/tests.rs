use super::*;
use kernel::core::agents::registry::{AgentDescriptor, AgentState};
use std::collections::HashMap;
use std::io::{BufReader, Cursor, Read};

fn fixture() -> ManagedBootstrap {
    ManagedBootstrap {
        kind: BootstrapKind::V1,
        descriptor: AgentDescriptor {
            pid: "registered-runtime".into(),
            name: "original-agent".into(),
            kind: AgentKind::Managed,
            owner_id: "original-owner".into(),
            zone_id: "original-zone".into(),
            parent_pid: None,
            state: AgentState::Registered,
            exit_code: None,
            generation: 1,
            cwd: "/workspace".into(),
            root: "/".into(),
            children: vec![],
            created_at_ms: 1,
            updated_at_ms: 1,
            last_heartbeat_ms: None,
            connection_id: None,
            external_info: None,
            labels: HashMap::new(),
            repos: vec![],
            reason: None,
        },
        child_os_pid: 123,
        connection: BootstrapConnection {
            endpoint: "https://127.0.0.1:2126".into(),
            credential_directory: std::env::temp_dir().join("original-credential"),
        },
        workspace_vfs_root: "/workspace".into(),
        shell_root: None,
        authenticated_senders: true,
    }
}

fn encoded() -> Vec<u8> {
    let mut bytes = Vec::new();
    write_bootstrap(&mut bytes, &fixture()).unwrap();
    bytes
}

#[test]
fn original_descriptor_roundtrips_and_buffered_acp_is_preserved() {
    let mut bytes = encoded();
    let acp = b"{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":1}\n";
    bytes.extend_from_slice(acp);
    let mut reader = BufReader::with_capacity(bytes.len(), Cursor::new(bytes));
    let frame = read_bootstrap(&mut reader, 123).unwrap();
    assert_eq!(frame.descriptor.pid, "registered-runtime");
    assert_eq!(frame.descriptor.owner_id, "original-owner");
    assert_eq!(frame.descriptor.zone_id, "original-zone");
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, acp);
}

#[test]
fn wrong_os_pid_missing_line_and_malformed_payload_refuse() {
    assert!(read_bootstrap(&mut Cursor::new(encoded()), 124).is_err());
    for bytes in [
        vec![],
        b"{}\n".to_vec(),
        b"not-json\n".to_vec(),
        b"\xff\n".to_vec(),
    ] {
        assert!(read_bootstrap(&mut Cursor::new(bytes), 123).is_err());
    }
    let mut bytes = encoded();
    bytes.pop();
    assert_eq!(
        read_bootstrap(&mut Cursor::new(bytes), 123)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn unknown_nested_fields_kind_and_duplicate_identity_refuse() {
    let original: serde_json::Value = serde_json::from_slice(&encoded()).unwrap();
    for path in [vec![], vec!["descriptor"], vec!["connection"]] {
        let mut value = original.clone();
        let mut node = &mut value;
        for key in path {
            node = &mut node[key];
        }
        node["unexpected"] = true.into();
        let bytes = format!("{value}\n").into_bytes();
        assert!(read_bootstrap(&mut Cursor::new(bytes), 123).is_err());
    }
    let bytes = String::from_utf8(encoded())
        .unwrap()
        .replace("nexus.managed-bootstrap.v1", "nexus.managed-bootstrap.v2");
    assert!(read_bootstrap(&mut Cursor::new(bytes), 123).is_err());
    let bytes = String::from_utf8(encoded()).unwrap().replacen(
        "\"childOsPid\":123",
        "\"childOsPid\":123,\"childOsPid\":123",
        1,
    );
    assert!(read_bootstrap(&mut Cursor::new(bytes), 123).is_err());
}

#[test]
fn exact_frame_bound_accepts_lf_and_one_extra_byte_refuses_without_tail_read() {
    let original = encoded();
    let mut at_bound = original[..original.len() - 1].to_vec();
    at_bound.resize(MAX_FRAME_BYTES - 1, b' ');
    at_bound.push(b'\n');
    assert!(read_bootstrap(&mut Cursor::new(&at_bound), 123).is_ok());
    let mut oversized = at_bound.clone();
    oversized.insert(MAX_FRAME_BYTES - 1, b' ');
    let mut reader = BufReader::with_capacity(17, Cursor::new(oversized));
    assert!(read_bootstrap(&mut reader, 123).is_err());
    assert!(reader.get_ref().position() <= MAX_FRAME_BYTES as u64 + 17);
    let mut frame = fixture();
    frame
        .descriptor
        .labels
        .insert("oversized".into(), "x".repeat(MAX_FRAME_BYTES));
    let mut output = Vec::new();
    assert!(write_bootstrap(&mut output, &frame).is_err());
    assert!(output.is_empty());
}

#[test]
fn typed_reply_refuses_acp_and_unclassified_error_without_leaking_input() {
    for reply in [
        BootstrapReply::Ready,
        BootstrapReply::Error {
            message: BootstrapFailure::CredentialRefused,
        },
    ] {
        let mut bytes = Vec::new();
        write_reply(&mut bytes, &reply).unwrap();
        assert_eq!(read_reply(&mut Cursor::new(bytes)).unwrap(), reply);
    }
    let raw = b"{\"status\":\"error\",\"message\":\"secret-example\"}\n";
    let error = read_reply(&mut Cursor::new(raw)).unwrap_err();
    assert!(!error.to_string().contains("secret-example"));
    assert!(read_reply(&mut Cursor::new(b"{\"jsonrpc\":\"2.0\",\"result\":{}}\n")).is_err());
}
