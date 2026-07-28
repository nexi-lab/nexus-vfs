//! Tiny live client for a RUNNING `nexusd-cluster` agent plane (the loopback
//! `sk-` token plane, e.g. `127.0.0.1:2129`). Not a test — a hand tool for
//! validating a real deployment's A2A mailbox round-trip end to end, the piece
//! a spawned-daemon integration test can't cover (it drives THIS founder, with
//! its real secret / mount / topology). Mirrors `tests/common::Vfs`.
//!
//! Usage:
//!   mailbox_cli <port> <sk-token> readdir   <path>
//!   mailbox_cli <port> <sk-token> stat      <path>
//!   mailbox_cli <port> <sk-token> read      <path>
//!   mailbox_cli <port> <sk-token> mkstream  <path>            # DT_STREAM (wal,memory)
//!   mailbox_cli <port> <sk-token> send      <path> <message>  # stream append
//!   mailbox_cli <port> <sk-token> collect   <path>            # stream read-all

use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, IpcPathRequest, ReadRequest, ReaddirRequest,
    SetattrRequest, StatRequest, StreamWriteRequest,
};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

const DT_STREAM: i32 = 4;

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        if let Err(e) = run().await {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    });
}

async fn run() -> Result<(), String> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        return Err("usage: mailbox_cli <port> <token> <op> <path> [message]".into());
    }
    let (port, cred, op, path) = (&a[1], &a[2], &a[3], &a[4]);

    // Two modes by the credential:
    //  * `sk-...`  → token plane, plaintext loopback (the historical form).
    //  * a bundle dir (`.../agents/{name}/` with agent.pem/agent-key.pem/ca.pem,
    //    as `auth mint --subject-type agent --cert` writes) → cert plane, mTLS.
    //    The agent signs each send and verifies each collect with its cert.
    let cert_mode = !cred.starts_with("sk-");
    let (mut c, auth, agent) = if cert_mode {
        let dir = std::path::Path::new(cred);
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("cert bundle dir has no agent name")?
            .to_string();
        let cert =
            std::fs::read(dir.join("agent.pem")).map_err(|e| format!("read agent.pem: {e}"))?;
        let key = std::fs::read(dir.join("agent-key.pem"))
            .map_err(|e| format!("read agent-key.pem: {e}"))?;
        let ca = std::fs::read(dir.join("ca.pem")).map_err(|e| format!("read ca.pem: {e}"))?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&ca))
            .identity(Identity::from_pem(&cert, &key))
            .domain_name(lib::transport_primitives::TlsConfig::CLUSTER_SERVER_NAME);
        let channel = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
            .map_err(|e| format!("endpoint: {e}"))?
            .tls_config(tls)
            .map_err(|e| format!("tls: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("mTLS dial :{port}: {e}"))?;
        // The cert authenticates; no token.
        (
            NexusVfsServiceClient::new(channel),
            String::new(),
            Some((name, cert, key, ca)),
        )
    } else {
        let c = NexusVfsServiceClient::connect(format!("http://127.0.0.1:{port}"))
            .await
            .map_err(|e| format!("dial :{port}: {e}"))?;
        (c, cred.clone(), None)
    };

    match op.as_str() {
        "readdir" => {
            let r = c
                .readdir(ReaddirRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("readdir rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            for e in r.entries {
                println!("{}", e.name);
            }
        }
        "stat" => {
            let r = c
                .stat(StatRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("stat rpc: {e}"))?
                .into_inner();
            println!("found={}", r.found);
        }
        "read" => {
            let r = c
                .read(ReadRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                    timeout_ms: 5000,
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("read rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            print!("{}", String::from_utf8_lossy(&r.content));
        }
        "mkstream" => {
            let r = c
                .setattr(SetattrRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                    entry_type: DT_STREAM,
                    io_profile: "wal,memory".into(),
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("setattr rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            println!("mkstream ok: {path}");
        }
        "send" => {
            let msg = a.get(5).ok_or("send needs a <message> arg")?;
            // A cert agent signs its message so any consumer can verify the
            // `from` against the CA; a token agent sends raw bytes.
            let data = match &agent {
                Some((name, cert, key, _ca)) => {
                    lib::transport_primitives::authorship::seal(name, msg.as_bytes(), key, cert)?
                }
                None => msg.as_bytes().to_vec(),
            };
            let r = c
                .stream_write_nowait(StreamWriteRequest {
                    path: path.clone(),
                    data,
                    auth_token: auth.clone(),
                })
                .await
                .map_err(|e| format!("stream_write rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            println!("sent offset={}", r.offset);
        }
        "collect" => {
            let r = c
                .stream_collect_all(IpcPathRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                })
                .await
                .map_err(|e| format!("stream_collect_all rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            match &agent {
                // Verify the sealed envelope against the CA and print who really
                // wrote it — the cross-trust-domain check, on the reader's side.
                Some((_name, _cert, _key, ca)) => {
                    let (from, content) = lib::transport_primitives::authorship::open(&r.data, ca)?;
                    println!("from={from} content={}", String::from_utf8_lossy(&content));
                }
                None => print!("{}", String::from_utf8_lossy(&r.data)),
            }
        }
        other => return Err(format!("unknown op '{other}'")),
    }
    Ok(())
}

fn err_if(is_error: bool, payload: &[u8]) -> Result<(), String> {
    if is_error {
        Err(format!("vfs error: {}", String::from_utf8_lossy(payload)))
    } else {
        Ok(())
    }
}
