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
    let (port, token, op, path) = (&a[1], &a[2], &a[3], &a[4]);
    let mut c = NexusVfsServiceClient::connect(format!("http://127.0.0.1:{port}"))
        .await
        .map_err(|e| format!("dial :{port}: {e}"))?;

    match op.as_str() {
        "readdir" => {
            let r = c
                .readdir(ReaddirRequest {
                    path: path.clone(),
                    auth_token: token.clone(),
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
                    auth_token: token.clone(),
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
                    auth_token: token.clone(),
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
                    auth_token: token.clone(),
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
            let r = c
                .stream_write_nowait(StreamWriteRequest {
                    path: path.clone(),
                    data: msg.as_bytes().to_vec(),
                    auth_token: token.clone(),
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
                    auth_token: token.clone(),
                })
                .await
                .map_err(|e| format!("stream_collect_all rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            print!("{}", String::from_utf8_lossy(&r.data));
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
