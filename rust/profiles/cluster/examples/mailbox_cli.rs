//! Tiny live client for a RUNNING `nexusd-cluster` agent plane (the loopback
//! `sk-` token plane, e.g. `127.0.0.1:2129`). Not a test — a hand tool for
//! validating a real deployment's A2A mailbox round-trip end to end, the piece
//! a spawned-daemon integration test can't cover (it drives THIS founder, with
//! its real secret / mount / topology). Mirrors `tests/common::Vfs`.
//!
//! Usage (a bare `<port>` means loopback; `<host:port>` reaches another node, which
//! is how a replication check reads the same path from both ends with one credential):
//!   mailbox_cli <host:port|port> <sk-token> readdir   <path>
//!   mailbox_cli <port> <sk-token> stat      <path>
//!   mailbox_cli <port> <sk-token> read      <path>
//!   mailbox_cli <port> <sk-token> mkstream  <path>            # DT_STREAM (wal,memory)
//!   mailbox_cli <port> <credential> send    <peer> <message>  # a message an AGENT reads
//!   mailbox_cli <port> <credential> send-sealed <path> <msg>  # signed; only `collect` opens it
//!   mailbox_cli <port> <sk-token> collect   <path>            # read-all + verify seal
//!   mailbox_cli <port> <sk-token> send-raw  <path> <message>  # UNSIGNED plain-JSON append
//!   mailbox_cli <port> <sk-token> collect-raw <path>          # read-all, raw bytes (no open)
//!   mailbox_cli <port> <sk-token> mkdir     <path>
//!   mailbox_cli <port> <sk-token> write     <path> <content>  # plain file write
//!   mailbox_cli <port> <sk-token> call      <method> <json>   # a service RPC
//!
//! `call` reaches the SERVICE plane rather than the file plane — the same
//! `NexusVFSService.Call` a control-plane client uses, so the agent lifecycle
//! (`start_session_v1`, `get_session_v1`, `cancel_v1`) is drivable from here. A
//! co-hosted agent has no terminal: its lifecycle is these RPCs and its input is a
//! stream append, which is why one tool covers both.
//!
//! Three ops put a message on a transcript, and what separates them is what the
//! RECEIVER can do with the frame. `send` and `send-raw` write a plain JSON
//! envelope, which is what an agent's parser reads; `send-sealed` writes a
//! signature, which only `collect` opens. So `send` is the one that reaches an
//! agent — it names the peer and indexes the conversation — `send-raw` appends
//! exactly the bytes given at a path, and `send-sealed` is for when the point is
//! the signature rather than the delivery.
//!
//! `send-raw` + `collect-raw` also show the daemon's A2A stamp hook: on a
//! `*/transcript` mailbox it rewrites a plain envelope's `from` to the
//! authenticated (possibly cross-trust-domain) `agent_id` — e.g. a foreign
//! agent whose CA was `foreign-ca register`ed reads back
//! `"from":"{trust_domain}/agent/{name}"`. That is the identity a receiver gets
//! without a signature. In cert mode point `ca.pem` at the BROKER's cluster CA
//! (to verify the server); the agent leaf may be signed by a different (foreign) CA.

use kernel::kernel::vfs_proto::{
    nexus_vfs_service_client::NexusVfsServiceClient, CallRequest, IpcPathRequest, MkdirRequest,
    ReadRequest, ReaddirRequest, SetattrRequest, StatRequest, StreamReadAtRequest,
    StreamWriteRequest, WriteRequest,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

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
        return Err("usage: mailbox_cli <host:port|port> <token> <op> <path> [message]".into());
    }
    let (target, cred, op, path) = (&a[1], &a[2], &a[3], &a[4]);

    // A bare port keeps meaning loopback; `host:port` reaches ANOTHER node.
    //
    // The whole purpose of this tool is checking a real deployment, and a
    // cross-machine one has more than one endpoint: the honest test of "did this
    // message replicate" is reading the same path from both nodes and comparing the
    // tails. With loopback baked in, that check needed a second copy of this tool on
    // the far machine — so the check that matters most was the one that was hardest
    // to run. An agent credential is cluster-wide, so the same one authenticates at
    // either endpoint.
    let authority = if target.contains(':') {
        target.clone()
    } else {
        format!("127.0.0.1:{target}")
    };

    // Two modes by the credential:
    //  * `sk-...`  → token plane, plaintext loopback (the historical form).
    //  * a credential directory, as `auth mint --subject-type agent` prints → cert
    //    plane, mTLS. Everything the dial needs comes out of the credential, which
    //    is the shape a client should copy: no filenames and no server name of its
    //    own to keep in step with the mint. The agent signs each send and verifies
    //    each collect with its cert.
    let cert_mode = !cred.starts_with("sk-");
    let (mut c, auth, agent) = if cert_mode {
        let loaded = lib::transport_primitives::AgentCredential::load(std::path::Path::new(cred))?;
        let (name, cert, key, ca) = (loaded.agent, loaded.cert_pem, loaded.key_pem, loaded.ca_pem);
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&ca))
            .identity(Identity::from_pem(&cert, &key))
            .domain_name(&loaded.server_name);
        let channel = Endpoint::from_shared(format!("https://{authority}"))
            .map_err(|e| format!("endpoint: {e}"))?
            .tls_config(tls)
            .map_err(|e| format!("tls: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("mTLS dial {authority}: {e}"))?;
        // The cert authenticates; no token.
        (
            NexusVfsServiceClient::new(channel),
            String::new(),
            Some((name, cert, key, ca)),
        )
    } else {
        let c = NexusVfsServiceClient::connect(format!("http://{authority}"))
            .await
            .map_err(|e| format!("dial {authority}: {e}"))?;
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
            // `found` alone cannot answer the question this path is usually statted for.
            // A chat-list entry is supposed to be a DT_LINK into the flat conversation,
            // and a DT_LINK that got created as a plain directory still stats as found —
            // so the two layouts were indistinguishable through this tool. entry_type
            // and link_target are what tell them apart.
            println!(
                "found={} entry_type={} is_dir={} size={} link_target={:?} zone={}",
                r.found, r.entry_type, r.is_directory, r.size, r.link_target, r.zone_id
            );
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
        // `send <peer> <message>` — a message an AGENT will actually read.
        //
        // Takes the peer, not a path, and does what the library's send does: derive
        // the pair's conversation, index it under BOTH agents' chat lists, provision
        // the transcript, then append a plain envelope. Every one of those is
        // load-bearing, and learning that cost a live duet debugging session:
        //
        //   * a SEALED frame (what this op used to write) is unreadable to an agent —
        //     its envelope parser cannot parse a seal, so the frame is skipped in
        //     silence. Use `send-sealed` when the point is the signature.
        //   * a transcript with no chat-list entry is never discovered: a receiver
        //     finds conversations by listing `/agents/<name>/conversations/`, so the
        //     message waits in a stream nobody tails.
        //   * the conversation id is a hash of the unordered pair, so a caller that
        //     works in paths has to compute blake3 by hand to say "message mac-ai".
        "send" => {
            let peer = path; // positional slot 4 is the PEER for this op
            let msg = a.get(5).ok_or("send needs a <message> arg")?;
            let me = match &agent {
                Some((name, _, _, _)) => name.clone(),
                None => {
                    return Err("send needs a credential so the pair can be named; \
                                    use send-raw <path> <message> on the token plane"
                        .into())
                }
            };
            let cid = a2a::conversation_id(&me, peer);
            let transcript = a2a::conversation_transcript_path(&cid);
            let root = format!("{}/{cid}", a2a::CONVERSATIONS_BASE);

            // Index under both sides. Body is the conversation root, which is what a
            // receiver reads to know where to tail.
            for (owner, other) in [(me.as_str(), peer.as_str()), (peer.as_str(), me.as_str())] {
                let dir = format!(
                    "{}/{owner}{}",
                    a2a::A2A_INBOX_BASE,
                    a2a::AGENT_CONVERSATIONS_SEGMENT
                );
                mkdir(&mut c, &dir, &auth).await?;
                write_file(
                    &mut c,
                    &a2a::agent_conversation_link_path(owner, other),
                    root.as_bytes(),
                    &auth,
                )
                .await?;
            }
            mkstream(&mut c, &transcript, &auth).await?;
            stream_append(
                &mut c,
                &transcript,
                // The wire SSOT: `a2a::MailboxEnvelope` is the type the stamping hook
                // and every agent's parser agree on, so the tool serialises THAT
                // rather than hand-writing its JSON. sudocode's envelope adds fields
                // (timestamp, kind) that all default, so a three-field one is valid.
                a2a::MailboxEnvelope {
                    from: me.clone(),
                    to: peer.clone(),
                    body: msg.clone(),
                }
                .to_bytes(),
                &auth,
            )
            .await?;
            println!("to {peer} via {transcript}");
        }
        "send-sealed" => {
            // The cross-org SIGNED form, at an explicit path: a receiver verifies
            // `from` against the CA itself rather than trusting the node's stamp. Its
            // own op because an AGENT cannot read it — see `send`.
            let msg = a.get(5).ok_or("send-sealed needs a <message> arg")?;
            let (name, cert, key) = match &agent {
                Some((name, cert, key, _ca)) => (name, cert, key),
                None => return Err("send-sealed needs a credential, not an sk- token".into()),
            };
            let data =
                lib::transport_primitives::authorship::seal(name, msg.as_bytes(), key, cert)?;
            stream_append(&mut c, path, data, &auth).await?;
        }

        "send-raw" => {
            // Unsigned append: plain bytes, no seal. On a `*/transcript`
            // mailbox the daemon's stamp hook rewrites `from` to the
            // authenticated agent_id — the path that surfaces classify's
            // qualified `{trust_domain}/agent/{name}` for a foreign agent.
            let msg = a.get(5).ok_or("send-raw needs a <message> arg")?;
            stream_append(&mut c, path, msg.as_bytes().to_vec(), &auth).await?;
        }
        "collect-raw" => {
            // Raw stream bytes, no envelope open — shows the stamped `from`.
            let data = stream_read_all(&mut c, path, &auth).await?;
            print!("{}", String::from_utf8_lossy(&data));
        }
        "collect" => {
            // Frame by frame, cursor-advancing — the shape a real receiver reads in,
            // and the reason this is not `stream_read_all`: one envelope per frame,
            // so collecting the whole stream and opening it ONCE fails the moment a
            // conversation holds a second message ("envelope is not JSON: trailing
            // characters"), which is every conversation that got a reply.
            let mut cursor = 0u64;
            let mut seen = 0usize;
            loop {
                let (data, next, eof) = stream_read_frame(&mut c, path, cursor, &auth).await?;
                if eof {
                    break;
                }
                seen += 1;
                // Read what the writers write — BOTH forms, in the order they occur.
                //
                // This used to branch on the credential: an agent credential meant
                // "open as a seal", which made `collect` unable to read anything `send`
                // had written. Two halves of one tool describing different formats, and
                // the reader's error ("envelope has no content") named neither.
                //
                // A plain `MailboxEnvelope` is what `send` writes and what a co-host
                // receiver consumes; a seal is what `send-sealed` writes for the
                // cross-org path and what a co-host SKIPS. A reader that handles only
                // one of them is a reader for a conversation nobody is having.
                if let Some(env) = a2a::MailboxEnvelope::from_bytes(&data) {
                    println!(
                        "[{cursor}] plain from={} to={} kind={} body={}",
                        env.from,
                        env.to,
                        // `kind` rides along as an unknown field the substrate does not
                        // police, so read it out of the JSON rather than the struct.
                        serde_json::from_slice::<serde_json::Value>(&data)
                            .ok()
                            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(String::from))
                            .unwrap_or_default(),
                        env.body,
                    );
                } else if let Some((_name, _cert, _key, ca)) = &agent {
                    // Verify the seal against the CA and print who really wrote it —
                    // the cross-trust-domain check, on the reader's side.
                    let (from, content) = lib::transport_primitives::authorship::open(&data, ca)?;
                    println!(
                        "[{cursor}] sealed from={from} content={}",
                        String::from_utf8_lossy(&content)
                    );
                } else {
                    println!("[{cursor}] raw {}", String::from_utf8_lossy(&data));
                }
                if next <= cursor {
                    break;
                }
                cursor = next;
            }
            println!("{seen} frame(s), next offset {cursor}");
        }
        "link" => {
            // A DT_LINK over the wire — the capability `Setattr` gained a link target
            // for. Here because a chat-list index is a link, and without a way to make
            // one from a client there was no way to check that the wire carries it.
            let target = a.get(5).ok_or("link needs a <target> arg")?;
            let r = c
                .setattr(SetattrRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                    entry_type: 6, // DT_LINK — 6, not 3 (that is DT_PIPE)
                    link_target: Some(target.clone()),
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("setattr rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            println!("linked {path} -> {target}");
        }
        "mkdir" => {
            let r = c
                .mkdir(MkdirRequest {
                    path: path.clone(),
                    auth_token: auth.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|e| format!("mkdir rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            println!("mkdir ok: {path}");
        }
        "write" => {
            // A plain write, for the entries a conversation needs besides its
            // transcript — chiefly an agent's chat-list entry
            // (`/agents/<name>/conversations/<peer>`), which is how a receiver
            // DISCOVERS a conversation. A transcript nobody is indexed into is a
            // message that arrives and is never looked at.
            let content = a.get(5).ok_or("write needs a <content> arg")?;
            let r = c
                .write(WriteRequest {
                    path: path.clone(),
                    content: content.as_bytes().to_vec(),
                    auth_token: auth.clone(),
                })
                .await
                .map_err(|e| format!("write rpc: {e}"))?
                .into_inner();
            err_if(r.is_error, &r.error_payload)?;
            println!("wrote {} bytes to {path}", content.len());
        }
        "call" => {
            let payload = a.get(5).map(String::as_str).unwrap_or("{}");
            let r = c
                .call(CallRequest {
                    method: path.clone(),
                    payload: payload.as_bytes().to_vec(),
                    auth_token: auth.clone(),
                })
                .await
                .map_err(|e| format!("call rpc: {e}"))?
                .into_inner();
            let body = String::from_utf8_lossy(&r.payload).into_owned();
            // A service refusal comes back IN the response, not as a transport error,
            // so a caller that only checks the RPC result reads a refusal as success.
            if r.is_error {
                return Err(format!("{} refused: {body}", path));
            }
            println!("{body}");
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

/// `mkdir`, as a helper so `send` can provision what it indexes.
async fn mkdir(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    auth: &str,
) -> Result<(), String> {
    let r = c
        .mkdir(MkdirRequest {
            path: path.to_string(),
            auth_token: auth.to_string(),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("mkdir rpc: {e}"))?
        .into_inner();
    // An existing directory is the normal case here, not a failure.
    if r.is_error && !String::from_utf8_lossy(&r.error_payload).contains("already exists") {
        return Err(format!(
            "mkdir {path}: {}",
            String::from_utf8_lossy(&r.error_payload)
        ));
    }
    Ok(())
}

/// A plain file write, as a helper for the chat-list entries `send` files.
async fn write_file(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    content: &[u8],
    auth: &str,
) -> Result<(), String> {
    let r = c
        .write(WriteRequest {
            path: path.to_string(),
            content: content.to_vec(),
            auth_token: auth.to_string(),
        })
        .await
        .map_err(|e| format!("write rpc: {e}"))?
        .into_inner();
    err_if(r.is_error, &r.error_payload)
}

/// Provision a DT_STREAM if it is not there — idempotent, like the library's.
async fn mkstream(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    auth: &str,
) -> Result<(), String> {
    let r = c
        .setattr(SetattrRequest {
            path: path.to_string(),
            auth_token: auth.to_string(),
            entry_type: DT_STREAM,
            io_profile: "wal,memory".into(),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("setattr rpc: {e}"))?
        .into_inner();
    err_if(r.is_error, &r.error_payload)
}

/// Append `data` to a DT_STREAM and print the assigned offset. Shared by all three
/// sending ops — they differ only in what `data` is (a plain envelope for `send` and
/// `send-raw`, a signature for `send-sealed`) and in who picks the path.
async fn stream_append(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    data: Vec<u8>,
    auth: &str,
) -> Result<(), String> {
    let r = c
        .stream_write_nowait(StreamWriteRequest {
            path: path.to_string(),
            data,
            auth_token: auth.to_string(),
        })
        .await
        .map_err(|e| format!("stream_write rpc: {e}"))?
        .into_inner();
    err_if(r.is_error, &r.error_payload)?;
    println!("sent offset={}", r.offset);
    Ok(())
}

/// One frame at `offset` — `(data, next_offset, eof)`.
///
/// Non-blocking: this walks what is already there rather than waiting for more, so
/// `collect` terminates on a live conversation instead of hanging at the tail.
async fn stream_read_frame(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    offset: u64,
    auth: &str,
) -> Result<(Vec<u8>, u64, bool), String> {
    let r = c
        .stream_read_at(StreamReadAtRequest {
            path: path.to_string(),
            offset,
            blocking: false,
            timeout_ms: 0,
            auth_token: auth.to_string(),
        })
        .await
        .map_err(|e| format!("stream_read_at rpc: {e}"))?
        .into_inner();
    err_if(r.is_error, &r.error_payload)?;
    Ok((r.data, r.next_offset, r.eof))
}

/// Read a whole DT_STREAM's bytes, frames concatenated — `collect-raw`'s view, for
/// when the question is what is on the wire rather than what it means.
async fn stream_read_all(
    c: &mut NexusVfsServiceClient<Channel>,
    path: &str,
    auth: &str,
) -> Result<Vec<u8>, String> {
    let r = c
        .stream_collect_all(IpcPathRequest {
            path: path.to_string(),
            auth_token: auth.to_string(),
        })
        .await
        .map_err(|e| format!("stream_collect_all rpc: {e}"))?
        .into_inner();
    err_if(r.is_error, &r.error_payload)?;
    Ok(r.data)
}
