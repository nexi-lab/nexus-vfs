//! Subprocess hosting for the session mailbox protocol.
//!
//! Child stdio is private to this adapter. Both hosting modes expose the same
//! conversation endpoint; no public fd turn transport is created.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use a2a::session::{SessionEndpoint, SessionPayload, SessionSide, MAX_SESSION_FRAME_BYTES};
use a2a::session_io::SessionMailbox;
use dashmap::DashMap;
use kernel::core::agents::registry::{AgentDescriptor, AgentRegistry, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use subprocess::HostedSubprocess;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::{RawSpawn, SpawnHandle, SpawnSpec};

struct SubprocessHandle {
    endpoint: SessionEndpoint,
    cancel: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
}

impl SpawnHandle for SubprocessHandle {
    fn abort(&self) {
        if let Some(cancel) = self.cancel.lock().take() {
            let _ = cancel.send(());
        }
    }
    fn session_endpoint(&self) -> Option<&SessionEndpoint> {
        Some(&self.endpoint)
    }
}

pub(crate) struct KernelRawSpawn {
    kernel: Arc<Kernel>,
    agent_registry: Arc<AgentRegistry>,
    spawn_handles: Arc<DashMap<String, Box<dyn SpawnHandle>>>,
}

impl KernelRawSpawn {
    pub(crate) fn new(
        kernel: Arc<Kernel>,
        agent_registry: Arc<AgentRegistry>,
        spawn_handles: Arc<DashMap<String, Box<dyn SpawnHandle>>>,
    ) -> Self {
        Self {
            kernel,
            agent_registry,
            spawn_handles,
        }
    }
}

impl RawSpawn for KernelRawSpawn {
    fn spawn(
        &self,
        desc: &AgentDescriptor,
        spec: SpawnSpec,
        endpoint: SessionEndpoint,
    ) -> Result<Option<u32>, String> {
        let result = self.spawn_inner(desc, spec, endpoint);
        if result.is_err() {
            let _ = self.agent_registry.kill(&desc.pid, 127);
        }
        result
    }
}

impl KernelRawSpawn {
    fn spawn_inner(
        &self,
        desc: &AgentDescriptor,
        spec: SpawnSpec,
        endpoint: SessionEndpoint,
    ) -> Result<Option<u32>, String> {
        if spec.cmd.is_empty() {
            return Err("spawn_spec.cmd is required".into());
        }
        let ctx = OperationContext::new(
            &desc.owner_id,
            &desc.zone_id,
            false,
            Some(&desc.name),
            false,
        );
        let mailbox = Arc::new(SessionMailbox::open(
            Arc::clone(&self.kernel),
            ctx,
            endpoint.clone(),
            SessionSide::Agent,
        )?);
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "subprocess hosting requires an active tokio runtime")?;
        let mut argv = vec![spec.cmd];
        argv.extend(spec.args);
        let cwd = if spec.cwd.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(spec.cwd)
        };
        let mut child = runtime
            .block_on(HostedSubprocess::spawn_no_pipes(argv, spec.env, &cwd))
            .map_err(|e| format!("launch session subprocess: {e}"))?;
        let os_pid = child.os_pid();
        let (mut stdin, stdout, mut stderr) = child
            .take_stdio_for_connection()
            .map_err(|e| format!("take subprocess stdio: {e}"))?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (failed_tx, mut failed_rx) = mpsc::unbounded_channel::<String>();
        let stopped = Arc::new(AtomicBool::new(false));
        self.spawn_handles.insert(
            desc.pid.clone(),
            Box::new(SubprocessHandle {
                endpoint,
                cancel: parking_lot::Mutex::new(Some(cancel_tx)),
            }),
        );
        let _ = self
            .agent_registry
            .update_state(&desc.pid, AgentState::Ready);

        let input_mailbox = Arc::clone(&mailbox);
        let input_stopped = Arc::clone(&stopped);
        let input_failed = failed_tx.clone();
        let input = runtime.spawn(async move {
            while !input_stopped.load(Ordering::Acquire) {
                let reader = Arc::clone(&input_mailbox);
                match tokio::task::spawn_blocking(move || reader.receive(200)).await {
                    Ok(Ok(Some(SessionPayload::Rpc { message }))) => {
                        let mut bytes = serde_json::to_vec(&message).expect("JSON value");
                        bytes.push(b'\n');
                        if let Err(error) = stdin.write_all(&bytes).await {
                            let _ = input_failed.send(format!("session stdin failed: {error}"));
                            break;
                        }
                        if let Err(error) = stdin.flush().await {
                            let _ =
                                input_failed.send(format!("session stdin flush failed: {error}"));
                            break;
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Ok(Some(SessionPayload::Closed { reason }))) | Ok(Err(reason)) => {
                        let _ = input_failed.send(reason);
                        break;
                    }
                    Err(error) => {
                        let _ = input_failed.send(error.to_string());
                        break;
                    }
                }
            }
        });
        let output_mailbox = Arc::clone(&mailbox);
        let output = runtime.spawn(async move {
            let reason = pump_output(stdout, output_mailbox)
                .await
                .err()
                .unwrap_or_else(|| "session subprocess closed stdout".into());
            let _ = failed_tx.send(reason);
        });
        // Diagnostics use the same conversation, never a public fd side channel.
        let diagnostic_mailbox = Arc::clone(&mailbox);
        let diagnostics = runtime.spawn(async move {
            let mut buffer = [0; 8192];
            while let Ok(count) = stderr.read(&mut buffer).await {
                if count == 0 {
                    break;
                }
                let message = serde_json::json!({"jsonrpc":"2.0", "method":"_nexus/diagnostic",
                    "params":{"stream":"stderr","text":String::from_utf8_lossy(&buffer[..count])}});
                let writer = Arc::clone(&diagnostic_mailbox);
                if !matches!(
                    tokio::task::spawn_blocking(
                        move || writer.send(SessionPayload::Rpc { message })
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        });
        let registry = Arc::clone(&self.agent_registry);
        let pid = desc.pid.clone();
        runtime.spawn(async move {
            let (natural_exit, failure) = {
                let wait = child.wait();
                tokio::pin!(wait);
                tokio::select! {
                    exit = &mut wait => (Some(exit), None),
                    _ = cancel_rx => (None, Some("session terminated".to_string())),
                    failure = failed_rx.recv() => (None, failure),
                }
            };
            let exit = match natural_exit {
                Some(exit) => exit,
                None => {
                    child.kill().await;
                    child.wait().await
                }
            };
            stopped.store(true, Ordering::Release);
            input.abort();
            // Drain terminal responses before closure. Bound grandchildren
            // retaining stdout so they cannot hold session teardown forever.
            let mut output = output;
            if tokio::time::timeout(Duration::from_secs(5), &mut output)
                .await
                .is_err()
            {
                output.abort();
                let _ = output.await;
            }
            let mut diagnostics = diagnostics;
            if tokio::time::timeout(Duration::from_secs(1), &mut diagnostics)
                .await
                .is_err()
            {
                diagnostics.abort();
                let _ = diagnostics.await;
            }
            let reason = failure.unwrap_or_else(|| {
                format!(
                    "subprocess exited: code={:?}, signal={:?}",
                    exit.code, exit.signal
                )
            });
            let _ = tokio::task::spawn_blocking(move || {
                mailbox.send(SessionPayload::Closed { reason })
            })
            .await;
            let _ = registry.kill(&pid, exit.as_reap_code());
        });
        Ok(os_pid)
    }
}

/// ACP stdio uses newline-delimited JSON. Bound partial lines as well as complete frames.
async fn pump_output<R: AsyncRead + Unpin>(
    mut reader: R,
    mailbox: Arc<SessionMailbox<Kernel>>,
) -> Result<(), String> {
    let mut buffer = [0; 8192];
    let mut line = Vec::new();
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|e| format!("session stdout failed: {e}"))?;
        if count == 0 {
            if !line.is_empty() {
                forward_line(&line, &mailbox).await?;
            }
            return Ok(());
        }
        for byte in &buffer[..count] {
            if *byte == b'\n' {
                if !line.iter().all(u8::is_ascii_whitespace) {
                    forward_line(&line, &mailbox).await?;
                }
                line.clear();
            } else {
                line.push(*byte);
                if line.len() > MAX_SESSION_FRAME_BYTES {
                    return Err("subprocess ACP frame exceeds the size limit".into());
                }
            }
        }
    }
}

async fn forward_line(line: &[u8], mailbox: &Arc<SessionMailbox<Kernel>>) -> Result<(), String> {
    let message =
        serde_json::from_slice(line).map_err(|e| format!("invalid subprocess ACP message: {e}"))?;
    let mailbox = Arc::clone(mailbox);
    tokio::task::spawn_blocking(move || mailbox.send(SessionPayload::Rpc { message }))
        .await
        .map_err(|e| e.to_string())?
}
