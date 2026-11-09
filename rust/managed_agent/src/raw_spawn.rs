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
use kernel::core::agents::registry::{AgentDescriptor, AgentInstance, AgentRegistry, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use subprocess::HostedSubprocess;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::durable_session::DurableSession;
use super::{
    store_host_handle, HostedSessions, PreparedRawSpawn, RawSpawn, SpawnHandle, SpawnSpec,
};

struct SubprocessHandle {
    endpoint: SessionEndpoint,
    cancel: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    durable: Arc<DurableSession>,
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
    fn durable_session_id(&self) -> Option<&str> {
        self.durable.id()
    }
}

#[derive(Clone)]
pub(crate) struct KernelRawSpawn {
    kernel: Arc<Kernel>,
    agent_registry: Arc<AgentRegistry>,
    spawn_handles: HostedSessions,
}

impl KernelRawSpawn {
    pub(crate) fn new(
        kernel: Arc<Kernel>,
        agent_registry: Arc<AgentRegistry>,
        spawn_handles: HostedSessions,
    ) -> Self {
        Self {
            kernel,
            agent_registry,
            spawn_handles,
        }
    }
}

impl RawSpawn for KernelRawSpawn {
    fn prepare(
        &self,
        spec: SpawnSpec,
        resume_session_id: Option<String>,
    ) -> Result<Box<dyn PreparedRawSpawn>, String> {
        if spec.cmd.is_empty() {
            return Err("spawn_spec.cmd is required".into());
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "subprocess hosting requires an active tokio runtime")?;
        let mut argv = vec![spec.cmd];
        argv.extend(spec.args);
        let cwd = if spec.cwd.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(spec.cwd)
        };
        let child = runtime
            .block_on(HostedSubprocess::spawn_no_pipes(argv, spec.env, &cwd))
            .map_err(|e| format!("launch session subprocess: {e}"))?;
        let os_pid = child.os_pid().ok_or("launched subprocess has no OS PID")?;
        Ok(Box::new(PreparedSubprocess {
            spawner: self.clone(),
            child,
            runtime,
            os_pid,
            durable: Arc::new(DurableSession::new(resume_session_id)),
        }))
    }
}

struct PreparedSubprocess {
    spawner: KernelRawSpawn,
    child: HostedSubprocess,
    runtime: tokio::runtime::Handle,
    os_pid: u32,
    durable: Arc<DurableSession>,
}

impl PreparedRawSpawn for PreparedSubprocess {
    fn os_pid(&self) -> u32 {
        self.os_pid
    }
    fn attach(
        self: Box<Self>,
        desc: &AgentDescriptor,
        instance: AgentInstance,
        endpoint: SessionEndpoint,
    ) -> Result<(), String> {
        let Self {
            spawner,
            child,
            runtime,
            durable,
            ..
        } = *self;
        spawner.attach(desc, instance, endpoint, child, runtime, durable)
    }
}

impl KernelRawSpawn {
    fn attach(
        &self,
        desc: &AgentDescriptor,
        instance: AgentInstance,
        endpoint: SessionEndpoint,
        mut child: HostedSubprocess,
        runtime: tokio::runtime::Handle,
        durable: Arc<DurableSession>,
    ) -> Result<(), String> {
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
        let (mut stdin, stdout, mut stderr) = child
            .take_stdio_for_connection()
            .map_err(|e| format!("take subprocess stdio: {e}"))?;
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (failed_tx, mut failed_rx) = mpsc::unbounded_channel::<String>();
        let stopped = Arc::new(AtomicBool::new(false));
        store_host_handle(
            &self.agent_registry,
            &self.spawn_handles,
            desc.pid.clone(),
            instance.clone(),
            Box::new(SubprocessHandle {
                endpoint,
                cancel: parking_lot::Mutex::new(Some(cancel_tx)),
                durable: Arc::clone(&durable),
            }),
        )?;
        let input_mailbox = Arc::clone(&mailbox);
        let input_stopped = Arc::clone(&stopped);
        let input_failed = failed_tx.clone();
        let input_durable = Arc::clone(&durable);
        let input_registry = Arc::clone(&self.agent_registry);
        let input_instance = instance.clone();
        let input = runtime.spawn(async move {
            while !input_stopped.load(Ordering::Acquire) {
                let reader = Arc::clone(&input_mailbox);
                match tokio::task::spawn_blocking(move || reader.receive(200)).await {
                    Ok(Ok(Some(SessionPayload::Rpc { message }))) => {
                        // Receive can block; fence the original incarnation
                        // again before this request reaches its private child.
                        if !input_registry.is_current_instance(&input_instance) {
                            let _ = input_failed
                                .send("session incarnation retired before request".into());
                            break;
                        }
                        if let Err(error) = input_durable.before_request(&message) {
                            let _ = input_failed.send(error);
                            break;
                        }
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
        let output_registry = Arc::clone(&self.agent_registry);
        let output_instance = instance.clone();
        let output = runtime.spawn(async move {
            let reason = pump_output(
                stdout,
                output_mailbox,
                durable,
                output_registry,
                output_instance,
            )
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
            let _ = registry.kill_instance(&instance, exit.as_reap_code());
        });
        Ok(())
    }
}

/// ACP stdio uses newline-delimited JSON. Bound partial lines as well as complete frames.
async fn pump_output<R: AsyncRead + Unpin>(
    mut reader: R,
    mailbox: Arc<SessionMailbox<Kernel>>,
    durable: Arc<DurableSession>,
    registry: Arc<AgentRegistry>,
    instance: AgentInstance,
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
                forward_line(&line, &mailbox, &durable, &registry, &instance).await?;
            }
            return Ok(());
        }
        for byte in &buffer[..count] {
            if *byte == b'\n' {
                if !line.iter().all(u8::is_ascii_whitespace) {
                    forward_line(&line, &mailbox, &durable, &registry, &instance).await?;
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

async fn forward_line(
    line: &[u8],
    mailbox: &Arc<SessionMailbox<Kernel>>,
    durable: &DurableSession,
    registry: &AgentRegistry,
    instance: &AgentInstance,
) -> Result<(), String> {
    let message =
        serde_json::from_slice(line).map_err(|e| format!("invalid subprocess ACP message: {e}"))?;
    if !registry.is_current_instance(instance) {
        return Err("session incarnation retired before response".into());
    }
    if durable.observe_response(&message)? {
        if !registry.bind_managed_host(instance) {
            return Err("session incarnation retired before durable binding".into());
        }
        match registry.update_instance_state(instance, AgentState::Ready, None) {
            Ok(true) => {}
            _ => return Err("session incarnation retired before ready".into()),
        }
    }
    let mailbox = Arc::clone(mailbox);
    tokio::task::spawn_blocking(move || mailbox.send(SessionPayload::Rpc { message }))
        .await
        .map_err(|e| e.to_string())??;
    // This does not undo an append. A retirement during I/O closes the old
    // connection; get/list and consumers must still check its current fence.
    if !registry.is_current_instance(instance) {
        return Err("session incarnation retired during response publication".into());
    }
    Ok(())
}
