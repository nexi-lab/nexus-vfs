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
use kernel::core::agents::registry::{AgentDescriptor, AgentInstance, AgentRegistry, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use subprocess::local_host::PreparedLocalHost;
use subprocess::{HostedSubprocess, ProcessExit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::{PreparedRawSpawn, ProcessLaunch, RawSpawn, SpawnHandle, StateObserver};

struct SubprocessHandle {
    endpoint: SessionEndpoint,
    durable: Arc<parking_lot::Mutex<Option<String>>>,
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
    fn durable_session_id(&self) -> Option<String> {
        self.durable.lock().clone()
    }
}

#[derive(Clone)]
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
    fn prepare(&self, spec: ProcessLaunch) -> Result<Box<dyn PreparedRawSpawn>, String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "subprocess hosting requires an active tokio runtime")?;
        // One executor entry for either placement. Keep resource preparation
        // inside the same future rather than instantiating block_on per backend.
        let execution = runtime.block_on(PreparedExecution::prepare(spec))?;
        Ok(Box::new(PreparedSubprocess {
            spawner: self.clone(),
            execution,
            runtime,
        }))
    }
}

enum PreparedExecution {
    Owned(Box<HostedSubprocess>),
    Local(PreparedLocalHost),
}

impl PreparedExecution {
    async fn prepare(launch: ProcessLaunch) -> Result<Self, String> {
        match launch {
            ProcessLaunch::Daemon(spec) => {
                if spec.cmd.is_empty() {
                    return Err("spawn_spec.cmd is required".into());
                }
                let mut argv = vec![spec.cmd];
                argv.extend(spec.args);
                let cwd = if spec.cwd.is_empty() {
                    PathBuf::from(".")
                } else {
                    PathBuf::from(spec.cwd)
                };
                let child = HostedSubprocess::spawn_no_pipes(argv, spec.env, &cwd)
                    .await
                    .map_err(|error| format!("launch session subprocess: {error}"))?;
                if child.os_pid().is_none() {
                    return Err("launched subprocess has no OS PID".into());
                }
                Ok(Self::Owned(Box::new(child)))
            }
            ProcessLaunch::Local(offer) => PreparedLocalHost::connect(&offer)
                .await
                .map(Self::Local)
                .map_err(|error| format!("prepare local host: {error}")),
        }
    }
}

struct PreparedSubprocess {
    spawner: KernelRawSpawn,
    execution: PreparedExecution,
    runtime: tokio::runtime::Handle,
}

impl PreparedRawSpawn for PreparedSubprocess {
    fn os_pid(&self) -> Option<u32> {
        match &self.execution {
            PreparedExecution::Owned(child) => child.os_pid(),
            PreparedExecution::Local(_) => None,
        }
    }
    fn attach(
        self: Box<Self>,
        desc: &AgentDescriptor,
        instance: AgentInstance,
        endpoint: SessionEndpoint,
        observer: StateObserver,
    ) -> Result<(), String> {
        let Self {
            spawner,
            execution,
            runtime,
            ..
        } = *self;
        spawner.attach(desc, instance, endpoint, execution, runtime, observer)
    }
}

type Reader = Box<dyn AsyncRead + Unpin + Send>;
type Writer = Box<dyn AsyncWrite + Unpin + Send>;

struct ProcessIo {
    process: ProcessControl,
    stdin: Writer,
    stdout: Reader,
    stderr: Option<Reader>,
    host_closed: Option<oneshot::Sender<()>>,
}

struct LocalControl {
    local: bool,
    durable: Arc<parking_lot::Mutex<Option<String>>>,
    observer: StateObserver,
    native_ready: bool,
}

/// An owned Child can attest its exit. A terminal-owned process can only
/// close its control connection; the shell retains OS wait/reap authority.
enum ProcessControl {
    Owned(Box<HostedSubprocess>),
    Local { closed: oneshot::Receiver<()> },
}

impl ProcessControl {
    async fn wait(&mut self) -> ProcessExit {
        match self {
            Self::Owned(child) => child.wait().await,
            // EOF/errors arrive through the shared output worker, preserving
            // its actual failure reason rather than inventing a process exit.
            Self::Local { .. } => std::future::pending().await,
        }
    }
    async fn stop_and_wait(&mut self) -> Option<ProcessExit> {
        match self {
            Self::Owned(child) => {
                child.kill().await;
                Some(child.wait().await)
            }
            Self::Local { closed } => {
                // Input has already closed. Give the host's ordinary cleanup
                // a bounded opportunity; this is not an OS exit receipt.
                let _ = tokio::time::timeout(Duration::from_secs(10), closed).await;
                None
            }
        }
    }
}

impl KernelRawSpawn {
    fn attach(
        &self,
        desc: &AgentDescriptor,
        instance: AgentInstance,
        endpoint: SessionEndpoint,
        execution: PreparedExecution,
        runtime: tokio::runtime::Handle,
        observer: StateObserver,
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
        let ProcessIo {
            mut process,
            mut stdin,
            stdout,
            stderr,
            host_closed,
        } = match execution {
            PreparedExecution::Owned(mut child) => {
                let (stdin, stdout, stderr) = child
                    .take_stdio_for_connection()
                    .map_err(|error| format!("take subprocess stdio: {error}"))?;
                ProcessIo {
                    process: ProcessControl::Owned(child),
                    stdin: Box::new(stdin),
                    stdout: Box::new(stdout),
                    stderr: Some(Box::new(stderr)),
                    host_closed: None,
                }
            }
            PreparedExecution::Local(launch) => {
                // Bootstrap carries the admitted identity, not the registry's
                // internal descriptor or OS process authority.
                let grant = serde_json::json!({"instance": {
                    "pid": desc.pid,
                    "name": desc.name,
                    "owner_id": desc.owner_id,
                    "zone_id": desc.zone_id,
                }, "session_endpoint":endpoint});
                let stream = runtime
                    .block_on(launch.start(&grant))
                    .map_err(|error| format!("release local host: {error}"))?;
                let (reader, writer) = stream.into_split();
                let (closed_tx, closed_rx) = oneshot::channel();
                ProcessIo {
                    process: ProcessControl::Local { closed: closed_rx },
                    stdin: Box::new(writer),
                    stdout: Box::new(reader),
                    stderr: None,
                    host_closed: Some(closed_tx),
                }
            }
        };
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (failed_tx, mut failed_rx) = mpsc::unbounded_channel::<String>();
        let stopped = Arc::new(AtomicBool::new(false));
        let durable = Arc::new(parking_lot::Mutex::new(None));
        let control = LocalControl {
            durable: Arc::clone(&durable),
            local: host_closed.is_some(),
            observer: Arc::clone(&observer),
            native_ready: false,
        };
        let is_local = control.local;
        self.spawn_handles.insert(
            desc.pid.clone(),
            Box::new(SubprocessHandle {
                endpoint,
                durable,
                cancel: parking_lot::Mutex::new(Some(cancel_tx)),
            }),
        );
        if !is_local {
            observer(AgentState::Ready, None);
        }

        let input_mailbox = Arc::clone(&mailbox);
        let input_stopped = Arc::clone(&stopped);
        let input_failed = failed_tx.clone();
        let input = spawn_session_task(
            &runtime,
            Box::pin(async move {
                while !input_stopped.load(Ordering::Acquire) {
                    let reader = Arc::clone(&input_mailbox);
                    let message = tokio::task::spawn_blocking(move || reader.receive(200)).await;
                    match message {
                        Ok(Ok(Some(SessionPayload::Rpc { message }))) => {
                            let mut bytes = serde_json::to_vec(&message).expect("JSON value");
                            bytes.push(b'\n');
                            if let Err(error) = stdin.write_all(&bytes).await {
                                let _ = input_failed.send(format!("session stdin failed: {error}"));
                                break;
                            }
                            if let Err(error) = stdin.flush().await {
                                let _ = input_failed
                                    .send(format!("session stdin flush failed: {error}"));
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
            }),
        );
        let output_mailbox = Arc::clone(&mailbox);
        let output = spawn_session_task(
            &runtime,
            Box::pin(async move {
                let reason = pump_output(stdout, output_mailbox, control)
                    .await
                    .err()
                    .unwrap_or_else(|| "session host control output closed".into());
                let _ = failed_tx.send(reason);
                drop(host_closed);
            }),
        );
        // Diagnostics use the same conversation, never a public fd side channel.
        let diagnostic_mailbox = Arc::clone(&mailbox);
        let diagnostics = spawn_session_task(
            &runtime,
            Box::pin(async move {
                let Some(mut stderr) = stderr else {
                    return;
                };
                let mut buffer = [0; 8192];
                while let Ok(count) = stderr.read(&mut buffer).await {
                    if count == 0 {
                        break;
                    }
                    let message = serde_json::json!({"jsonrpc":"2.0", "method":"_nexus/diagnostic",
                    "params":{"stream":"stderr","text":String::from_utf8_lossy(&buffer[..count])}});
                    if send_payload(&diagnostic_mailbox, SessionPayload::Rpc { message })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }),
        );
        let registry = Arc::clone(&self.agent_registry);
        spawn_session_task(
            &runtime,
            Box::pin(async move {
                let (natural_exit, failure) = {
                    let wait = process.wait();
                    tokio::pin!(wait);
                    tokio::select! {
                        exit = &mut wait => (Some(exit), None),
                        _ = cancel_rx => (None, Some("session terminated".to_string())),
                        failure = failed_rx.recv() => (None, failure),
                    }
                };
                stopped.store(true, Ordering::Release);
                // Dropping the sole writer closes input for both placements.
                // No further client command may be delivered after retirement.
                input.abort();
                let _ = input.await;
                let exit = match natural_exit {
                    Some(exit) => Some(exit),
                    None => process.stop_and_wait().await,
                };
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
                let reason = failure.unwrap_or_else(|| match exit {
                    Some(exit) => format!(
                        "subprocess exited: code={:?}, signal={:?}",
                        exit.code, exit.signal
                    ),
                    None => "host control closed; OS exit is unobserved".into(),
                });
                let _ = send_payload(&mailbox, SessionPayload::Closed { reason }).await;
                let _ =
                    registry.kill_instance(&instance, exit.map_or(-1, |exit| exit.as_reap_code()));
            }),
        );
        Ok(())
    }
}

/// Share executor bookkeeping for the fixed set of subprocess workers.
/// This adds one boxed future per worker at launch, never per event.
#[inline(never)]
fn spawn_session_task(
    runtime: &tokio::runtime::Handle,
    task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(task)
}

/// ACP stdio uses newline-delimited JSON. Bound partial lines as well as complete frames.
async fn pump_output<R: AsyncRead + Unpin>(
    mut reader: R,
    mailbox: Arc<SessionMailbox<Kernel>>,
    mut control: LocalControl,
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
                forward_line(&line, &mailbox, &mut control).await?;
            }
            return Ok(());
        }
        for byte in &buffer[..count] {
            if *byte == b'\n' {
                if !line.iter().all(u8::is_ascii_whitespace) {
                    forward_line(&line, &mailbox, &mut control).await?;
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
    control: &mut LocalControl,
) -> Result<(), String> {
    let message: serde_json::Value =
        serde_json::from_slice(line).map_err(|e| format!("invalid subprocess ACP message: {e}"))?;
    let ready = message["method"] == contracts::local_host::HOST_READY_METHOD;
    if ready || message["method"] == contracts::local_host::HOST_SESSION_METHOD {
        if !control.local || ready == control.native_ready {
            return Err("unexpected terminal session identity receipt".into());
        }
        let id = message["params"]["session_id"]
            .as_str()
            .filter(|id| super::valid_durable_session_id(id))
            .ok_or("terminal runtime did not report a valid durable session ID")?;
        *control.durable.lock() = Some(id.to_string());
        if ready {
            (control.observer)(AgentState::Ready, None);
            control.native_ready = true;
        }
        return Ok(());
    }
    if message["method"] == contracts::local_host::HOST_STATE_METHOD {
        if !control.native_ready || !control.local {
            return Err("terminal state requires a running native runtime".into());
        }
        let params = &message["params"];
        let state = params["state"]
            .as_str()
            .and_then(AgentState::from_str)
            .filter(|state| {
                matches!(
                    state,
                    AgentState::Ready | AgentState::Busy | AgentState::AwaitingInput
                )
            })
            .ok_or("invalid native runtime state")?;
        let reason = match &params["reason"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(reason) if reason.len() <= 128 => Some(reason.clone()),
            _ => return Err("invalid native runtime state reason".into()),
        };
        (control.observer)(state, reason);
        return Ok(());
    }
    send_payload(mailbox, SessionPayload::Rpc { message }).await
}

/// All subprocess output uses the same blocking mailbox write boundary.
async fn send_payload(
    mailbox: &Arc<SessionMailbox<Kernel>>,
    payload: SessionPayload,
) -> Result<(), String> {
    let mailbox = Arc::clone(mailbox);
    tokio::task::spawn_blocking(move || mailbox.send(payload))
        .await
        .map_err(|error| error.to_string())?
}
