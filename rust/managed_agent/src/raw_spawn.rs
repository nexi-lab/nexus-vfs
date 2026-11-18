//! Subprocess hosting for the session mailbox protocol.
//!
//! Child stdio is private to this adapter. Both hosting modes expose the same
//! conversation endpoint; no public fd turn transport is created.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::session_transport::{HostSessionIo, SessionTransport};
use a2a::session::{SessionEndpoint, SessionPayload, MAX_SESSION_FRAME_BYTES};
use kernel::core::agents::registry::{AgentDescriptor, AgentInstance, AgentRegistry, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use subprocess::local_host::PreparedLocalHost;
use subprocess::{HostedSubprocess, ProcessExit};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::durable_session::DurableSession;
use super::{
    store_host_handle, HostedSessions, PreparedRawSpawn, ProcessLaunch, RawSpawn, SpawnHandle,
    StateObserver,
};

struct SubprocessHandle {
    transport: SessionTransport,
    durable: Arc<SessionBinding>,
    cancel: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
}

impl SpawnHandle for SubprocessHandle {
    fn abort(&self) {
        if let Some(cancel) = self.cancel.lock().take() {
            let _ = cancel.send(());
        }
    }
    fn session_endpoint(&self) -> Option<&SessionEndpoint> {
        Some(self.transport.endpoint())
    }
    fn durable_session_id(&self) -> Option<String> {
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
        spec: ProcessLaunch,
        resume_session_id: Option<String>,
    ) -> Result<Box<dyn PreparedRawSpawn>, String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "subprocess hosting requires an active tokio runtime")?;
        // One executor entry for either placement. Keep resource preparation
        // inside the same future rather than instantiating block_on per backend.
        let durable = Arc::new(match &spec {
            ProcessLaunch::Daemon(_) => SessionBinding::Acp(DurableSession::new(resume_session_id)),
            ProcessLaunch::Local(_) => SessionBinding::Native(parking_lot::Mutex::new(None)),
        });
        let execution = runtime.block_on(PreparedExecution::prepare(spec))?;
        Ok(Box::new(PreparedSubprocess {
            spawner: self.clone(),
            execution,
            runtime,
            durable,
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
    durable: Arc<SessionBinding>,
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
        transport: SessionTransport,
        observer: StateObserver,
    ) -> Result<(), String> {
        let Self {
            spawner,
            execution,
            runtime,
            durable,
        } = *self;
        spawner.attach(
            desc,
            instance,
            transport,
            Attachment {
                execution,
                runtime,
                durable,
                observer,
            },
        )
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

// A raw ACP child establishes its one transcript by a correlated response.
// A native host has already opened its engine and reports later /new switches.
// These have different establishment rules but share one hosted handle and fence.
enum SessionBinding {
    Acp(DurableSession),
    Native(parking_lot::Mutex<Option<String>>),
}

impl SessionBinding {
    fn id(&self) -> Option<String> {
        match self {
            Self::Acp(binding) => binding.id().map(str::to_owned),
            Self::Native(id) => id.lock().clone(),
        }
    }

    fn before_request(&self, message: &serde_json::Value) -> Result<(), String> {
        match self {
            Self::Acp(binding) => binding.before_request(message),
            // The existing native engine owns session selection and checks
            // incoming ACP session IDs; the service does not open another one.
            Self::Native(_) => Ok(()),
        }
    }

    fn observe_response(&self, message: &serde_json::Value) -> Result<bool, String> {
        match self {
            Self::Acp(binding) => binding.observe_response(message),
            Self::Native(_) => Ok(false),
        }
    }

    fn native_session(&self, ready: bool, id: &str) -> Result<(), String> {
        let Self::Native(current) = self else {
            return Err("unexpected terminal session identity receipt".into());
        };
        let mut current = current.lock();
        if ready == current.is_some() {
            return Err("unexpected terminal session identity receipt".into());
        }
        *current = Some(id.to_owned());
        Ok(())
    }

    fn native_ready(&self) -> bool {
        matches!(self, Self::Native(id) if id.lock().is_some())
    }
}

struct Attachment {
    execution: PreparedExecution,
    runtime: tokio::runtime::Handle,
    durable: Arc<SessionBinding>,
    observer: StateObserver,
}

struct HostControl {
    durable: Arc<SessionBinding>,
    observer: StateObserver,
    registry: Arc<AgentRegistry>,
    instance: AgentInstance,
}

impl HostControl {
    fn check_current(&self) -> Result<(), String> {
        if !self.registry.is_current_instance(&self.instance) {
            return Err("session incarnation retired before response".into());
        }
        Ok(())
    }

    fn bind_ready(&self) -> Result<(), String> {
        if !self.registry.bind_managed_host(&self.instance) {
            return Err("session incarnation retired before durable binding".into());
        }
        match self
            .registry
            .update_instance_state(&self.instance, AgentState::Ready, None)
        {
            Ok(true) => Ok(()),
            _ => Err("session incarnation retired before ready".into()),
        }
    }
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
        transport: SessionTransport,
        attachment: Attachment,
    ) -> Result<(), String> {
        let Attachment {
            execution,
            runtime,
            durable,
            observer,
        } = attachment;
        let ctx = OperationContext::new(
            &desc.owner_id,
            &desc.zone_id,
            false,
            Some(&desc.name),
            false,
        );
        let mailbox = Arc::new(transport.open(Arc::clone(&self.kernel), ctx)?);
        let endpoint = transport.endpoint();
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
        let is_local = host_closed.is_some();
        let control = HostControl {
            durable: Arc::clone(&durable),
            observer,
            registry: Arc::clone(&self.agent_registry),
            instance: instance.clone(),
        };
        store_host_handle(
            &self.agent_registry,
            &self.spawn_handles,
            desc.pid.clone(),
            instance.clone(),
            Box::new(SubprocessHandle {
                transport: transport.clone(),
                durable: Arc::clone(&durable),
                cancel: parking_lot::Mutex::new(Some(cancel_tx)),
            }),
            None,
            Some(transport),
        )?;

        let input_mailbox = Arc::clone(&mailbox);
        let input_stopped = Arc::clone(&stopped);
        let input_failed = failed_tx.clone();
        let input_registry = Arc::clone(&self.agent_registry);
        let input_instance = instance.clone();
        let input = spawn_session_task(
            &runtime,
            Box::pin(async move {
                while !input_stopped.load(Ordering::Acquire) {
                    let reader = Arc::clone(&input_mailbox);
                    let message = tokio::task::spawn_blocking(move || reader.receive(200)).await;
                    match message {
                        Ok(Ok(Some(SessionPayload::Rpc { message }))) => {
                            // Receiving can block. Recheck the original host before
                            // delivering a controller command to its private transport.
                            if !input_registry.is_current_instance(&input_instance) {
                                let _ = input_failed
                                    .send("session incarnation retired before request".into());
                                break;
                            }
                            if let Err(error) = durable.before_request(&message) {
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
                    .unwrap_or_else(|| {
                        if is_local {
                            "local host control output closed; OS exit is unobserved"
                        } else {
                            "subprocess closed stdout"
                        }
                        .into()
                    });
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
    mailbox: Arc<HostSessionIo<Kernel>>,
    control: HostControl,
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
                forward_line(&line, &mailbox, &control).await?;
            }
            return Ok(());
        }
        for byte in &buffer[..count] {
            if *byte == b'\n' {
                if !line.iter().all(u8::is_ascii_whitespace) {
                    forward_line(&line, &mailbox, &control).await?;
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
    mailbox: &Arc<HostSessionIo<Kernel>>,
    control: &HostControl,
) -> Result<(), String> {
    let message: serde_json::Value =
        serde_json::from_slice(line).map_err(|e| format!("invalid subprocess ACP message: {e}"))?;
    control.check_current()?;
    let ready = message["method"] == contracts::local_host::HOST_READY_METHOD;
    if ready || message["method"] == contracts::local_host::HOST_SESSION_METHOD {
        let id = message["params"]["session_id"]
            .as_str()
            .filter(|id| super::valid_durable_id(id))
            .ok_or("terminal runtime did not report a valid durable session ID")?;
        control.durable.native_session(ready, id)?;
        if ready {
            control.bind_ready()?;
        }
        return Ok(());
    }
    if message["method"] == contracts::local_host::HOST_STATE_METHOD {
        if !control.durable.native_ready() {
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
    if control.durable.observe_response(&message)? {
        control.bind_ready()?;
    }
    send_payload(mailbox, SessionPayload::Rpc { message }).await?;
    // A retirement during I/O closes the original connection. It does not
    // authorize a replacement host or undo a completed durable append.
    control.check_current()
}

/// All subprocess output uses the same blocking mailbox write boundary.
async fn send_payload(
    mailbox: &Arc<HostSessionIo<Kernel>>,
    payload: SessionPayload,
) -> Result<(), String> {
    if mailbox.is_live() {
        return mailbox.send(payload);
    }
    let mailbox = Arc::clone(mailbox);
    tokio::task::spawn_blocking(move || mailbox.send(payload))
        .await
        .map_err(|error| error.to_string())?
}
