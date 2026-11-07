//! Subprocess hosting for the session mailbox protocol.
//!
//! Child stdio is private to this adapter. Both hosting modes expose the same
//! conversation endpoint; no public fd turn transport is created.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use a2a::session::{SessionEndpoint, SessionPayload, SessionSide, MAX_SESSION_FRAME_BYTES};
use a2a::session_io::SessionMailbox;
use dashmap::DashMap;
use kernel::core::agents::registry::{AgentDescriptor, AgentInstance, AgentRegistry, AgentState};
use kernel::kernel::{Kernel, OperationContext};
use subprocess::terminal::PreparedTerminalLaunch;
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
        let execution = match spec {
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
                let child = runtime
                    .block_on(HostedSubprocess::spawn_no_pipes(argv, spec.env, &cwd))
                    .map_err(|error| format!("launch session subprocess: {error}"))?;
                if child.os_pid().is_none() {
                    return Err("launched subprocess has no OS PID".into());
                }
                PreparedExecution::Owned(Box::new(child))
            }
            ProcessLaunch::Terminal(offer) => PreparedExecution::Terminal(
                runtime
                    .block_on(PreparedTerminalLaunch::connect(&offer))
                    .map_err(|error| format!("prepare local terminal launcher: {error}"))?,
            ),
        };
        Ok(Box::new(PreparedSubprocess {
            spawner: self.clone(),
            execution,
            runtime,
        }))
    }
}

enum PreparedExecution {
    Owned(Box<HostedSubprocess>),
    Terminal(PreparedTerminalLaunch),
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
            PreparedExecution::Terminal(_) => None,
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
    stop_input: Option<oneshot::Receiver<()>>,
    terminal_closed: Option<oneshot::Sender<ProcessExit>>,
}

struct TerminalControl {
    exit: Option<oneshot::Sender<ProcessExit>>,
    durable: Arc<parking_lot::Mutex<Option<String>>>,
    observer: StateObserver,
    native_ready: bool,
}

/// The launcher is the sole OS supervisor of a delegated child. Closing its
/// input requests stop; its EOF confirms the control owner has exited. A lost
/// launcher reports unknown status, never a fabricated successful child exit.
enum ProcessControl {
    Owned(Box<HostedSubprocess>),
    Terminal {
        closed: oneshot::Receiver<ProcessExit>,
        stop: Option<oneshot::Sender<()>>,
    },
}

impl ProcessControl {
    // Erase the two ownership backends at their lifetime boundary. The parent
    // supervisor does not carry both process-wait state machines through every
    // select branch. There is one allocation per wait, never per control frame.
    fn wait(&mut self) -> Pin<Box<dyn std::future::Future<Output = ProcessExit> + Send + '_>> {
        match self {
            Self::Owned(child) => Box::pin(child.wait()),
            Self::Terminal { closed, .. } => {
                Box::pin(async move { closed.await.unwrap_or_default() })
            }
        }
    }
    async fn stop_and_wait(&mut self) -> ProcessExit {
        match self {
            Self::Owned(child) => {
                child.kill().await;
                child.wait().await
            }
            Self::Terminal { stop, closed } => {
                if let Some(stop) = stop.take() {
                    let _ = stop.send(());
                }
                // Only delegated ownership can lose its wait receipt. Keep
                // daemon-owned Child reaping unchanged and report unknown
                // rather than claiming success when the launcher disappears.
                tokio::time::timeout(Duration::from_secs(10), closed)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default()
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
            stop_input,
            terminal_closed,
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
                    stop_input: None,
                    terminal_closed: None,
                }
            }
            PreparedExecution::Terminal(launch) => {
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
                    .map_err(|error| format!("release local terminal launch: {error}"))?;
                let (reader, writer) = stream.into_split();
                let (closed_tx, closed_rx) = oneshot::channel();
                let (stop_tx, stop_rx) = oneshot::channel();
                ProcessIo {
                    process: ProcessControl::Terminal {
                        closed: closed_rx,
                        stop: Some(stop_tx),
                    },
                    stdin: Box::new(writer),
                    stdout: Box::new(reader),
                    stderr: None,
                    stop_input: Some(stop_rx),
                    terminal_closed: Some(closed_tx),
                }
            }
        };
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (failed_tx, mut failed_rx) = mpsc::unbounded_channel::<String>();
        let stopped = Arc::new(AtomicBool::new(false));
        let durable = Arc::new(parking_lot::Mutex::new(None));
        let control = TerminalControl {
            durable: Arc::clone(&durable),
            exit: terminal_closed,
            observer: Arc::clone(&observer),
            native_ready: false,
        };
        let is_terminal = control.exit.is_some();
        self.spawn_handles.insert(
            desc.pid.clone(),
            Box::new(SubprocessHandle {
                endpoint,
                durable,
                cancel: parking_lot::Mutex::new(Some(cancel_tx)),
            }),
        );
        if !is_terminal {
            observer(AgentState::Ready, None);
        }

        let input_mailbox = Arc::clone(&mailbox);
        let input_stopped = Arc::clone(&stopped);
        let input_failed = failed_tx.clone();
        let input = runtime.spawn(async move {
            let stop = async {
                match stop_input {
                    Some(stop) => {
                        let _ = stop.await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(stop);
            while !input_stopped.load(Ordering::Acquire) {
                let reader = Arc::clone(&input_mailbox);
                let message = tokio::select! {
                    message = tokio::task::spawn_blocking(move || reader.receive(200)) => message,
                    _ = &mut stop => { let _ = stdin.shutdown().await; break; },
                };
                match message {
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
            let reason = pump_output(stdout, output_mailbox, control)
                .await
                .err()
                .unwrap_or_else(|| "session subprocess closed stdout".into());
            let _ = failed_tx.send(reason);
        });
        // Diagnostics use the same conversation, never a public fd side channel.
        let diagnostic_mailbox = Arc::clone(&mailbox);
        let diagnostics = runtime.spawn(async move {
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
                let wait = process.wait();
                tokio::pin!(wait);
                tokio::select! {
                    exit = &mut wait => (Some(exit), None),
                    _ = cancel_rx => (None, Some("session terminated".to_string())),
                    failure = failed_rx.recv() => (None, failure),
                }
            };
            let exit = match natural_exit {
                Some(exit) => exit,
                None => process.stop_and_wait().await,
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
    mut control: TerminalControl,
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
    control: &mut TerminalControl,
) -> Result<(), String> {
    let message: serde_json::Value =
        serde_json::from_slice(line).map_err(|e| format!("invalid subprocess ACP message: {e}"))?;
    if message["method"] == contracts::local_launch::TERMINAL_EXIT_METHOD {
        let sender = control
            .exit
            .take()
            .ok_or("unexpected terminal exit receipt")?;
        let exit: ProcessExit = serde_json::from_value(message["params"].clone())
            .map_err(|error| format!("invalid terminal exit receipt: {error}"))?;
        if exit.code.is_some() && exit.signal.is_some() {
            return Err("terminal exit receipt has both a code and a signal".into());
        }
        let _ = sender.send(exit);
        return Ok(());
    }
    let ready = message["method"] == contracts::local_launch::TERMINAL_READY_METHOD;
    if ready || message["method"] == contracts::local_launch::TERMINAL_SESSION_METHOD {
        if control.exit.is_none() || ready == control.native_ready {
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
    if message["method"] == contracts::local_launch::TERMINAL_STATE_METHOD {
        if !control.native_ready || control.exit.is_none() {
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
    let mailbox = Arc::clone(mailbox);
    tokio::task::spawn_blocking(move || mailbox.send(SessionPayload::Rpc { message }))
        .await
        .map_err(|e| e.to_string())?
}
