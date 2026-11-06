//! A local terminal launcher delegates admission to a manager while retaining
//! the OS child handle. Only control bytes cross the connection; the child's
//! stdio is inherited directly from the original terminal.
//!
//! An offer is a one-use capability, not a process credential. A manager must
//! authenticate and authorize the caller separately. Reported child PIDs must
//! never be used to mint credentials or signal a process in the manager.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

pub use contracts::local_launch::LaunchOffer;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

use crate::{HostedSubprocess, ProcessExit};

/// Private child bootstrap. It carries no provider or Node credentials.
pub const BOOTSTRAP_ENV: &str = "NEXUS_TERMINAL_BOOTSTRAP";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
const HELLO: &[u8] = b"nexus-terminal-launch/1\n";

async fn connect_offer(offer: &LaunchOffer) -> io::Result<TcpStream> {
    offer.validate().map_err(invalid)?;
    timeout(CONNECT_TIMEOUT, async {
        let mut stream = TcpStream::connect(offer.endpoint()).await?;
        stream.set_nodelay(true)?;
        stream.write_all(offer.token().as_bytes()).await?;
        let mut hello = [0; HELLO.len()];
        stream.read_exact(&mut hello).await?;
        if hello != HELLO {
            return Err(invalid("unexpected terminal launch protocol"));
        }
        Ok(stream)
    })
    .await
    .map_err(|_| timed_out("terminal launch connection timed out"))?
}

/// The manager prepares this connection before publishing the registry entry.
/// Dropping it before `start` revokes the launch without creating a child.
pub struct PreparedTerminalLaunch(TcpStream);

impl PreparedTerminalLaunch {
    pub async fn connect(offer: &LaunchOffer) -> io::Result<Self> {
        Ok(Self(connect_offer(offer).await?))
    }

    /// Release bootstrap only after the managed instance has been registered.
    /// The grant is host metadata, not an authentication credential. Subsequent
    /// bytes on the returned connection are private runtime control traffic.
    pub async fn start(mut self, grant: &Value) -> io::Result<TcpStream> {
        timeout(CONNECT_TIMEOUT, write_grant(&mut self.0, grant))
            .await
            .map_err(|_| timed_out("terminal launch grant write timed out"))??;
        Ok(self.0)
    }
}

/// Created in the terminal's process tree. The owner publishes `offer()` to the
/// manager, then runs this launcher concurrently with that admission request.
/// There is no long-lived launch service, independent registry or replay cache.
pub struct TerminalLauncher {
    listener: TcpListener,
    offer: LaunchOffer,
    deadline: Instant,
}

impl TerminalLauncher {
    pub async fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let offer = LaunchOffer::new(
            listener.local_addr()?,
            uuid::Uuid::new_v4().simple().to_string(),
        )
        .map_err(invalid)?;
        Ok(Self {
            listener,
            offer,
            deadline: Instant::now() + PREPARE_TIMEOUT,
        })
    }

    pub fn offer(&self) -> &LaunchOffer {
        &self.offer
    }

    async fn accept(&self) -> io::Result<TcpStream> {
        tokio::time::timeout_at(self.deadline, async {
            loop {
                let (mut stream, _) = self.listener.accept().await?;
                let mut token = [0; 32];
                let read = timeout(CONNECT_TIMEOUT, stream.read_exact(&mut token)).await;
                if !matches!(read, Ok(Ok(_))) || token != self.offer.token().as_bytes() {
                    continue;
                }
                stream.set_nodelay(true)?;
                stream.write_all(HELLO).await?;
                return Ok(stream);
            }
        })
        .await
        .map_err(|_| timed_out("terminal launch admission timed out"))?
    }

    /// Run the locally selected executable only after admission. The manager
    /// cannot replace argv/env/cwd through the grant. Cancellation closes the
    /// runtime control stream first, allowing terminal restoration and session
    /// persistence, then kills and reaps this exact child if grace expires.
    pub async fn run(
        self,
        argv: Vec<String>,
        environment: HashMap<String, String>,
        cwd: &Path,
    ) -> io::Result<ProcessExit> {
        self.run_with_shutdown(argv, environment, cwd, std::future::pending())
            .await
    }

    /// Admission can fail after the manager connects. The local caller can
    /// revoke the offer or stop an already-created child without dropping its
    /// wait/reap future. A successful admission leaves this future pending.
    pub async fn run_with_shutdown(
        self,
        argv: Vec<String>,
        mut environment: HashMap<String, String>,
        cwd: &Path,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> io::Result<ProcessExit> {
        tokio::pin!(shutdown);
        let mut manager = tokio::select! {
            result = self.accept() => result?,
            () = &mut shutdown => return Err(interrupted()),
        };
        // Revoke the listener as soon as one authorized manager attaches.
        drop(self);
        let grant = tokio::select! {
            result = timeout(CONNECT_TIMEOUT, read_grant(&mut manager)) =>
                result.map_err(|_| timed_out("terminal launch grant timed out"))??,
            () = &mut shutdown => return Err(interrupted()),
        };
        // This second capability is private to the child; it never enters the
        // managed request or public session endpoint.
        let bootstrap = Self::bind().await?;
        environment.insert(
            BOOTSTRAP_ENV.into(),
            serde_json::to_string(bootstrap.offer()).map_err(invalid)?,
        );
        let mut interrupt = Interrupt::new()?;
        let mut child = HostedSubprocess::spawn_in_terminal(argv, environment, cwd)
            .await
            .map_err(io::Error::other)?;
        let mut pending = Vec::new();
        let connection = {
            let accepted = bootstrap.accept();
            tokio::pin!(accepted);
            let mut buffer = [0; 4096];
            loop {
                tokio::select! {
                    result = &mut accepted => break result,
                    exit = child.wait() => return Err(io::Error::other(format!("terminal child exited before bootstrap: {exit:?}"))),
                    () = &mut shutdown => break Err(interrupted()),
                    result = manager.read(&mut buffer) => match result {
                        Ok(0) => break Err(interrupted()),
                        Ok(count) if pending.len() + count <= MAX_BOOTSTRAP_BYTES => pending.extend_from_slice(&buffer[..count]),
                        Ok(_) => break Err(invalid("terminal control exceeded bootstrap buffer")),
                        Err(error) => break Err(error),
                    },
                }
            }
        };
        drop(bootstrap);
        let mut runtime = match connection {
            Ok(stream) => stream,
            Err(error) => {
                child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        if let Err(error) = timeout(CONNECT_TIMEOUT, async {
            write_grant(&mut runtime, &grant).await?;
            runtime.write_all(&pending).await
        })
        .await
        .map_err(|_| timed_out("native runtime grant write timed out"))
        .and_then(|result| result)
        {
            child.kill().await;
            let _ = child.wait().await;
            return Err(error);
        }
        // The terminal sends Ctrl-C to the whole foreground group. Consume it
        // in the launcher; the native child receives it directly exactly once.
        // The signal listener remains registered throughout child ownership.
        let natural_exit = {
            let (mut manager_in, mut manager_out) = manager.split();
            let (mut runtime_in, mut runtime_out) = runtime.split();
            let input = tokio::io::copy(&mut manager_in, &mut runtime_out);
            let output = tokio::io::copy(&mut runtime_in, &mut manager_out);
            tokio::pin!(input, output);
            loop {
                tokio::select! {
                    exit = child.wait() => {
                        // Preserve final control replies already written by
                        // the child before appending the launcher's receipt.
                        let _ = timeout(Duration::from_secs(1), &mut output).await;
                        break Some(exit);
                    },
                    _ = &mut input => break None,
                    _ = &mut output => break None,
                    () = &mut shutdown => break None,
                    signal = interrupt.recv() => {
                        if signal.is_none() { break None; }
                    }
                }
            }
        };
        // Release the control socket even if the manager still holds its half.
        drop(runtime);
        let exit = match natural_exit {
            Some(exit) => exit,
            None => match timeout(STOP_TIMEOUT, child.wait()).await {
                Ok(exit) => exit,
                Err(_) => {
                    child.kill().await;
                    child.wait().await
                }
            },
        };
        let mut receipt = serde_json::to_vec(&serde_json::json!({
            "jsonrpc":"2.0", "method":contracts::local_launch::TERMINAL_EXIT_METHOD,
            "params":exit,
        }))
        .map_err(invalid)?;
        receipt.push(b'\n');
        // Losing a receipt does not change the child's actual exit status.
        let _ = timeout(Duration::from_secs(1), manager.write_all(&receipt)).await;
        Ok(exit)
    }
}

fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "terminal launch was revoked")
}

/// Install before spawning, so a Ctrl-C during bootstrap cannot kill the
/// launcher while leaving the child behind. Native children still receive the
/// terminal's signal directly; neither forwarding nor duplicate cancellation.
#[cfg(unix)]
struct Interrupt(tokio::signal::unix::Signal);
#[cfg(windows)]
struct Interrupt(tokio::signal::windows::CtrlC);

impl Interrupt {
    fn new() -> io::Result<Self> {
        #[cfg(unix)]
        {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).map(Self)
        }
        #[cfg(windows)]
        {
            tokio::signal::windows::ctrl_c().map(Self)
        }
    }
    async fn recv(&mut self) -> Option<()> {
        self.0.recv().await
    }
}

/// Native runtimes connect here before opening an engine or taking over stdin.
/// After receiving the grant, serve the shared ACP handler on the returned
/// stream; EOF means that the managed host is being stopped.
pub async fn connect_bootstrap(offer: LaunchOffer) -> io::Result<(TcpStream, Value)> {
    let mut stream = connect_offer(&offer).await?;
    let grant = timeout(CONNECT_TIMEOUT, read_grant(&mut stream))
        .await
        .map_err(|_| timed_out("native runtime bootstrap timed out"))??;
    Ok((stream, grant))
}

async fn write_grant(stream: &mut TcpStream, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(invalid)?;
    if bytes.len() > MAX_BOOTSTRAP_BYTES {
        return Err(invalid("terminal launch grant is too large"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

async fn read_grant(stream: &mut TcpStream) -> io::Result<Value> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_BOOTSTRAP_BYTES {
        return Err(invalid("terminal launch grant is too large"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(invalid)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn timed_out(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}
