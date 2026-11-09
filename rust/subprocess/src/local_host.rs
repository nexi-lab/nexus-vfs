//! One-use local control connection for an already-created host process.
//! Authentication and admission belong to ManagedAgentService; this helper
//! transfers only the registered instance grant and its control transport.
//! The host keeps its existing terminal. Neither side acquires OS-PID authority.

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

pub use contracts::local_host::LocalHostOffer;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BOOTSTRAP_BYTES: usize = 64 * 1024;
const HELLO: &[u8] = b"nexus-local-host/1\n";

async fn connect_offer(offer: &LocalHostOffer) -> io::Result<TcpStream> {
    offer.validate().map_err(invalid)?;
    timeout(CONNECT_TIMEOUT, async {
        let mut stream = TcpStream::connect(offer.endpoint()).await?;
        stream.set_nodelay(true)?;
        stream.write_all(offer.token().as_bytes()).await?;
        let mut hello = [0; HELLO.len()];
        stream.read_exact(&mut hello).await?;
        if hello != HELLO {
            return Err(invalid("unexpected local host protocol"));
        }
        Ok(stream)
    })
    .await
    .map_err(|_| timed_out("local host connection timed out"))?
}

/// The manager prepares this connection before publishing the registry entry.
/// Dropping it before `start` revokes preparation before an engine is opened.
pub struct PreparedLocalHost(TcpStream);

impl PreparedLocalHost {
    pub async fn connect(offer: &LocalHostOffer) -> io::Result<Self> {
        Ok(Self(connect_offer(offer).await?))
    }

    /// Release bootstrap only after the managed instance has been registered.
    /// The grant is host metadata, not an authentication credential. Subsequent
    /// bytes on the returned connection are private runtime control traffic.
    pub async fn start(mut self, grant: &Value) -> io::Result<TcpStream> {
        timeout(CONNECT_TIMEOUT, write_grant(&mut self.0, grant))
            .await
            .map_err(|_| timed_out("local host grant write timed out"))??;
        Ok(self.0)
    }
}

/// The host publishes `offer()` through authenticated admission and awaits
/// `accept()` concurrently. The same process then runs its native application.
pub struct LocalHost {
    listener: TcpListener,
    offer: LocalHostOffer,
    deadline: Instant,
}

impl LocalHost {
    pub async fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let offer = LocalHostOffer::new(
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

    pub fn offer(&self) -> &LocalHostOffer {
        &self.offer
    }

    async fn accept_connection(&self) -> io::Result<TcpStream> {
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
        .map_err(|_| timed_out("local host admission timed out"))?
    }

    /// Consume the one-use offer and receive the registered instance grant.
    /// The caller continues in its own process; no child, terminal forwarding,
    /// supervisor or replay buffer is created. EOF is a lost control connection,
    /// never evidence that the host's OS process has exited.
    pub async fn accept(self) -> io::Result<(TcpStream, Value)> {
        let mut stream = self.accept_connection().await?;
        drop(self);
        let grant = timeout(CONNECT_TIMEOUT, read_grant(&mut stream))
            .await
            .map_err(|_| timed_out("local host grant timed out"))??;
        Ok((stream, grant))
    }
}

async fn write_grant(stream: &mut TcpStream, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(invalid)?;
    if bytes.len() > MAX_BOOTSTRAP_BYTES {
        return Err(invalid("local host grant is too large"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

async fn read_grant(stream: &mut TcpStream) -> io::Result<Value> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_BOOTSTRAP_BYTES {
        return Err(invalid("local host grant is too large"));
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
