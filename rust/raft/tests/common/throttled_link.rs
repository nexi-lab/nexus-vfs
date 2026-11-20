//! A slow, droppable TCP link in front of a node's raft transport. Whoever
//! dials the link's address reaches `target` through it: bytes toward the
//! target cross at a capped rate that all connections share, as they would
//! one physical link, and every connection can be cut on demand.
//! Unlike `LossyLink`, which answers whole RPCs, this
//! link knows nothing above TCP — a slow link and a dropped connection look
//! to the transport exactly as they do in production.
//!
//! The link listens on a loopback port the OS chose; it holds the listener
//! from bind to drop, so nothing else can be handed the port.
//!
//! Included with `#[path]` by the binaries that use it.

#![allow(dead_code)] // each test binary uses a different subset

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// The link, as seen by the test that owns it.
pub struct ThrottledLink {
    address: SocketAddr,
    shared: Arc<Shared>,
    accept: tokio::task::JoinHandle<()>,
}

struct Shared {
    target: String,
    /// Bytes per second toward the target, over all connections; zero is
    /// unlimited.
    rate: AtomicU64,
    /// When the link is free again: each piece forwarded reserves its time
    /// on the link after the pieces before it, whichever connection they
    /// came from.
    free_at: tokio::sync::Mutex<tokio::time::Instant>,
    /// While set, new connections are closed as soon as they are accepted.
    down: AtomicBool,
    /// Bumped to cut every open connection.
    cut: watch::Sender<u64>,
    toward_target: AtomicU64,
    connections: AtomicU64,
}

impl ThrottledLink {
    /// Listen on a loopback port and forward to `target` (`host:port`) at
    /// `bytes_per_sec` toward it (zero: unlimited).
    pub async fn start(target: &str, bytes_per_sec: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind link");
        let address = listener.local_addr().expect("link address");
        let shared = Arc::new(Shared {
            target: target.to_owned(),
            rate: AtomicU64::new(bytes_per_sec),
            free_at: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            down: AtomicBool::new(false),
            cut: watch::channel(0).0,
            toward_target: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        });
        let accept = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                while let Ok((inbound, _)) = listener.accept().await {
                    if shared.down.load(Ordering::SeqCst) {
                        continue;
                    }
                    shared.connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(forward(inbound, Arc::clone(&shared)));
                }
            }
        });
        Self {
            address,
            shared,
            accept,
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Change the rate toward the target (zero: unlimited).
    pub fn set_rate(&self, bytes_per_sec: u64) {
        self.shared.rate.store(bytes_per_sec, Ordering::SeqCst);
    }

    /// Cut every open connection. New ones are accepted unless the link is
    /// [down](Self::set_down).
    pub fn drop_connections(&self) {
        self.shared.cut.send_modify(|generation| *generation += 1);
    }

    /// Take the link down (cutting every connection and refusing new ones)
    /// or bring it back.
    pub fn set_down(&self, down: bool) {
        self.shared.down.store(down, Ordering::SeqCst);
        if down {
            self.drop_connections();
        }
    }

    /// Bytes forwarded toward the target so far, over every connection.
    pub fn bytes_toward_target(&self) -> u64 {
        self.shared.toward_target.load(Ordering::SeqCst)
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> u64 {
        self.shared.connections.load(Ordering::SeqCst)
    }
}

impl Drop for ThrottledLink {
    fn drop(&mut self) {
        self.accept.abort();
        self.drop_connections();
    }
}

async fn forward(inbound: TcpStream, shared: Arc<Shared>) {
    let Ok(outbound) = TcpStream::connect(&shared.target).await else {
        return;
    };
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    let (mut from_dialer, mut to_dialer) = inbound.into_split();
    let (mut from_target, mut to_target) = outbound.into_split();
    let mut cut = shared.cut.subscribe();
    let toward = async {
        // Small reads keep the pacing smooth at low rates.
        let mut buffer = [0u8; 2048];
        loop {
            let read = match from_dialer.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            let rate = shared.rate.load(Ordering::SeqCst);
            if rate > 0 {
                let crossed_at = {
                    let mut free_at = shared.free_at.lock().await;
                    // Keep the byte clock across reads. Restarting at `now`
                    // charges timer rounding and scheduling overhead for every
                    // 2 KiB, making a Windows link substantially slower than
                    // its configured rate. Cap idle credit at one buffer.
                    let now = tokio::time::Instant::now();
                    let credit = Duration::from_secs_f64(buffer.len() as f64 / rate as f64);
                    let start = (*free_at).max(now - credit);
                    *free_at = start + Duration::from_secs_f64(read as f64 / rate as f64);
                    *free_at
                };
                if crossed_at > tokio::time::Instant::now() {
                    tokio::time::sleep_until(crossed_at).await;
                }
            }
            if to_target.write_all(&buffer[..read]).await.is_err() {
                return;
            }
            shared
                .toward_target
                .fetch_add(read as u64, Ordering::SeqCst);
        }
    };
    let back = async {
        let _ = tokio::io::copy(&mut from_target, &mut to_dialer).await;
    };
    // Whichever ends first — a side closing, or the cut — closes both
    // sockets by dropping them.
    tokio::select! {
        _ = toward => {}
        _ = back => {}
        _ = cut.changed() => {}
    }
}
