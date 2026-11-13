//! Listener and handshake ownership for a TLS connection stream.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_stream::Stream;

const ACCEPT_BUFFER: usize = 1024;
type Connection = io::Result<TlsStream<TcpStream>>;

/// The consumer owns the listening socket and every unfinished handshake.
pub(super) fn incoming<I: Send + 'static>(
    listener: TcpListener,
    config: impl Fn() -> Option<(Arc<ServerConfig>, I)> + Send + 'static,
    is_current: impl Fn(&I) -> bool + Send + Sync + 'static,
) -> impl Stream<Item = Connection> {
    Incoming {
        listener,
        config: Box::new(config),
        is_current: Arc::new(is_current),
        handshakes: JoinSet::new(),
    }
}

struct Incoming<I> {
    listener: TcpListener,
    config: Box<dyn Fn() -> Option<(Arc<ServerConfig>, I)> + Send>,
    is_current: Arc<dyn Fn(&I) -> bool + Send + Sync>,
    handshakes: JoinSet<Connection>,
}

impl<I: Send + 'static> Stream for Incoming<I> {
    type Item = Connection;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        for _ in 0..ACCEPT_BUFFER {
            match this.handshakes.poll_join_next(cx) {
                Poll::Ready(Some(Ok(connection))) => return Poll::Ready(Some(connection)),
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Some(Err(io::Error::other(error))));
                }
                Poll::Ready(None) | Poll::Pending => {}
            }
            if this.handshakes.len() >= ACCEPT_BUFFER {
                return Poll::Pending;
            }
            let tcp = match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => stream,
                Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error))),
                Poll::Pending => return Poll::Pending,
            };
            let Some((config, installation)) = (this.config)() else {
                drop(tcp);
                continue;
            };
            let is_current = Arc::clone(&this.is_current);
            this.handshakes.spawn(async move {
                let accepted = TlsAcceptor::from(config).accept(tcp).await?;
                if !is_current(&installation) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "TLS credentials changed while accepting connection",
                    ));
                }
                Ok(accepted)
            });
        }
        // Bound work per poll even while peers repeatedly fail admission.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
