//! Tonic requests and response bodies bound to their original local credentials.

use std::pin::Pin;
use std::task::{Context, Poll};

use http_body::{Body, Frame};
use tonic::body::Body as TonicBody;
use tonic::codegen::{http, BoxFuture, Bytes, Service, StdError};
use tonic::transport::Channel;

use super::{SharedTlsConfig, TlsSnapshot};

#[derive(Clone, Debug)]
struct CredentialGuard {
    source: SharedTlsConfig,
    snapshot: TlsSnapshot,
}

impl CredentialGuard {
    fn check(&self) -> Result<(), tonic::Status> {
        if self.source.is_current(&self.snapshot) {
            Ok(())
        } else {
            Err(tonic::Status::unauthenticated(
                "local credential installation is no longer current",
            ))
        }
    }

    fn body(&self, inner: TonicBody) -> TonicBody {
        TonicBody::new(CredentialBody {
            inner,
            guard: self.clone(),
            finished: false,
        })
    }
}

/// A connection whose requests retain the installation that admitted its dial.
///
/// Replacing or withdrawing that installation fences retained clones, buffered
/// request bodies and response frames. The credential owner supplies the source;
/// this transport does not mint or refresh credentials.
#[derive(Clone, Debug)]
pub struct CredentialChannel {
    channel: Channel,
    guard: CredentialGuard,
}

impl CredentialChannel {
    /// Bind a connection established with `snapshot` by the owning dialer.
    pub fn new(channel: Channel, source: SharedTlsConfig, snapshot: TlsSnapshot) -> Self {
        Self {
            channel,
            guard: CredentialGuard { source, snapshot },
        }
    }
}

impl Service<http::Request<TonicBody>> for CredentialChannel {
    type Response = http::Response<TonicBody>;
    type Error = StdError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Err(error) = self.guard.check() {
            return Poll::Ready(Err(error.into()));
        }
        self.channel.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: http::Request<TonicBody>) -> Self::Future {
        let guard = self.guard.clone();
        let pending = guard.source.with_current(&guard.snapshot, || {
            self.channel.call(request.map(|body| guard.body(body)))
        });
        Box::pin(async move {
            let pending = pending.ok_or_else(|| {
                StdError::from(tonic::Status::unauthenticated(
                    "local credential installation changed before request submission",
                ))
            })?;
            let response = pending.await?;
            guard.check()?;
            Ok(response.map(|body| guard.body(body)))
        })
    }
}

struct CredentialBody {
    inner: TonicBody,
    guard: CredentialGuard,
    finished: bool,
}

impl Body for CredentialBody {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if let Err(error) = self.guard.check() {
            self.finished = true;
            return Poll::Ready(Some(Err(error)));
        }
        // The inner body may execute application code, so never poll it while
        // holding the credential lock. Recheck before exposing its result.
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if let Err(error) = self.guard.check() {
            self.finished = true;
            return Poll::Ready(Some(Err(error)));
        }
        if matches!(result, Poll::Ready(None | Some(Err(_)))) {
            self.finished = true;
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        // Keep the guard present even for empty inner bodies: tonic otherwise
        // elides this wrapper during construction and can skip its final check.
        self.finished
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests;
