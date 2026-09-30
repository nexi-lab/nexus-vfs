//! Transport error types.

/// Transport-layer error.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::result_large_err)]
pub enum TransportError {
    /// Connection failed.
    #[error("connection error: {0}")]
    Connection(String),

    /// A zone's on-disk store is held by a different process — the payload is the
    /// store path.
    ///
    /// Its own variant because callers ACT on it: it is the one open failure that
    /// says nothing is wrong with the data, only that someone else is using it, and
    /// the fix is about which process runs (stop the daemon, or declare the same
    /// thing at its boot) rather than about the data dir. Carrying the distinction in
    /// the type is what lets a CLI say that without matching on error prose.
    #[error("data dir already open by another process: {0}")]
    DataDirLocked(String),

    /// RPC call failed.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// Invalid address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Timeout.
    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    /// Server not running.
    #[error("server not running")]
    ServerNotRunning,

    /// Tonic transport error.
    #[error("tonic error: {0}")]
    Tonic(#[from] tonic::transport::Error),

    /// Tonic status error.
    #[error("status: {0}")]
    Status(#[from] tonic::Status),
}

pub type Result<T> = std::result::Result<T, TransportError>;
