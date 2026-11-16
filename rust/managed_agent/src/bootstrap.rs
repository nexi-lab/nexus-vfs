//! One private host/child prelude before ACP, without storage or network I/O.
//!
//! The host must obtain the descriptor, child OS PID and published credential
//! directory from its authenticated current-instance custody. Decoding this
//! frame does not authenticate those values or grant Session storage access.
//! Never accept it through the public mailbox or forward a controller's key.
//! The child loads the original credential bundle, verifies its agent identity,
//! authenticates the connection, then constructs its single managed context.

use kernel::core::agents::registry::{AgentDescriptor, AgentKind};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

/// Includes the terminating LF; no caller may raise this bound for v1.
pub const MAX_FRAME_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum BootstrapKind {
    #[serde(rename = "nexus.managed-bootstrap.v1")]
    V1,
}

/// Refers to the existing published AgentCredential bundle, not key bytes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapConnection {
    pub endpoint: String,
    pub credential_directory: PathBuf,
}

/// AgentDescriptor is the original kernel type, including its registry PID.
/// `child_os_pid` is deliberately separate from that registry identity.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedBootstrap {
    pub kind: BootstrapKind,
    pub descriptor: AgentDescriptor,
    pub child_os_pid: u32,
    pub connection: BootstrapConnection,
    pub workspace_vfs_root: String,
    pub shell_root: Option<PathBuf>,
    pub authenticated_senders: bool,
}

impl ManagedBootstrap {
    /// Pure validation, before credential loading or any managed-context probe.
    /// It checks framing/targeting only; the real server enforces credentials
    /// and grants. An exact SID still needs Q1's authorization before its store.
    pub fn validate_for_child(&self, actual_os_pid: u32) -> io::Result<()> {
        if self.child_os_pid == 0 || self.child_os_pid != actual_os_pid {
            return Err(invalid("managed bootstrap child OS PID mismatch"));
        }
        if self.descriptor.kind != AgentKind::Managed || self.descriptor.state.is_terminal() {
            return Err(invalid(
                "managed bootstrap requires a live managed descriptor",
            ));
        }
        for value in [
            &self.descriptor.pid,
            &self.descriptor.name,
            &self.descriptor.owner_id,
            &self.descriptor.zone_id,
            &self.connection.endpoint,
        ] {
            if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
                return Err(invalid(
                    "managed bootstrap has an invalid identity or endpoint",
                ));
            }
        }
        if !self.connection.credential_directory.is_absolute()
            || self
                .shell_root
                .as_ref()
                .is_some_and(|root| !root.is_absolute())
            || !self.workspace_vfs_root.starts_with('/')
            || self.workspace_vfs_root.chars().any(char::is_control)
        {
            return Err(invalid("managed bootstrap has an invalid root"));
        }
        Ok(())
    }
}

/// Public failure categories only: never echo credentials, raw prelude bytes,
/// or unredacted underlying connection errors onto the private protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapFailure {
    InvalidPrelude,
    CredentialRefused,
    ConnectionRefused,
    ContextRefused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapReply {
    Ready,
    Error { message: BootstrapFailure },
}

/// Preserve this exact reader for the subsequent ACP stream. Any ACP bytes
/// already buffered after LF remain in it; do not recreate a reader over stdin.
pub fn read_bootstrap(
    reader: &mut impl BufRead,
    actual_os_pid: u32,
) -> io::Result<ManagedBootstrap> {
    let frame: ManagedBootstrap = read_frame(reader)?;
    frame.validate_for_child(actual_os_pid)?;
    Ok(frame)
}

pub fn write_bootstrap(writer: &mut impl Write, frame: &ManagedBootstrap) -> io::Result<()> {
    frame.validate_for_child(frame.child_os_pid)?;
    write_frame(writer, frame)
}

pub fn read_reply(reader: &mut impl BufRead) -> io::Result<BootstrapReply> {
    read_frame(reader)
}

pub fn write_reply(writer: &mut impl Write, reply: &BootstrapReply) -> io::Result<()> {
    write_frame(writer, reply)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_frame<T: DeserializeOwned>(reader: &mut impl BufRead) -> io::Result<T> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "managed bootstrap missing complete line",
            ));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let used = newline.map_or(available.len(), |index| index + 1);
        if used > MAX_FRAME_BYTES - line.len() {
            return Err(invalid("managed bootstrap exceeds v1 frame bound"));
        }
        line.extend_from_slice(&available[..used]);
        reader.consume(used);
        if newline.is_some() {
            return serde_json::from_slice(&line)
                .map_err(|_| invalid("invalid managed bootstrap JSON"));
        }
        if line.len() == MAX_FRAME_BYTES {
            return Err(invalid("managed bootstrap exceeds v1 frame bound"));
        }
    }
}

fn write_frame(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    let mut frame = BoundedFrame(Vec::new());
    serde_json::to_writer(&mut frame, value)
        .map_err(|_| invalid("managed bootstrap serialization or v1 bound refused"))?;
    frame.0.push(b'\n');
    writer.write_all(&frame.0)?;
    writer.flush()
}

struct BoundedFrame(Vec<u8>);

impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() >= MAX_FRAME_BYTES - self.0.len() {
            return Err(invalid("managed bootstrap exceeds v1 frame bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
