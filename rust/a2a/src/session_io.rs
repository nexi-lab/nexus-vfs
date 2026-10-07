//! Kernel-backed session transport, shared by subprocess and in-process hosts.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kernel::kernel::syscall::KernelSyscall;
use kernel::kernel::OperationContext;

use crate::session::{SessionCodec, SessionEndpoint, SessionPayload, SessionSide};

struct Reader {
    codec: SessionCodec,
    offset: u64,
}

/// One live, authenticated attachment. Reading and writing have separate locks:
/// a blocking tail read never prevents the engine from requesting permission,
/// and a running turn never prevents its answer from being read.
pub struct SessionMailbox<K: KernelSyscall> {
    kernel: Arc<K>,
    ctx: OperationContext,
    endpoint: SessionEndpoint,
    reader: Mutex<Reader>,
    writer: Mutex<SessionCodec>,
    closed: AtomicBool,
}

impl<K: KernelSyscall> SessionMailbox<K> {
    pub fn open(
        kernel: Arc<K>,
        mut ctx: OperationContext,
        endpoint: SessionEndpoint,
        side: SessionSide,
    ) -> Result<Self, String> {
        endpoint.validate()?;
        let actor = match side {
            SessionSide::Agent => &endpoint.agent,
            SessionSide::Controller => &endpoint.controller,
        };
        if ctx.agent_id.as_deref().unwrap_or(&ctx.user_id) != actor {
            return Err("session mailbox actor does not match its authenticated context".into());
        }
        ctx.propagates_cross_node = true;
        crate::ensure_conversation(kernel.as_ref(), &ctx, &endpoint.agent, &endpoint.controller)?;
        if kernel
            .sys_stat(&endpoint.transcript, contracts::ROOT_ZONE_ID)
            .is_none_or(|entry| entry.entry_type != 4)
        {
            return Err("session conversation requires a framed stream backend".into());
        }
        Ok(Self {
            kernel,
            ctx,
            reader: Mutex::new(Reader {
                codec: SessionCodec::new(endpoint.clone(), side)?,
                offset: 0,
            }),
            writer: Mutex::new(SessionCodec::new(endpoint.clone(), side)?),
            endpoint,
            closed: AtomicBool::new(false),
        })
    }

    pub fn endpoint(&self) -> &SessionEndpoint {
        &self.endpoint
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn send(&self, payload: SessionPayload) -> Result<(), String> {
        let mut writer = self.writer.lock().map_err(|_| "session writer poisoned")?;
        if self.is_closed() {
            return Err("session channel is closed".into());
        }
        let closing = matches!(payload, SessionPayload::Closed { .. });
        let bytes = writer.encode(payload)?;
        // Go through sys_write, never stream_write_nowait: authorization and
        // the authoritative sender stamp apply to every control message.
        match self
            .kernel
            .sys_write(&self.endpoint.transcript, &self.ctx, &bytes, 0)
        {
            Ok(result) if result.hit => {}
            Ok(_) => {
                self.closed.store(true, Ordering::Release);
                return Err("session conversation is not writable through the kernel".into());
            }
            Err(error) => {
                self.closed.store(true, Ordering::Release);
                return Err(format!(
                    "session append failed; delivery outcome is unknown: {error:?}"
                ));
            }
        }
        if closing {
            self.closed.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Consume one conversation record. `None` means a timeout, our own write,
    /// or traffic for another attachment. Callers keep this loop independent of
    /// the engine's turn worker. The stream cursor is a record offset, not bytes.
    pub fn receive(&self, timeout_ms: u64) -> Result<Option<SessionPayload>, String> {
        if self.is_closed() {
            return Err("session channel is closed".into());
        }
        let mut reader = self.reader.lock().map_err(|_| "session reader poisoned")?;
        let result = self
            .kernel
            .sys_read(
                &self.endpoint.transcript,
                &self.ctx,
                timeout_ms,
                reader.offset,
            )
            .map_err(|e| format!("session read failed: {e:?}"))?;
        let Some(bytes) = result.data.filter(|bytes| !bytes.is_empty()) else {
            return Ok(None);
        };
        let next = result
            .stream_next_offset
            .ok_or("session conversation must be a framed stream")? as u64;
        if next <= reader.offset {
            return Err("session stream did not advance its cursor".into());
        }
        let decoded = reader.codec.decode(&bytes)?;
        reader.offset = next;
        if matches!(decoded, Some(SessionPayload::Closed { .. })) {
            self.closed.store(true, Ordering::Release);
        }
        Ok(decoded)
    }
}
