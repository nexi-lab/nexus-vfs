//! Delivery for hosted ACP, independent of engine state and durable history.
//!
//! The live transport is explicitly negotiated. Its replay buffer is bounded;
//! a lost cursor is reported, never treated as complete history. Both process
//! and thread hosts use this adapter. Only the authenticated service accepts
//! controller traffic; the host capability never crosses the wire.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use a2a::session::{
    validate_payload, SessionEndpoint, SessionPayload, SessionSide, LIVE_SESSION_PROTOCOL,
    MAX_SESSION_FRAME_BYTES,
};
use a2a::session_io::SessionMailbox;
use a2a::session_live::{DeliveryFrame, ReadSessionResponse};
use contracts::{OperationContext, RustCallError};
use kernel::core::agents::registry::AgentDescriptor;
use kernel::kernel::syscall::KernelSyscall;
use parking_lot::{Condvar, Mutex};

const BUFFER_BYTES: usize = 8 * 1024 * 1024;
const REPLAY_FRAMES: usize = 1024;
const INPUT_FRAMES: usize = 128;
const BATCH_BYTES: usize = 512 * 1024;
const BATCH_FRAMES: usize = 128;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
const RETIRED_CHANNELS: usize = 8;
const RETIRED_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct SessionTransport {
    endpoint: SessionEndpoint,
    live: Option<Arc<LiveSession>>,
}

impl SessionTransport {
    /// Legacy transports remain explicit, including for injected providers.
    pub fn mailbox(endpoint: SessionEndpoint) -> Result<Self, String> {
        endpoint.validate()?;
        if endpoint.protocol != a2a::session::SESSION_PROTOCOL {
            return Err("mailbox attachment requires acp-mailbox/1".into());
        }
        Ok(Self {
            endpoint,
            live: None,
        })
    }

    pub(crate) fn new(endpoint: SessionEndpoint, desc: &AgentDescriptor) -> Self {
        let live = (endpoint.protocol == LIVE_SESSION_PROTOCOL).then(|| {
            Arc::new(LiveSession {
                pid: desc.pid.clone(),
                owner: desc.owner_id.clone(),
                zone: desc.zone_id.clone(),
                controller: endpoint.controller.clone(),
                channel: endpoint.channel_id.clone(),
                state: Mutex::new(State::default()),
                input_ready: Condvar::new(),
                output_ready: Condvar::new(),
            })
        });
        Self { endpoint, live }
    }

    #[inline]
    pub fn endpoint(&self) -> &SessionEndpoint {
        &self.endpoint
    }

    pub fn open<K: KernelSyscall>(
        &self,
        kernel: Arc<K>,
        ctx: OperationContext,
    ) -> Result<HostSessionIo<K>, String> {
        if ctx.agent_id.as_deref().unwrap_or(&ctx.user_id) != self.endpoint.agent {
            return Err("host transport requires its admitted agent identity".into());
        }
        if let Some(live) = &self.live {
            if ctx.user_id != live.owner || ctx.zone_id != live.zone {
                return Err("host transport requires its admitted owner and zone".into());
            }
            Ok(HostSessionIo::Live(Arc::clone(live)))
        } else {
            SessionMailbox::open(kernel, ctx, self.endpoint.clone(), SessionSide::Agent)
                .map(Box::new)
                .map(HostSessionIo::Mailbox)
        }
    }

    pub(crate) fn live(&self) -> Option<&Arc<LiveSession>> {
        self.live.as_ref()
    }
}

/// Host-side I/O; controller admission always goes through ManagedAgentService.
pub enum HostSessionIo<K: KernelSyscall> {
    Mailbox(Box<SessionMailbox<K>>),
    Live(Arc<LiveSession>),
}

impl<K: KernelSyscall> HostSessionIo<K> {
    pub fn send(&self, payload: SessionPayload) -> Result<(), String> {
        match self {
            Self::Mailbox(mailbox) => mailbox.send(payload),
            Self::Live(live) => live.publish(payload),
        }
    }

    pub fn receive(&self, timeout_ms: u64) -> Result<Option<SessionPayload>, String> {
        match self {
            Self::Mailbox(mailbox) => mailbox.receive(timeout_ms),
            Self::Live(live) => live.receive(Duration::from_millis(timeout_ms)),
        }
    }

    #[inline]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }
}

#[derive(Debug)]
struct BufferedFrame {
    frame: DeliveryFrame,
    bytes: usize,
}

#[derive(Debug, Default)]
struct State {
    output: VecDeque<BufferedFrame>,
    output_bytes: usize,
    input: VecDeque<(SessionPayload, usize)>,
    input_bytes: usize,
    sent: u64,
    accepted: u64,
    retired: bool,
    closed: bool,
}

/// A service-owned capability, not a second engine/session state registry.
#[derive(Debug)]
pub struct LiveSession {
    pid: String,
    owner: String,
    zone: String,
    controller: String,
    channel: String,
    state: Mutex<State>,
    input_ready: Condvar,
    output_ready: Condvar,
}

fn payload_bytes(payload: &SessionPayload) -> Result<usize, String> {
    validate_payload(payload)?;
    let bytes = serde_json::to_vec(payload)
        .map_err(|error| error.to_string())?
        .len();
    if bytes > MAX_SESSION_FRAME_BYTES {
        return Err("session payload exceeds the size limit".into());
    }
    Ok(bytes)
}

impl LiveSession {
    pub(crate) fn authorize(&self, ctx: &OperationContext) -> Result<(), RustCallError> {
        // An administrator can stop a host through lifecycle RPCs but cannot
        // impersonate its controller or consume its private ACP traffic.
        if ctx.agent_id.as_deref() != Some(self.controller.as_str())
            || ctx.user_id != self.owner
            || ctx.zone_id != self.zone
        {
            return Err(RustCallError::PermissionDenied(
                "live ACP requires the original controller, owner and zone".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn submit(&self, sequence: u64, payload: SessionPayload) -> Result<(), String> {
        let bytes = payload_bytes(&payload)?;
        let mut state = self.state.lock();
        if state.retired || state.closed {
            return Err("live ACP attachment no longer accepts input".into());
        }
        if sequence > MAX_SEQUENCE || sequence != state.accepted + 1 {
            return Err(format!(
                "input sequence must follow {}; do not resubmit an uncertain prompt",
                state.accepted
            ));
        }
        if state.input.len() >= INPUT_FRAMES || state.input_bytes + bytes > BUFFER_BYTES {
            return Err("live ACP input queue is full; input was not accepted".into());
        }
        state.input.push_back((payload, bytes));
        state.input_bytes += bytes;
        state.accepted = sequence;
        self.input_ready.notify_one();
        Ok(())
    }

    fn receive(&self, timeout: Duration) -> Result<Option<SessionPayload>, String> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock();
        loop {
            if state.retired || state.closed {
                return Err("live ACP host attachment is closed".into());
            }
            if let Some((payload, bytes)) = state.input.pop_front() {
                state.input_bytes -= bytes;
                return Ok(Some(payload));
            }
            if self.input_ready.wait_until(&mut state, deadline).timed_out() {
                return Ok(None);
            }
        }
    }

    fn publish(&self, payload: SessionPayload) -> Result<(), String> {
        let bytes = payload_bytes(&payload)?;
        let mut state = self.state.lock();
        if state.closed || state.sent >= MAX_SEQUENCE {
            return Err("live ACP output is closed".into());
        }
        // Retirement does not truncate a final response already draining from
        // the original host. Only that host owns this capability.
        state.sent += 1;
        state.closed = matches!(payload, SessionPayload::Closed { .. });
        let sequence = state.sent;
        state.output.push_back(BufferedFrame {
            frame: DeliveryFrame { sequence, payload },
            bytes,
        });
        state.output_bytes += bytes;
        while state.output.len() > REPLAY_FRAMES || state.output_bytes > BUFFER_BYTES {
            let removed = state.output.pop_front().expect("nonempty replay");
            state.output_bytes -= removed.bytes;
        }
        self.output_ready.notify_all();
        Ok(())
    }

    pub(crate) fn read(&self, after: u64, timeout_ms: u64) -> Result<ReadSessionResponse, String> {
        if timeout_ms > 1000 {
            return Err("live ACP read timeout must not exceed 1000 ms".into());
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut state = self.state.lock();
        if after > state.sent {
            return Err("live ACP cursor is ahead of this attachment".into());
        }
        while state.sent == after && !state.closed {
            if self.output_ready.wait_until(&mut state, deadline).timed_out() {
                break;
            }
        }
        let earliest = state
            .output
            .front()
            .map_or(state.sent + 1, |item| item.frame.sequence);
        let resync_required = after + 1 < earliest;
        let mut bytes = 0;
        let frames = if resync_required {
            Vec::new()
        } else {
            state
                .output
                .iter()
                .filter(|item| item.frame.sequence > after)
                .take(BATCH_FRAMES)
                .take_while(|item| {
                    // A single legal large frame must still make progress.
                    let accept = bytes == 0 || bytes + item.bytes <= BATCH_BYTES;
                    if accept {
                        bytes += item.bytes;
                    }
                    accept
                })
                .map(|item| item.frame.clone())
                .collect()
        };
        Ok(ReadSessionResponse {
            frames,
            earliest_sequence: earliest,
            latest_sequence: state.sent,
            accepted_sequence: state.accepted,
            resync_required,
            retired: state.retired,
            closed: state.closed,
        })
    }

    fn retire(&self) {
        let mut state = self.state.lock();
        state.retired = true;
        state.input.clear();
        state.input_bytes = 0;
        self.input_ready.notify_all();
        self.output_ready.notify_all();
    }
}

/// Only final delivery receipts survive removal from the host registry. At most
/// eight bounded buffers (64 MiB worst case) remain, valid for sixty seconds.
/// Expiration is checked on access; there is no timer or additional worker.
#[derive(Default)]
pub(crate) struct RetiredSessions(Mutex<VecDeque<(Instant, Arc<LiveSession>)>>);

impl RetiredSessions {
    pub(crate) fn retire(&self, transport: &SessionTransport) {
        let Some(live) = transport.live() else { return };
        live.retire();
        let mut sessions = self.0.lock();
        sessions.retain(|(at, _)| at.elapsed() < RETIRED_TTL);
        while sessions.len() >= RETIRED_CHANNELS {
            sessions.pop_front();
        }
        sessions.push_back((Instant::now(), Arc::clone(live)));
    }

    pub(crate) fn get(&self, pid: &str, channel: &str) -> Option<Arc<LiveSession>> {
        let mut sessions = self.0.lock();
        sessions.retain(|(at, _)| at.elapsed() < RETIRED_TTL);
        sessions
            .iter()
            .find(|(_, live)| live.pid == pid && live.channel == channel)
            .map(|(_, live)| Arc::clone(live))
    }
}
