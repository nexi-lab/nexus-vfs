//! Driving an LLM mount: the write is the request, a sibling stream is the reply.
//!
//! ## What a caller does
//!
//! Write a chat-completion request — the provider's own JSON, e.g.
//! `{"messages":[…],"model":"…"}` — to any path under an LLM mount, then tail
//! the sibling stream the request names:
//!
//! ```text
//! sys_write("/llm/ask-42.prompt", request_json)
//! sys_read ("/llm/ask-42.reply")      // blocking tail, as for /proc/{pid}/fd/*
//! ```
//!
//! Token frames arrive as the model produces them, then a terminal `done`
//! control frame carrying the session hash, then the stream closes. A failure
//! arrives as a structured `error` frame and the stream closes, so a reader is
//! never left waiting for output that is not coming.
//!
//! ## Why a write, and not a syscall
//!
//! The predecessor was `PyKernel::llm_start_streaming(mount, zone, request,
//! stream_path)` — a pyo3 entry point reached from the Python CLI. It did not
//! survive the move to this workspace, and for a while the docstrings that
//! outlived it described a syscall that was no longer anywhere in the tree.
//!
//! Rebuilding it in that shape was rejected deliberately. A model call that
//! needs its own syscall is not a path through the filesystem; it is an RPC
//! wearing a filesystem's clothes, and every surface that already understands
//! writes — permissions, hooks, audit, federation — would have to be taught
//! about it one at a time. As a write it inherits all of them by construction.
//!
//! That inheritance is the property worth stating plainly, because it is the
//! whole point:
//!
//! * the **request** passes `apply_mutating_write_hooks`, because every write
//!   does; and
//! * every frame of the **reply** passes it too, because [`StreamSink`] —
//!   which routes through `Kernel::stream_write_nowait` — is the only way the
//!   backend can emit one. `StreamManager::write_nowait` is `pub(crate)`, so
//!   there is no second door to find.
//!
//! Both directions are inside one seam. A prompt leaving the trust boundary
//! and a model's reply entering it are inspectable, rewritable and refusable
//! at the same single place — which is what makes sanitising a reply on the
//! way back in possible at all.
//!
//! ## The two paths
//!
//! `<name>.prompt` and `<name>.reply` — siblings: same directory, same mount,
//! same permissions. A reader allowed to see the question is allowed to see
//! the answer, and no second rule decides it. The pair is legible in a
//! directory listing, which is most of why the request carries a marker
//! rather than being "any write under the mount".
//!
//! The marker also settles two things for free. A reply lands on `.reply`,
//! which is not `.prompt`, so a reply can never be read as a fresh request —
//! without that, the first token would start a second call and that call's
//! first token a third. And a write that is not a prompt leaves this hook
//! after one suffix compare, which is what keeps a feature almost nobody
//! uses off the path every write takes.
//!
//! ## Asking twice, and who owns the name
//!
//! Writing a prompt path again **asks again**. The previous answer is
//! replaced, not appended to and not returned a second time — the same thing
//! overwriting a file means everywhere else. It is not idempotent: two
//! identical writes are two completions, and two bills.
//!
//! **The stem is the caller's concurrency key, and nothing here allocates
//! it.** Two requests that may be in flight at once need two stems.
//! `ask-42.prompt` and `ask-43.prompt` are independent; the same stem written
//! twice in quick succession is one slot being reused, and the later ask wins
//! it. That is a deliberate consequence of letting the caller name the pair
//! rather than handing back a generated id: the names stay meaningful and
//! greppable, and the cost is that uniqueness is the caller's to keep.
//!
//! This is worth stating because the failure it replaces was silent. Before,
//! a repeat ask did nothing at all and left the first answer in place, so a
//! caller polling `.reply` read a stale completion and had no way to tell.
//!
//! Both paths belong to the caller, who created one and named the other.
//! Nothing here reaps them: a prompt is an ordinary file and a reply is an
//! ordinary DT_STREAM, so they persist and are unlinked exactly like anything
//! else the caller wrote. The system records no state of its own about a
//! completion — there is no request table, no in-flight registry, nothing
//! that would outlive the answer.
//!
//! ## Shape of the service
//!
//! A hook, and the service that owns its lifetime. The hook lives here rather
//! than in the kernel because the kernel has no business knowing that model
//! providers exist: `as_llm_streaming()` is an `ObjectStore` extension trait
//! it already declares, and everything past that answer is this crate's.
//!
//! Registering through `ServiceRegistry` also means the kernel needed no new
//! field, no new constructor and no ABI change to gain this — the alternative,
//! reaching `Arc<Kernel>` from inside `sys_write`, would have meant a
//! self-reference on `Kernel` and touching every one of its ~48 construction
//! sites.

use std::sync::Arc;

use kernel::core::dispatch::{HookContext, NativeInterceptHook};
use kernel::kernel::Kernel;

/// A write to a path ending in this is a completion request.
///
/// Two things depend on it being an explicit marker rather than "any write
/// under an LLM mount".
///
/// It keeps the contract legible: a directory listing shows `ask-42.prompt`
/// beside `ask-42.reply` and a first-time reader can see which is which
/// without being told.
///
/// And it keeps this hook off the critical path. The hook is consulted after
/// EVERY write in the system, and deciding "is this an LLM mount?" means a
/// `VFSRouter::route` call — a longest-prefix-match walk that allocates a
/// `RouteResult`. Asking that of every write in order to serve the few that
/// are prompts is the wrong trade. With a marker the common answer is a
/// suffix compare against seven bytes, and the router is only consulted for
/// a write that has already said it is a prompt.
pub const PROMPT_SUFFIX: &str = ".prompt";

/// The stream a prompt's reply arrives on: the request path with
/// [`PROMPT_SUFFIX`] swapped for this.
///
/// Part of the mount's contract, so it is one constant here rather than a
/// convention each caller rebuilds from string pieces.
pub const REPLY_SUFFIX: &str = ".reply";

/// The reply stream for a prompt path.
///
/// One function so the request/reply pairing is defined once; a caller that
/// builds the name itself and a hook that builds it differently would be two
/// halves of a bug nothing catches.
pub fn reply_path_for(prompt_path: &str) -> Option<String> {
    let stem = prompt_path.strip_suffix(PROMPT_SUFFIX)?;
    Some(format!("{stem}{REPLY_SUFFIX}"))
}

/// Capacity of a reply stream, in bytes.
///
/// Sized for a long completion held whole by a reader that never drains it.
/// A DT_STREAM seals and spills past its capacity rather than failing the
/// write, so this is a working-set choice and not a ceiling on how long an
/// answer may be.
const REPLY_CAPACITY: usize = 1024 * 1024;

/// Service name in `ServiceRegistry`, and the owner tag its hook is filed
/// under.
pub const NAME: &str = "llm_mount";

/// Post-write hook that turns a write on an LLM mount into a completion.
///
/// POST rather than PRE on purpose: a completion should follow a write that
/// actually happened. A pre-hook would fire the provider call while the write
/// could still fail, leaving a model invoked — and billed — for a request the
/// filesystem then rejected.
///
/// Holding the `Arc<Kernel>` is what makes the work able to outlive the write:
/// the reply is pumped from a spawned task long after `sys_write` returned.
struct LlmMountHook {
    kernel: Arc<Kernel>,
    /// One lock per reply path, held for a whole completion.
    ///
    /// Per path rather than one global lock because the lock is held across
    /// the provider call: a global one would serialise every completion on
    /// the daemon behind whichever mount is slowest.
    ///
    /// Entries are dropped once nobody holds them, so this does not grow a
    /// row for every path the daemon has ever served.
    slots: Arc<dashmap::DashMap<String, Arc<std::sync::Mutex<()>>>>,
}

impl LlmMountHook {
    /// The lock that owns one reply path, for as long as an answer is being
    /// written to it.
    fn slot_for(&self, reply_path: &str) -> Arc<std::sync::Mutex<()>> {
        self.slots
            .entry(reply_path.to_string())
            .or_insert_with(|| Arc::new(std::sync::Mutex::new(())))
            .clone()
    }
}

/// Drops a slot's map row when the last holder leaves, on every exit path
/// including a panic — a row leaked here would pin a mutex forever.
struct SlotRelease<'a> {
    slots: &'a dashmap::DashMap<String, Arc<std::sync::Mutex<()>>>,
    path: &'a str,
}

impl Drop for SlotRelease<'_> {
    fn drop(&mut self) {
        // Two strong refs at this point are the map's own and this task's, so
        // that is the "nobody else is waiting" case.
        self.slots
            .remove_if(self.path, |_, m| Arc::strong_count(m) <= 2);
    }
}

/// Make `reply_path` an empty, open stream ready for this answer, replacing
/// any previous one. Call with the path's slot held.
///
/// Replacing is the whole point. `create_stream` refuses a path that already
/// exists, so asking twice on one path used to log a warning and return: the
/// second write succeeded, no completion ran, and the FIRST answer stayed on
/// `.reply` for the caller to read as though it were the second. Silently
/// serving a stale answer is the worst of the three behaviours this could
/// have had, and it is what a test now forbids.
fn open_reply_stream(kernel: &Arc<Kernel>, reply_path: &str) -> Result<(), String> {
    if kernel.has_stream(reply_path) {
        kernel
            .destroy_stream(reply_path)
            .map_err(|e| format!("destroying the previous reply: {e:?}"))?;
    }
    kernel
        .create_stream(reply_path, REPLY_CAPACITY)
        .map_err(|e| format!("creating the reply stream: {e:?}"))
}

impl NativeInterceptHook for LlmMountHook {
    fn name(&self) -> &str {
        NAME
    }

    fn on_post(&self, ctx: &HookContext) {
        let HookContext::Write(w) = ctx else {
            return;
        };
        // The whole cost of this hook for a write that is not a prompt: one
        // suffix compare, no allocation, no router. Everything below is
        // reached only by a write that has already declared itself.
        //
        // It also settles the recursion question for free — a reply lands on
        // a `.reply` path, which does not end in `.prompt`, so a reply can
        // never be read as a new request.
        let Some(reply_path) = reply_path_for(&w.path) else {
            return;
        };

        // Declaring itself a prompt is not the same as being one: the path
        // must actually resolve to a mount whose backend speaks the protocol.
        // A `.prompt` write anywhere else is an ordinary file, and stays one.
        let route = match self
            .kernel
            .vfs_router_arc()
            .route(&w.path, &w.identity.zone_id)
        {
            Some(r) => r,
            None => return,
        };
        let Some(backend) = route.backend.clone() else {
            return;
        };
        if backend.as_llm_streaming().is_none() {
            return;
        }

        // The sink carries the principal that wrote the request, so every reply
        // frame is attributed to whoever asked — not to the kernel, and not to
        // the mount. A hook inspecting the model's output is then deciding
        // about a caller rather than about an anonymous write.
        let ctx = caller_context(w);
        let sink = self.kernel.stream_sink(ctx.clone());

        // The request bytes are read back rather than carried through the hook
        // context: a post-hook is handed an empty `content` by design, so that
        // no write in the kernel pays to clone its payload for a hook that
        // usually does not want it. Reading happens inside the task, so the
        // writer is not held for it either.
        let kernel = Arc::clone(&self.kernel);
        let request_path = w.path.clone();
        // One completion at a time per reply path, and the slot is taken
        // inside the task so the writer is never made to wait on a model.
        //
        // Held across the WHOLE completion, not just the stream reset. A lock
        // around the reset alone is not enough and a test proved it: a second
        // ask would reset the stream out from under a completion still
        // appending to it, and the reader got a torn answer. Serialising here
        // is what makes "asking twice replaces the first answer" true rather
        // than merely likely.
        let slot = self.slot_for(&reply_path);
        let slots = Arc::clone(&self.slots);
        self.kernel.runtime().spawn_blocking(move || {
            let _held = slot.lock().unwrap_or_else(|e| e.into_inner());
            // Shed the map row once this was its last user, so `slots` tracks
            // completions in flight rather than every path ever asked.
            let _release = SlotRelease {
                slots: &slots,
                path: &reply_path,
            };
            if let Err(e) = open_reply_stream(&kernel, &reply_path) {
                tracing::warn!(
                    target: "nexus::llm_mount",
                    path = %reply_path,
                    error = %e,
                    "llm: could not open the reply stream; no completion started"
                );
                return;
            }
            let req = kernel::kernel::ReadRequest {
                path: request_path,
                offset: 0,
                len: None,
                timeout_ms: 0,
            };
            let request = match kernel.sys_read(&[req], &ctx).pop() {
                Some(Ok(r)) => match r.data {
                    Some(bytes) if !bytes.is_empty() => bytes,
                    _ => {
                        fail_stream(&sink, &reply_path, "request was empty");
                        return;
                    }
                },
                Some(Err(e)) => {
                    fail_stream(&sink, &reply_path, &format!("request unreadable: {e:?}"));
                    return;
                }
                None => {
                    fail_stream(&sink, &reply_path, "read returned no result");
                    return;
                }
            };
            // Re-taken here: the borrow cannot cross the spawn, and the
            // `Arc<dyn ObjectStore>` is what owns it.
            let Some(llm) = backend.as_llm_streaming() else {
                fail_stream(&sink, &reply_path, "mount stopped being LLM-capable");
                return;
            };
            if let Err(e) = llm.run_streaming(&request, &reply_path, &sink) {
                // `run_streaming` has already emitted an `error` frame and
                // closed the stream, so the reader is not waiting. This is the
                // operator's copy.
                tracing::warn!(
                    target: "nexus::llm_mount",
                    path = %reply_path,
                    error = %e,
                    "llm: completion failed"
                );
            }
        });
    }
}

/// Rebuild the writer's context from what the hook was given.
///
/// `HookIdentity` flattens `agent_id: Option<String>` to a `String`, so the
/// empty case has to be read back as `None` — an agent acting for itself and a
/// plain user are different callers, and collapsing them would make every
/// reply frame look like it came from an agent named "".
fn caller_context(w: &kernel::core::dispatch::WriteHookCtx) -> contracts::OperationContext {
    let agent_id = if w.identity.agent_id.is_empty() {
        None
    } else {
        Some(w.identity.agent_id.as_str())
    };
    contracts::OperationContext::new(
        &w.identity.user_id,
        &w.identity.zone_id,
        w.identity.is_admin,
        agent_id,
        /* is_system */ false,
    )
}

/// Tell the reader the completion is not coming, in the shape `run_streaming`
/// uses for its own failures, then close.
///
/// Every failure path after the stream exists goes through here. A reader
/// tailing a stream cannot distinguish "nothing yet" from "nothing ever", so
/// the one thing this must never do is return silently and leave the stream
/// open.
fn fail_stream(
    sink: &Arc<dyn kernel::extensions::llm_streaming::StreamSink>,
    path: &str,
    why: &str,
) {
    let frame = format!(r#"{{"type":"error","message":{}}}"#, json_string(why));
    let _ = sink.append(path, frame.as_bytes());
    let _ = sink.close(path);
    tracing::warn!(target: "nexus::llm_mount", path = %path, reason = %why, "llm: completion aborted");
}

/// Minimal JSON string escaping — this crate emits exactly one string field
/// and pulling a serialiser in for it would be the larger cost.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Register the service and its hook.
///
/// Declared for `ServiceRegistry` so the hook's lifetime is the service's:
/// unregister or swap the service and the kernel batch-removes the hook, which
/// is the reason this is a service at all rather than a loose
/// `register_native_hook` call at boot.
pub fn service_decl() -> kernel::kernel::ServiceDecl {
    kernel::kernel::ServiceDecl {
        name: NAME.to_string(),
        install: Box::new(install),
    }
}

fn install(kernel: &Arc<Kernel>) -> Result<(), String> {
    let handle = kernel.enlist_hook_only_service(NAME)?;
    kernel.register_service_hook(
        &handle,
        Box::new(LlmMountHook {
            kernel: Arc::clone(kernel),
            slots: Arc::new(dashmap::DashMap::new()),
        }),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prompt_names_its_reply_sibling() {
        assert_eq!(
            reply_path_for("/llm/ask-42.prompt").as_deref(),
            Some("/llm/ask-42.reply")
        );
    }

    /// The recursion guard, stated as a test because the consequence of losing
    /// it is not a crash but an unbounded spend: each reply frame would open a
    /// new completion, and each of those a third.
    #[test]
    fn a_reply_is_not_itself_a_prompt() {
        assert_eq!(reply_path_for("/llm/ask-42.reply"), None);
    }

    /// An ordinary write is not a prompt, which is both the contract and the
    /// reason this hook costs a write nothing.
    #[test]
    fn an_ordinary_path_is_not_a_prompt() {
        assert_eq!(reply_path_for("/llm/notes.txt"), None);
        assert_eq!(reply_path_for("/data/file"), None);
        assert_eq!(reply_path_for(""), None);
    }

    #[test]
    fn error_frames_escape_what_they_quote() {
        assert_eq!(json_string("a\"b"), r#""a\"b""#);
        assert_eq!(json_string("line\nbreak"), r#""line\nbreak""#);
        assert_eq!(json_string("tab\there"), r#""tab\there""#);
    }
}
