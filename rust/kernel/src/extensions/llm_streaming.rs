//! `LlmStreamingBackend` — object-safe §3.A.2 extension trait on
//! `ObjectStore`. Connector backends opt in so a protocol-specific SSE
//! pipeline (OpenAI, Anthropic, …) can be driven without the kernel
//! learning any provider's wire format.
//!
//! Distinct from §3.B Control-Plane HAL traits: those are runtime DI
//! surfaces the kernel reaches through trait dispatch
//! (`DistributedCoordinator`, `ObjectStoreProvider`); this is a
//! sub-capability ObjectStore impls expose through
//! [`crate::abc::object_store::ObjectStore::as_llm_streaming`].
//!
//! Trait declaration lives in the kernel because the
//! `ObjectStore::as_llm_streaming() -> Option<&dyn LlmStreamingBackend>`
//! method signature references it. Concrete protocol-specific impls
//! (`OpenAIBackend`, `AnthropicBackend`) live in
//! `backends/src/transports/api/ai/*`.
//!
//! Nothing drives these backends yet — there is no caller in the tree, so
//! no model call happens through the kernel today. The shape here is the
//! half that is settled: whatever drives them hands over a [`StreamSink`],
//! never a stream buffer.

use std::sync::Arc;

/// Where a streaming backend puts what the model said.
///
/// A backend gets this rather than the `StreamManager` it used to be handed,
/// and the difference is the point: appending through the kernel runs
/// `apply_mutating_write_hooks`, and appending to the buffer directly does
/// not. A model's reply is untrusted content crossing into the trust
/// boundary, so it is the write that most needs a hook to see it — and it
/// was the one write that had none.
///
/// Deliberately two methods wide. A backend needs to say "here is more
/// output" and "that is all"; anything else it could reach for through a
/// stream handle — creating, destroying, reading someone else's stream — is
/// not its job, and a narrow handle is how that stays true without a rule
/// to remember.
pub trait StreamSink: Send + Sync {
    /// Append one frame. Returns the byte offset it landed at.
    ///
    /// A hook may rewrite the bytes or refuse the write outright, so a
    /// caller must treat `Err` as "this did not happen" rather than a
    /// transport hiccup to retry around.
    fn append(&self, path: &str, data: &[u8]) -> Result<usize, String>;

    /// Signal end-of-stream, waking every blocked reader. Carries no
    /// content, so no hook runs.
    fn close(&self, path: &str) -> Result<(), String>;
}

/// Streaming-capable LLM backend — object-safe trait so `ObjectStore` impls
/// can opt in without every backend learning every provider's SSE shape.
pub trait LlmStreamingBackend: Send + Sync {
    /// Run a streaming chat completion to completion. Appends token deltas
    /// to `stream_path` through `sink`, persists the session via CAS, closes
    /// the stream. Blocks the calling thread — the caller is expected to be
    /// on a worker thread, since this does I/O and waits on the provider.
    fn run_streaming(
        &self,
        request_bytes: &[u8],
        stream_path: &str,
        sink: &Arc<dyn StreamSink>,
    ) -> Result<(), String>;
}
