//! `extensions/` — opt-in §3.A.2 ObjectStore extension traits.
//!
//! The §3.A storage HAL has two flavors of contract:
//!
//! * **Mandatory pillars** — every backend implements them.  The three
//!   co-equal pillars (`ObjectStore`, `MetaStore`, `CacheStore`) live in
//!   [`crate::abc`], one trait file each.
//! * **Opt-in extensions** — sub-capabilities a backend MAY expose so
//!   the kernel can drive a richer syscall against it.  Each is reached
//!   through an `ObjectStore::as_*() -> Option<&dyn Ext>` downcast, so
//!   the extension trait DECLARATION must sit at the kernel boundary
//!   (the method signature in [`crate::abc::object_store`] references
//!   it).  Those declarations live here.
//!
//! This directory is the home for the second flavor.  It's a sibling to
//! `abc/` (pillars), `hal/` (§3.B control-plane DI surfaces), and
//! `core/` (§4 primitives) — a fourth tier-directory whose members are
//! all ObjectStore extension-trait declarations, nothing else.
//!
//! Concrete impls never live here — they live in `rust/backends/` next
//! to the backend that opts in (e.g. `OpenAIBackend` /
//! `AnthropicBackend` for `LlmStreamingBackend`).
//!
//! Current members:
//!
//! * [`llm_streaming`] — `LlmStreamingBackend`, connector-backend SSE
//!   streaming (reached via `ObjectStore::as_llm_streaming`).
//!
//! Not here: metadata-sync for out-of-band backends is a §4 kernel
//! primitive (a generic reconcile over `list_dir`/`stat`, which must
//! cross the dylib C-ABI), not an `as_*` extension trait — it lives in
//! `crate::core::metadata_sync`.

pub mod llm_streaming;
