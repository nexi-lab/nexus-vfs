//! LLM connector backends — SSE → DT_STREAM → CAS pipeline.

mod http_exchange;

#[cfg(feature = "driver-anthropic")]
pub mod anthropic;
#[cfg(feature = "driver-openai")]
pub mod openai;
