//! Pid allocator + epoch-ms helper for `ManagedAgentService`.
//!
//! There is no separate `session_id` for managed-agent sessions: the
//! AgentRegistry pid IS the session identifier sudowork sends back
//! over `cancel_v1` / `get_session_v1`.  Everything else
//! (workspace_path, model, agent name, state) is derived from the
//! descriptor on demand.

use std::sync::atomic::{AtomicU32, Ordering};

/// A co-hosted runtime belongs to this OS process. One process-wide counter
/// disambiguates runtimes across every service/kernel instance in the process.
pub(crate) fn alloc_pid() -> Result<String, String> {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let local = NEXT
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| "in-process runtime PID counter exhausted".to_string())?;
    Ok(contracts::agent_pid::encode_agent_pid(
        i64::from(std::process::id()),
        Some(local),
    ))
}

pub(crate) fn now_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
