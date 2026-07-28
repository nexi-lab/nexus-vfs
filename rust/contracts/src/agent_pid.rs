//! Agent per-run pid encoding — the run handle IS the OS process id.
//!
//! # Design (decided 2026-07-28 with the kernel lead)
//!
//! An agent has TWO identity layers:
//!   * **persistent identity = the agent NAME** (`/agents/{name}/chat-with-me`,
//!     cluster-unique, cross-machine, survives restart). This is what other
//!     agents address; the pid is never the external address.
//!   * **per-run handle = the pid** — ephemeral, one per process start.
//!
//! The pid is the **OS process id** (`host_pid`), optionally suffixed with a
//! runtime-assigned `local_id` when several *micro-agents* (coroutines/threads)
//! share ONE OS process. Rationale:
//!   * **OS-mechanism reuse + debuggability**: the pid literally equals the OS
//!     pid, so `/proc/{pid}`, `ps`, `kill`, `gdb`, cgroups apply directly, and
//!     the mapping survives without querying nexus (the id decodes to the OS
//!     handle). No separate `host_pid` field — it would be a duplicate (SSOT).
//!   * **lifetime = process lifetime**: when the OS process dies the pid is
//!     meaningless and the agent is reaped — the desired coupling, not a bug.
//!     OS pid reuse is fine: live pids are unique at any instant, and durable
//!     references are either the NAME (unforgeable `from`) or timestamped logs
//!     (`pid X @ time T` is unambiguous given T), so no `start_time` is needed.
//!   * **node-local**: `/proc/{pid}` is node-local; cross-machine identity is
//!     the NAME. So the pid carries no `node_id`.
//!   * **generic**: every agent runs in *some* OS process, so `host_pid` always
//!     exists (a coroutine's is its runtime process, shared — `local_id`
//!     disambiguates). `local_id` is a nexus-runtime per-process counter, not an
//!     OS thread id, so it is uniform cross-platform (incl. embedded).
//!
//! Format: `"{host_pid}"` or `"{host_pid}.{local_id}"`. A non-OS-derived id
//! (e.g. a legacy synthetic pid) decodes to `(None, None)` so callers degrade
//! gracefully. The Python mirror lives in `src/nexus/contracts/` — keep in sync.

/// Encode an agent run pid: the OS `host_pid`, plus an optional intra-process
/// `local_id` for micro-agents sharing one process. See module docs.
pub fn encode_agent_pid(host_pid: i64, local_id: Option<u32>) -> String {
    match local_id {
        Some(l) => format!("{host_pid}.{l}"),
        None => host_pid.to_string(),
    }
}

/// Decode a pid back to `(host_pid, local_id)`. A pid that is not OS-pid-derived
/// (legacy synthetic id, non-numeric) yields `(None, None)` — callers that want
/// OS-level ops check for `Some(host_pid)` and skip otherwise.
pub fn decode_agent_pid(pid: &str) -> (Option<i64>, Option<u32>) {
    let (host, local) = match pid.split_once('.') {
        Some((h, l)) => (h, l.parse::<u32>().ok()),
        None => (pid, None),
    };
    (host.parse::<i64>().ok(), local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pid_only_roundtrips() {
        let pid = encode_agent_pid(12345, None);
        assert_eq!(pid, "12345");
        assert_eq!(decode_agent_pid(&pid), (Some(12345), None));
    }

    #[test]
    fn host_pid_with_local_id_roundtrips() {
        let pid = encode_agent_pid(12345, Some(7));
        assert_eq!(pid, "12345.7");
        assert_eq!(decode_agent_pid(&pid), (Some(12345), Some(7)));
    }

    #[test]
    fn legacy_or_synthetic_pid_decodes_to_none() {
        // A uuid-style legacy pid is not OS-derived — degrade gracefully so the
        // registry still works, OS-op paths just skip it.
        assert_eq!(decode_agent_pid("a1b2c3d4e5f6"), (None, None));
        // Bogus local part: host still recovered, local dropped.
        assert_eq!(decode_agent_pid("12345.xyz"), (Some(12345), None));
    }
}
