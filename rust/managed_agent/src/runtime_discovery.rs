//! Owner-authorized snapshots of this node's live managed runtimes.

use contracts::OperationContext;
use kernel::core::agents::registry::{AgentKind, AgentState};
use kernel::kernel::syscall::KernelSyscall;
use kernel::service_registry::RustCallError;
use serde::{Deserialize, Serialize};

use super::{GetSessionResponse, ManagedAgentError, ManagedAgentService};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListSessionsRequest {
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ListSessionsResponse {
    sessions: Vec<GetSessionResponse>,
}

impl<K: KernelSyscall> ManagedAgentService<K> {
    pub(super) fn list_sessions(
        &self,
        ctx: &OperationContext,
        request: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, RustCallError> {
        if request
            .agent_id
            .as_ref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err(RustCallError::InvalidArgument(
                "agent_id must not be empty".into(),
            ));
        }
        let mut sessions = Vec::new();
        for candidate in self.agent_registry.list(
            None,
            Self::session_owner_scope(ctx),
            Some(&AgentKind::Managed),
            None,
        ) {
            let Some((instance, descriptor)) = self.agent_registry.get_instance(&candidate.pid)
            else {
                continue;
            };
            if descriptor.state == AgentState::Terminated
                || request
                    .agent_id
                    .as_ref()
                    .is_some_and(|id| id != &descriptor.name)
            {
                continue;
            }
            match Self::authorize_session_owner(ctx, &descriptor) {
                Ok(()) => {}
                Err(RustCallError::PermissionDenied(_)) => continue,
                Err(error) => return Err(error),
            }
            match self.session_snapshot(&instance, descriptor) {
                Ok(snapshot) => sessions.push(snapshot),
                // A runtime can exit or its PID can be reused during enumeration.
                Err(ManagedAgentError::UnknownSession(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        sessions.sort_by(|left, right| {
            left.agent_id
                .cmp(&right.agent_id)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        Ok(ListSessionsResponse { sessions })
    }
}
