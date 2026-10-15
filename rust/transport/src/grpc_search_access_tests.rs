use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::runtime_scope::RuntimeDelegation;
use kernel::core::dispatch::PermissionProvider;
use kernel::vfs_router::RouteResult;

fn session(user: &str, actor: &str) -> OperationContext {
    let mut ctx = OperationContext::new(user, "root", false, Some(actor), false);
    ctx.subject_type = "agent".into();
    ctx.subject_id = Some(actor.into());
    ctx
}

struct GatewayAuth;

impl AuthProvider for GatewayAuth {
    fn resolve(&self, _credentials: &AuthCredentials<'_>) -> Result<OperationContext, Status> {
        Ok(OperationContext::new("node/7", "root", true, None, true))
    }

    fn resolve_forwarded_agent(&self, user: &str, actor: &str) -> Result<OperationContext, Status> {
        Ok(session(user, actor))
    }
}

struct SessionPermissions(Arc<AtomicUsize>);

impl PermissionProvider for SessionPermissions {
    fn check(
        &self,
        _path: &str,
        _route: Option<&RouteResult>,
        _permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        assert_eq!(ctx.user_id, "alice");
        assert_eq!(ctx.agent_id.as_deref(), Some("session-alice"));
        assert!(!ctx.is_admin && !ctx.is_system);
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn delegated_search_checks_the_session_principal_without_gateway_privileges() {
    let kernel = Arc::new(Kernel::new());
    let checks = Arc::new(AtomicUsize::new(0));
    kernel.set_permission_provider(Arc::new(Box::new(SessionPermissions(Arc::clone(&checks)))));
    let policy = SearchGrpcPolicy::new(kernel, Arc::new(GatewayAuth))
        .with_runtime_scope(Arc::new(RuntimeScope::new("alice".into(), [7]).unwrap()));
    let peer = PeerIdentity {
        common_name: "gateway".into(),
        node_id: Some(7),
        zone_id: Some("root".into()),
        agent_name: None,
        trust_domain: None,
        owner: None,
        runtime_server_name: None,
        serial: Vec::new(),
    };
    let mut metadata = MetadataMap::new();
    RuntimeDelegation::from_context(&session("alice", "session-alice"))
        .unwrap()
        .apply(&mut metadata)
        .unwrap();
    let mut payload = GlobRequest {
        root_path: "/".into(),
        pattern: "*.md".into(),
        files: Some(DiscoveryFiles {
            paths: vec!["/note.md".into()],
        }),
        ..Default::default()
    }
    .encode_to_vec();
    policy
        .authorize("Glob", &mut payload, &metadata, Some(&peer))
        .unwrap();
    assert!(
        checks.load(Ordering::SeqCst) > 0,
        "gateway privileges bypassed file authorization"
    );
    let mut forbidden = PutPathContextRequest::default().encode_to_vec();
    let error = policy.authorize("PutPathContext", &mut forbidden, &metadata, Some(&peer));
    assert_eq!(error.err().unwrap().code(), tonic::Code::PermissionDenied);
    metadata.clear();
    assert_eq!(
        policy
            .authorize("Glob", &mut payload, &metadata, Some(&peer))
            .err()
            .unwrap()
            .code(),
        tonic::Code::PermissionDenied
    );
}
