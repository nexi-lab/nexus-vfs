//! Native space management over the existing context-aware Call service seam.
//! The composition root must supply its real identity posture and host CA key
//! identity. No profile installs this service yet. Its capability explicitly
//! advertises management only, never a usable collaboration data plane.

use crate::collaboration_policy::{
    validated_space_key, PolicyError, SpacePolicy, SpacePolicyStore,
};
use contracts::{OperationContext, RustCallError, RustService};
use kernel::kernel::{Kernel, ServiceDecl};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub const SERVICE_NAME: &str = "collaboration";
const METHODS: &[&str] = &[
    "capabilities_v1",
    "create_space_v1",
    "get_space_v1",
    "revoke_space_v1",
];

pub struct SpaceManagementService {
    store: Arc<dyn SpacePolicyStore>,
    host: [u8; 32],
}

impl SpaceManagementService {
    /// `identity_armed` is the actual boot posture, not a request/config claim.
    /// Even when armed, every Call separately requires a native Node context;
    /// a generic system/admin bit does not authorize management.
    pub fn new(
        store: Arc<dyn SpacePolicyStore>,
        host: [u8; 32],
        identity_armed: bool,
    ) -> Result<Self, String> {
        if !identity_armed {
            return Err("collaboration management cannot run with Open/NoAuth".into());
        }
        Ok(Self { store, host })
    }

    pub fn service_decl(
        store: Arc<dyn SpacePolicyStore>,
        host: [u8; 32],
        identity_armed: bool,
    ) -> Result<ServiceDecl, String> {
        let service = Arc::new(Self::new(store, host, identity_armed)?);
        Ok(ServiceDecl {
            name: SERVICE_NAME.into(),
            install: Box::new(move |kernel: &Arc<Kernel>| {
                kernel.register_rust_service(SERVICE_NAME, service.clone(), service.exports())
            }),
        })
    }
}

fn require_node(ctx: &OperationContext) -> Result<(), RustCallError> {
    let named_node = ctx
        .user_id
        .strip_prefix("node/")
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| ctx.user_id == format!("node/{n}"));
    if !ctx.is_system
        || !ctx.is_admin
        || ctx.subject_type != "node"
        || !named_node
        || ctx.subject_id.as_deref() != Some(ctx.user_id.as_str())
        || ctx.agent_id.is_some()
        || ctx.trust_domain.is_some()
    {
        return Err(RustCallError::PermissionDenied(
            "collaboration management requires an authenticated local Node identity".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    policy: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Space {
    space: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn decode<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, RustCallError> {
    if payload.len() > 40 * 1024 {
        return Err(RustCallError::InvalidArgument(
            "collaboration management payload exceeds 40 KiB".into(),
        ));
    }
    serde_json::from_slice(payload).map_err(|e| RustCallError::InvalidArgument(e.to_string()))
}

fn invalid(error: PolicyError) -> RustCallError {
    RustCallError::InvalidArgument(format!("{error:?}"))
}
fn observed(policy: &SpacePolicy) -> Result<Value, RustCallError> {
    serde_json::from_slice(&policy.encode().map_err(invalid)?)
        .map_err(|e| RustCallError::Internal(e.to_string()))
}
fn mutation(result: Result<(), PolicyError>) -> Value {
    match result {
        Ok(()) => json!({"outcome":"confirmed"}),
        // Once a mutation is attempted, no error is reclassified as definite
        // no-submit. A separate get may reconcile it; never resubmit here.
        Err(error) => json!({"outcome":"unknown","reason":format!("{error:?}")}),
    }
}

impl RustService for SpaceManagementService {
    fn name(&self) -> &str {
        SERVICE_NAME
    }
    fn exports(&self) -> Vec<String> {
        METHODS.iter().map(|s| (*s).to_owned()).collect()
    }
    fn dispatch(
        &self,
        method: &str,
        payload: &[u8],
        ctx: &OperationContext,
    ) -> Result<Vec<u8>, RustCallError> {
        if !METHODS.contains(&method) {
            return Err(RustCallError::NotFound);
        }
        require_node(ctx)?;
        let result = match method {
            "capabilities_v1" => {
                let _: Empty = decode(payload)?;
                json!({"managementVersion":1,"dataPlaneVersion":0,"hostAuthority":self.host})
            }
            "create_space_v1" => {
                let request: Create = decode(payload)?;
                let policy = SpacePolicy::decode(
                    &serde_json::to_vec(&request.policy)
                        .map_err(|e| RustCallError::InvalidArgument(e.to_string()))?,
                )
                .map_err(invalid)?;
                if policy.host_authority() != &self.host {
                    return Err(RustCallError::PermissionDenied(
                        "space must be hosted by this authority".into(),
                    ));
                }
                mutation(self.store.create(&policy))
            }
            "get_space_v1" => {
                let request: Space = decode(payload)?;
                validated_space_key(&request.space).map_err(invalid)?;
                match self.store.current(&request.space) {
                    Ok(policy) if policy.host_authority() == &self.host => {
                        json!({"outcome":"observed","policy":observed(&policy)?})
                    }
                    Ok(_) => {
                        return Err(RustCallError::PermissionDenied(
                            "stored policy belongs to another host".into(),
                        ))
                    }
                    Err(PolicyError::NotFound) => json!({"outcome":"not_observed"}),
                    Err(PolicyError::Revoked) => json!({"outcome":"revoked"}),
                    Err(error) => json!({"outcome":"unknown","reason":format!("{error:?}")}),
                }
            }
            "revoke_space_v1" => {
                let request: Space = decode(payload)?;
                validated_space_key(&request.space).map_err(invalid)?;
                mutation(self.store.revoke(&request.space))
            }
            _ => return Err(RustCallError::NotFound),
        };
        serde_json::to_vec(&result).map_err(|e| RustCallError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_address::AgentAddress;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    const SPACE: &str = "0123456789abcdef0123456789abcdef";
    #[derive(Default)]
    struct Store {
        policy: Mutex<Option<SpacePolicy>>,
        calls: AtomicUsize,
        lose_reply: bool,
    }
    impl SpacePolicyStore for Store {
        fn create(&self, p: &SpacePolicy) -> Result<(), PolicyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.policy.lock().unwrap() = Some(p.clone());
            if self.lose_reply {
                Err(PolicyError::Unknown("reply lost after apply".into()))
            } else {
                Ok(())
            }
        }
        fn current(&self, _: &str) -> Result<SpacePolicy, PolicyError> {
            self.policy
                .lock()
                .unwrap()
                .clone()
                .ok_or(PolicyError::NotFound)
        }
        fn revoke(&self, _: &str) -> Result<(), PolicyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn node() -> OperationContext {
        let mut c = OperationContext::new("node/7", "root", true, None, true);
        c.subject_type = "node".into();
        c.subject_id = Some("node/7".into());
        c
    }
    fn create(host: u8) -> Vec<u8> {
        let p = SpacePolicy::new(
            SPACE.into(),
            [host; 32],
            "collab-one".into(),
            vec![
                AgentAddress::new([1; 32], "a".into()).unwrap(),
                AgentAddress::new([2; 32], "b".into()).unwrap(),
            ],
            0,
            100,
        )
        .unwrap();
        serde_json::to_vec(&json!({"policy":observed(&p).unwrap()})).unwrap()
    }
    #[test]
    fn noauth_and_non_node_contexts_cannot_manage_or_claim_a_node_in_the_payload() {
        let store = Arc::new(Store::default());
        assert!(SpaceManagementService::new(store.clone(), [1; 32], false).is_err());
        let service = SpaceManagementService::new(store.clone(), [1; 32], true).unwrap();
        for caller in [
            OperationContext::new("cluster-internal", "root", true, None, true),
            OperationContext::new("admin", "root", true, None, false),
            OperationContext::new("owner", "root", false, Some("session-x"), false),
        ] {
            assert!(matches!(
                service.dispatch("create_space_v1", &create(1), &caller),
                Err(RustCallError::PermissionDenied(_))
            ));
        }
        assert!(service
            .dispatch("create_space_v1", &create(2), &node())
            .is_err());
        assert!(service
            .dispatch(
                "revoke_space_v1",
                br#"{"space":"0123456789abcdef0123456789abcdef","caller":"node/7"}"#,
                &node()
            )
            .is_err());
        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            service.dispatch("unknown_method", b"{}", &node()),
            Err(RustCallError::NotFound)
        ));
    }
    #[test]
    fn mutation_loss_is_unknown_with_one_call_and_read_only_reconciliation() {
        let store = Arc::new(Store {
            lose_reply: true,
            ..Store::default()
        });
        let service = SpaceManagementService::new(store.clone(), [1; 32], true).unwrap();
        let response: Value = serde_json::from_slice(
            &service
                .dispatch("create_space_v1", &create(1), &node())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["outcome"], "unknown");
        let response: Value = serde_json::from_slice(
            &service
                .dispatch(
                    "get_space_v1",
                    br#"{"space":"0123456789abcdef0123456789abcdef"}"#,
                    &node(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["outcome"], "observed");
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        let caps: Value =
            serde_json::from_slice(&service.dispatch("capabilities_v1", b"{}", &node()).unwrap())
                .unwrap();
        assert_eq!(caps["managementVersion"], 1);
        assert_eq!(caps["dataPlaneVersion"], 0);
    }

    #[test]
    fn native_kernel_call_preserves_the_resolved_context_and_management_only_capability() {
        let store = Arc::new(Store::default());
        let kernel = Arc::new(Kernel::new());
        kernel
            .bring_up_services(vec![SpaceManagementService::service_decl(
                store.clone(),
                [1; 32],
                true,
            )
            .unwrap()])
            .unwrap();
        let open = OperationContext::new("cluster-internal", "root", true, None, true);
        assert!(matches!(
            kernel
                .dispatch_rust_call_ctx(&open, SERVICE_NAME, "create_space_v1", &create(1))
                .unwrap(),
            Err(RustCallError::PermissionDenied(_))
        ));
        let result = kernel
            .dispatch_rust_call_ctx(&node(), SERVICE_NAME, "create_space_v1", &create(1))
            .unwrap()
            .unwrap();
        let response: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(response["outcome"], "confirmed");
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        let caps = kernel
            .dispatch_rust_call_ctx(&node(), SERVICE_NAME, "capabilities_v1", b"{}")
            .unwrap()
            .unwrap();
        let caps: Value = serde_json::from_slice(&caps).unwrap();
        assert_eq!(caps["dataPlaneVersion"], 0);
    }
}
