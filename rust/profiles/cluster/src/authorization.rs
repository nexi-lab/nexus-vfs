//! Production authorization and HTTP composition. Tuples and API keys share
//! the credential consensus; transports share the daemon's identity and gate.

use super::{CommonArgs, ServiceBootCtx};
use anyhow::{bail, Result};
use kernel::kernel::{KernelError, OperationContext, ServiceDecl};
use kernel::vfs_router::RouteResult;
#[cfg(feature = "rebac")]
use kernel::vfs_router::VFSRouter;
use kernel::{Permission, PermissionProvider};
use std::sync::Arc;
use transport::grpc::DataPlaneReady;

/// Mandatory relationship enforcement supplied only by authenticated cluster
/// composition. This checks the original caller, not the service's privileges.
/// It does not establish a durable Session/storage association.
#[cfg(feature = "rebac")]
pub struct CurrentResourceGrants {
    relationships: Arc<nexus_rebac::RebacPermissionProvider>,
}

#[cfg(feature = "rebac")]
impl CurrentResourceGrants {
    /// Run off the async executor: the tuple store awaits an actual ReadIndex.
    /// Retain the same captured route/storage through the operation. A successful
    /// check must not be cached as authority for a later action or another route.
    pub fn check(
        &self,
        path: &str,
        route: &RouteResult,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        a2a::foreign_containment::ForeignAgentMailboxOnly.check(
            path,
            Some(route),
            permission,
            ctx,
        )?;
        self.relationships
            .check_current_grants(path, route, permission, ctx)
    }
}

/// The cluster's single permission slot enforces both policies, in order.
/// Foreign containment bounds trust-domain authority even when relationships grant access.
struct ClusterPermissionProvider {
    #[cfg(feature = "rebac")]
    router: Arc<VFSRouter>,
    #[cfg(feature = "rebac")]
    relationships: Option<Arc<nexus_rebac::RebacPermissionProvider>>,
}

impl PermissionProvider for ClusterPermissionProvider {
    fn check(
        &self,
        path: &str,
        route: Option<&RouteResult>,
        permission: Permission,
        ctx: &OperationContext,
    ) -> Result<(), KernelError> {
        a2a::foreign_containment::ForeignAgentMailboxOnly.check(path, route, permission, ctx)?;
        #[cfg(feature = "rebac")]
        if let Some(relationships) = &self.relationships {
            // Early syscall checks have no route yet. The mount owner, rather
            // than the caller's ambient zone, owns the relationship graph.
            // Reuse an existing route and preserve the privileged fast path.
            let resolved;
            let route = if route.is_none() && !ctx.is_admin && !ctx.is_system {
                resolved = self.router.route(path, &ctx.zone_id).ok_or_else(|| {
                    KernelError::PermissionDenied(format!(
                        "rebac: no mount owns {path} in zone {}",
                        ctx.zone_id
                    ))
                })?;
                Some(&resolved)
            } else {
                route
            };
            relationships.check(path, route, permission, ctx)?;
        }
        Ok(())
    }
}

pub(super) fn validate(common: &CommonArgs) -> Result<()> {
    if common.enable_rebac && !cfg!(feature = "rebac") {
        bail!("--enable-rebac requires a build with the rebac feature");
    }
    if let Some(addr) = common.http_addr {
        if !cfg!(feature = "http-api") {
            bail!("--http-addr requires a build with the http-api feature");
        }
        if !common.enable_rebac {
            bail!("--http-addr requires --enable-rebac so tuple management and enforcement share one policy");
        }
        if !addr.ip().is_loopback() {
            bail!("--http-addr must be loopback; expose it through a TLS reverse proxy");
        }
    }
    Ok(())
}

pub(super) fn service_decls(
    common: &CommonArgs,
    _ctx: &mut ServiceBootCtx,
    _zm: &nexus_raft::ZoneManager,
    _ready: Arc<DataPlaneReady>,
) -> Result<Vec<ServiceDecl>> {
    #[cfg(feature = "rebac")]
    let store = if common.enable_rebac {
        let plane = _ctx.credential_plane.as_ref().ok_or_else(|| {
            anyhow::anyhow!("relationship management requires the cluster credential plane")
        })?;
        Some(nexus_rebac::RaftReBACTupleStore::new_arc(
            plane.consensus.clone(),
            plane.runtime.clone(),
        ))
    } else {
        None
    };
    #[cfg(feature = "rebac")]
    let relationships = store.as_ref().map(|store| {
        Arc::new(nexus_rebac::RebacPermissionProvider::new(Arc::new(
            nexus_rebac::ReBACGraphCache::new(Arc::clone(store)),
        )))
    });
    #[cfg(feature = "rebac")]
    {
        _ctx.current_resource_grants = if _ctx.auth_armed {
            relationships.as_ref().map(|relationships| {
                Arc::new(CurrentResourceGrants {
                    relationships: Arc::clone(relationships),
                })
            })
        } else {
            None
        };
    }
    let services = vec![ServiceDecl {
        name: "authorization".into(),
        install: Box::new(move |kernel| {
            let provider = ClusterPermissionProvider {
                #[cfg(feature = "rebac")]
                router: kernel.vfs_router_arc(),
                #[cfg(feature = "rebac")]
                relationships,
            };
            kernel.set_permission_provider(Arc::new(Box::new(provider)));
            Ok(())
        }),
    }];
    #[cfg(feature = "http-api")]
    let services = {
        let mut services = services;
        if let Some(store) = store {
            if let Some(addr) = common.http_addr {
                let api_key_secret = _ctx
                    .credential_plane
                    .as_ref()
                    .and_then(|plane| plane.api_key_secret.as_deref());
                if _ctx.auth_armed && api_key_secret.is_none() {
                    bail!("HTTP bearer authentication requires NEXUS_API_KEY_SECRET; the certificate-only auth posture cannot authenticate HTTP callers");
                }
                use nexus_search_common::transport::{PeerChannelCache, PeerChannelConfig};
                let grpc = common.effective_bind_addr();
                let mut grpc: std::net::SocketAddr = grpc.parse()?;
                if grpc.ip().is_unspecified() {
                    grpc.set_ip(if grpc.is_ipv4() {
                        std::net::Ipv4Addr::LOCALHOST.into()
                    } else {
                        std::net::Ipv6Addr::LOCALHOST.into()
                    });
                }
                let credentials = _zm.registry().shared_tls();
                let (scheme, channels) = match _zm.node_tls().map_err(anyhow::Error::msg)? {
                    Some(_) => {
                        let channels = Arc::new(PeerChannelCache::with_tls(
                            PeerChannelConfig::default(),
                            credentials,
                        ));
                        ("https", channels)
                    }
                    None => (
                        "http",
                        Arc::new(PeerChannelCache::with_credentials(
                            PeerChannelConfig::default(),
                            credentials,
                        )),
                    ),
                };
                let search = nexus_http_api::SearchBackend::with_channels(
                    format!("{scheme}://{grpc}"),
                    channels,
                );
                services.push(nexus_http_api::service_decl(
                    addr,
                    search,
                    Arc::clone(&_ctx.auth),
                    _ctx.runtime.clone(),
                    api_key_secret.map(Arc::from),
                    store,
                    _ready,
                ));
            }
        }
        services
    };
    let _ = common;
    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[cfg(feature = "rebac")]
    #[test]
    fn boot_without_relationship_enforcement_exposes_no_current_grant_provider() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let data = tempfile::tempdir().unwrap();
        let zm = {
            let _entered = runtime.enter();
            nexus_raft::ZoneManager::new(
                "authorization-test",
                data.path().to_str().unwrap(),
                Vec::new(),
                "127.0.0.1:0",
                None,
            )
            .unwrap()
        };
        let mut common = crate::Args::try_parse_from(["nexusd-cluster"])
            .unwrap()
            .common;
        common.enable_rebac = false;
        common.http_addr = None;
        for auth_armed in [false, true] {
            let mut ctx = ServiceBootCtx {
                auth_armed,
                auth: Arc::new(transport::auth::NoAuth),
                runtime: runtime.handle().clone(),
                credential_plane: None,
                current_resource_grants: None,
            };
            let declarations =
                service_decls(&common, &mut ctx, &zm, DataPlaneReady::pending()).unwrap();
            assert_eq!(declarations.len(), 1);
            assert!(ctx.current_resource_grants.is_none());
        }
    }

    #[test]
    fn open_posture_bypasses_collaboration_namespace_reservation() {
        use transport::auth::{AuthCredentials, AuthProvider, NoAuth};

        let auth = NoAuth;
        let context = auth.resolve(&AuthCredentials::from_token("")).unwrap();
        assert_eq!(auth.mode(), "no-auth");
        assert!(context.is_system && context.is_admin);
        let kernel = kernel::kernel::Kernel::new();
        let provider = ClusterPermissionProvider {
            #[cfg(feature = "rebac")]
            router: kernel.vfs_router_arc(),
            #[cfg(feature = "rebac")]
            relationships: None,
        };
        kernel.set_permission_provider(Arc::new(Box::new(provider)));
        // Recorded counterexample, not proof of authorization: Open posture
        // cannot qualify a hosting node for collaboration-space activation.
        assert!(kernel
            .check_permission(
                "/collaboration/v1/space/pairs/a/b/transcript",
                Permission::Write,
                &context,
            )
            .is_ok());
    }

    #[test]
    fn http_requires_compiled_enforcement_and_loopback() {
        let mut args = crate::Args::try_parse_from(["nexusd-cluster"])
            .unwrap()
            .common;
        args.enable_rebac = false;
        args.http_addr = None;
        assert!(validate(&args).is_ok());
        args.http_addr = Some("127.0.0.1:2026".parse().unwrap());
        assert!(validate(&args).is_err());
        args.enable_rebac = true;
        assert_eq!(validate(&args).is_ok(), cfg!(feature = "http-api"));
        args.http_addr = Some("0.0.0.0:2026".parse().unwrap());
        assert!(validate(&args).is_err());
        args.http_addr = None;
        assert_eq!(validate(&args).is_ok(), cfg!(feature = "rebac"));
    }
}
