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

/// The cluster's single permission slot enforces both policies, in order.
/// Foreign containment bounds trust-domain authority even when relationships grant access.
struct ClusterPermissionProvider {
    #[cfg(feature = "rebac")]
    router: Arc<VFSRouter>,
    #[cfg(feature = "rebac")]
    relationships: Option<nexus_rebac::RebacPermissionProvider>,
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
    _ctx: &ServiceBootCtx,
    _tls: Option<&nexus_raft::transport::TlsConfig>,
    _ready: Arc<DataPlaneReady>,
) -> Result<Vec<ServiceDecl>> {
    #[cfg(feature = "rebac")]
    let store = common.enable_rebac.then(|| {
        nexus_rebac::RaftReBACTupleStore::new_arc(
            _ctx.credential_consensus.clone(),
            _ctx.credential_zone_runtime.clone(),
        )
    });
    #[cfg(feature = "rebac")]
    let relationships = store.as_ref().map(|store| {
        nexus_rebac::RebacPermissionProvider::new(Arc::new(nexus_rebac::ReBACGraphCache::new(
            Arc::clone(store),
        )))
    });
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
                if _ctx.auth_armed && _ctx.api_key_secret.is_none() {
                    bail!("HTTP bearer authentication requires NEXUS_API_KEY_SECRET; the certificate-only auth posture cannot authenticate HTTP callers");
                }
                use nexus_search_common::transport::{PeerChannelCache, PeerChannelConfig};
                use tonic::transport::{Certificate, ClientTlsConfig, Identity};
                let grpc = common.effective_bind_addr();
                let mut grpc: std::net::SocketAddr = grpc.parse()?;
                if grpc.ip().is_unspecified() {
                    grpc.set_ip(if grpc.is_ipv4() {
                        std::net::Ipv4Addr::LOCALHOST.into()
                    } else {
                        std::net::Ipv6Addr::LOCALHOST.into()
                    });
                }
                let (scheme, channels) = match _tls {
                    Some(tls) => (
                        "https",
                        PeerChannelCache::with_tls(
                            PeerChannelConfig::default(),
                            ClientTlsConfig::new()
                                .domain_name(nexus_raft::transport::TlsConfig::CLUSTER_SERVER_NAME)
                                .ca_certificate(Certificate::from_pem(&tls.ca_pem))
                                .identity(Identity::from_pem(&tls.cert_pem, &tls.key_pem)),
                        ),
                    ),
                    None => ("http", PeerChannelCache::new(PeerChannelConfig::default())),
                };
                let search = nexus_http_api::SearchBackend::with_channels(
                    format!("{scheme}://{grpc}"),
                    Arc::new(channels),
                );
                services.push(nexus_http_api::service_decl(
                    addr,
                    search,
                    Arc::clone(&_ctx.auth),
                    _ctx.runtime.clone(),
                    _ctx.api_key_secret.as_deref().map(Arc::from),
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
