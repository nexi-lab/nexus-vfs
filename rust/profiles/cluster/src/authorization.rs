//! Production authorization and HTTP composition. Tuples and API keys share
//! the credential consensus; transports share the daemon's identity and gate.

use super::{CommonArgs, ServiceBootCtx};
use anyhow::{bail, Result};
use kernel::kernel::ServiceDecl;
use std::sync::Arc;
use transport::grpc::DataPlaneReady;

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
    let services = Vec::new();
    #[cfg(feature = "rebac")]
    let services = {
        let mut services = services;
        if common.enable_rebac {
            let store = nexus_rebac::RaftReBACTupleStore::new_arc(
                _ctx.credential_consensus.clone(),
                _ctx.credential_zone_runtime.clone(),
            );
            services.push(nexus_rebac::service_decl(Arc::clone(&store)));
            #[cfg(feature = "http-api")]
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
