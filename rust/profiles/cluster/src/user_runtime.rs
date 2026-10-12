//! A durable runtime for one owner, using credentials issued outside this process.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use kernel::kernel::Kernel;
use lib::transport_primitives::{
    reloadable_tls_incoming, server_config, user_runtime_name_from_x509, user_runtime_server_name,
    AgentCredential, FederatedClientCertVerifier, LoadedCredential, ReloadableServerIdentity,
    USER_RUNTIME_MAX_VALIDITY_SECS,
};
use transport::grpc::{build_user_runtime_routes, DataPlaneReady};
use transport::runtime_scope::RuntimeScope;
use x509_parser::prelude::*;

use super::{BoxedServiceDeclsBuilder, CommonArgs, ServiceBootCtx};

const OWNER_FILE: &str = ".user-runtime-owner";

struct ValidatedCredential {
    bundle: LoadedCredential,
    expires_at: u64,
}

fn validate_credential(
    bundle: LoadedCredential,
    owner: &str,
    verifier: &FederatedClientCertVerifier,
) -> Result<ValidatedCredential> {
    let ca = ::pem::parse(&bundle.ca_pem).context("runtime CA PEM")?;
    if ca.contents() != verifier.cluster_ca_der() {
        bail!("runtime credential cannot change its trust root");
    }
    let bytes = ::pem::parse(&bundle.cert_pem).context("runtime certificate PEM")?;
    let (_, cert) = X509Certificate::from_der(bytes.contents())
        .map_err(|_| anyhow::anyhow!("invalid runtime certificate"))?;
    let name = user_runtime_name_from_x509(&cert).map_err(anyhow::Error::msg)?;
    if name.as_deref()
        != Some(
            user_runtime_server_name(owner)
                .map_err(anyhow::Error::msg)?
                .as_str(),
        )
    {
        bail!("runtime certificate belongs to another owner or lacks server capability");
    }
    if !cert.validity().is_valid() {
        bail!("runtime certificate is outside its validity window");
    }
    let lifetime = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
    if lifetime <= 0 || lifetime > USER_RUNTIME_MAX_VALIDITY_SECS as i64 {
        bail!("runtime certificate exceeds the permitted lifetime");
    }
    let peer = transport::peer_identity::classify_peer_cert(
        bytes.contents(),
        verifier.cluster_ca_der(),
        &[],
    )
    .map_err(|_| anyhow::anyhow!("runtime certificate has an untrusted issuer"))?;
    if peer.owner.as_deref() != Some(owner)
        || peer.agent_name.is_none()
        || peer.node_id.is_some()
        || peer.zone_id.is_some()
        || peer.trust_domain.is_some()
        || cert
            .basic_constraints()
            .map_err(|_| anyhow::anyhow!("invalid runtime constraints"))?
            .is_some_and(|constraints| constraints.value.ca)
    {
        bail!("runtime credential must be an ordinary agent of its fixed owner");
    }
    Ok(ValidatedCredential {
        expires_at: u64::try_from(cert.validity().not_after.timestamp())
            .context("invalid runtime expiry")?,
        bundle,
    })
}

fn bind_owner(dir: &Path, owner: &str) -> Result<()> {
    std::fs::create_dir_all(dir).context("create user runtime data directory")?;
    let file = dir.join(OWNER_FILE);
    if file.exists() {
        if std::fs::read(&file).context("read runtime owner binding")? != owner.as_bytes() {
            bail!("user runtime data directory belongs to another owner");
        }
        return Ok(());
    }
    if std::fs::read_dir(dir)?.next().is_some() {
        bail!("user runtime requires an empty new directory or an existing owner binding");
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file)
    {
        Ok(mut file) => {
            file.write_all(owner.as_bytes())
                .context("write runtime owner binding")?;
            file.sync_all().context("persist runtime owner binding")?;
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            if std::fs::read(&file)? != owner.as_bytes() {
                bail!("user runtime data directory belongs to another owner");
            }
        }
        Err(error) => return Err(error).context("create runtime owner binding"),
    }
    Ok(())
}

fn validate_options(common: &CommonArgs) -> Result<()> {
    if std::env::var_os("NEXUS_API_KEY_SECRET").is_some()
        || common.no_tls
        || common.insecure_no_auth
        || common.accept_enrollments
        || common.token.is_some()
        || !common.peers.trim().is_empty()
        || !common.cluster_init.is_empty()
        || !common.cluster_init_mount.is_empty()
        || common.enable_rebac
        || common.http_addr.is_some()
        || common.plugin_dir.is_some()
        || !common.mount_drivers.is_empty()
        || common.identity_dir.is_some()
        || common.advertise_addr.is_some()
    {
        bail!("serve-user accepts a fixed owner, external credential and local durable storage; cluster authority, federation, plugins and unauthenticated listeners are unavailable");
    }
    Ok(())
}

pub(super) async fn serve(
    common: CommonArgs,
    build_decls: BoxedServiceDeclsBuilder,
    owner: String,
    credential_path: PathBuf,
) -> Result<()> {
    super::refuse_retired_env_vars()?;
    validate_options(&common)?;
    let scope = RuntimeScope::new(owner.clone(), [])?;
    let initial = AgentCredential::load(&credential_path).map_err(anyhow::Error::msg)?;
    let verifier = FederatedClientCertVerifier::new(&initial.ca_pem).map_err(anyhow::Error::msg)?;
    let initial = validate_credential(initial, &owner, &verifier)?;
    let identity = ReloadableServerIdentity::new(
        server_config(
            Arc::clone(&verifier),
            &initial.bundle.cert_pem,
            &initial.bundle.key_pem,
        )
        .map_err(anyhow::Error::msg)?,
        initial.expires_at,
    );
    bind_owner(&common.data_dir, &owner)?;
    super::set_provider(Arc::new(super::DefaultObjectStoreProvider))
        .unwrap_or_else(|_| tracing::warn!("ObjectStoreProvider already registered"));
    let kernel = Arc::new(Kernel::new());
    if super::wire_durable_metastore(&kernel, common.metastore_path.as_deref(), &common.data_dir)?
        .is_none()
    {
        bail!("serve-user requires a durable metastore");
    }
    super::mount_root_filesystem(&kernel, &common)?;
    let data_dir = common
        .data_dir
        .to_str()
        .context("user runtime data directory must be UTF-8")?
        .to_owned();
    let zones = tokio::task::spawn_blocking(move || {
        nexus_raft::zone_manager::ZoneManager::isolated(&data_dir)
    })
    .await
    .context("open user runtime zone task")?
    .context("open user runtime zone")?;
    let root = zones
        .create_zone_async(contracts::ROOT_ZONE_ID, Vec::new())
        .await
        .context("open durable user root zone")?;
    let root_for_wait = Arc::clone(&root);
    if !tokio::task::spawn_blocking(move || root_for_wait.wait_for_leader(Duration::from_secs(10)))
        .await
        .context("wait for user root leader task")?
    {
        bail!("user root zone has no leader; durable writes are unavailable");
    }
    let peer_client = Arc::new(transport::federation::FederationClient::new(
        Arc::clone(kernel.runtime()),
        None,
    ));
    Arc::new(nexus_raft::distributed_coordinator::RaftDistributedCoordinator::new())
        .install_with_kernel(
            Arc::clone(&zones),
            zones.runtime_handle(),
            &common.effective_bind_addr(),
            &kernel,
            peer_client,
        );
    let auth: Arc<dyn transport::auth::AuthProvider> =
        Arc::new(auth::ApiKeyAuthProvider::cert_identity_only());
    let ctx = ServiceBootCtx {
        auth_armed: true,
        auth: Arc::clone(&auth),
        runtime: tokio::runtime::Handle::current(),
        credential_plane: None,
    };
    kernel
        .bring_up_services(build_decls(&ctx))
        .map_err(|error| anyhow::anyhow!("bring up user runtime services: {error}"))?;
    let verifier_slot = Arc::new(std::sync::OnceLock::new());
    verifier_slot
        .set(Arc::clone(&verifier))
        .map_err(|_| anyhow::anyhow!("runtime verifier already installed"))?;
    let routes = build_user_runtime_routes(
        kernel,
        auth,
        scope.with_server_identity(Arc::clone(&identity)),
        verifier_slot,
        DataPlaneReady::open(),
        contracts::MAX_GRPC_MESSAGE_BYTES,
        super::daemon_version_string(),
    );
    let bind = common.effective_bind_addr();
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind user runtime {bind}"))?;
    tracing::info!(owner = %owner, bind = %listener.local_addr()?, "confined user runtime ready");
    let incoming = reloadable_tls_incoming(listener, Arc::clone(&identity));
    let reload = tokio::spawn(async move {
        let mut previous = initial.bundle;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let path = credential_path.clone();
            let candidate = tokio::task::spawn_blocking(move || AgentCredential::load(&path)).await;
            let candidate = match candidate {
                Ok(Ok(bundle)) => bundle,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "runtime credential reload refused");
                    continue;
                }
                Err(error) => {
                    tracing::error!(%error, "runtime credential loader failed");
                    break;
                }
            };
            if candidate.cert_pem == previous.cert_pem
                && candidate.key_pem == previous.key_pem
                && candidate.ca_pem == previous.ca_pem
            {
                continue;
            }
            let candidate = match validate_credential(candidate, &owner, &verifier) {
                Ok(candidate) => candidate,
                Err(error) => {
                    tracing::warn!(%error, "runtime credential replacement refused");
                    continue;
                }
            };
            match server_config(
                Arc::clone(&verifier),
                &candidate.bundle.cert_pem,
                &candidate.bundle.key_pem,
            ) {
                Ok(config) => {
                    identity.replace(config, candidate.expires_at);
                    previous = candidate.bundle;
                    tracing::info!("runtime server identity rotated");
                }
                Err(error) => tracing::warn!(%error, "runtime TLS replacement refused"),
            }
        }
    });
    let result =
        lib::transport_primitives::apply_server_limits(tonic::transport::Server::builder())
            .timeout(Duration::from_secs(60))
            .add_routes(routes)
            .serve_with_incoming_shutdown(incoming, super::wait_for_shutdown())
            .await;
    reload.abort();
    result.context("user runtime server")
}
