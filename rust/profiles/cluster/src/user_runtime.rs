//! A durable runtime for one owner, using credentials issued outside this process.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use kernel::kernel::Kernel;
use lib::transport_primitives::{
    server_config, user_runtime_name_from_x509, user_runtime_server_name, AgentCredential,
    FederatedClientCertVerifier, LoadedCredential, SharedTlsConfig, SharedTlsListener, TlsConfig,
    TlsPolicy, USER_RUNTIME_MAX_VALIDITY_SECS,
};
use transport::grpc::{build_user_runtime_routes, DataPlaneReady};
use transport::runtime_scope::RuntimeScope;
use x509_parser::prelude::*;

use super::{BoxedServiceDeclsBuilder, CommonArgs, ServiceBootCtx};

const OWNER_FILE: &str = ".user-runtime-owner";

struct ValidatedCredential {
    bundle: LoadedCredential,
    identity: RuntimeIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeIdentity {
    agent: String,
    replica_id: Option<u64>,
}

impl ValidatedCredential {
    fn tls(&self) -> TlsConfig {
        TlsConfig {
            cert_pem: self.bundle.cert_pem.clone(),
            key_pem: self.bundle.key_pem.clone(),
            ca_pem: self.bundle.ca_pem.clone(),
        }
    }
}

enum CredentialUse<'a> {
    Bootstrap,
    Rotation(&'a RuntimeIdentity),
}

fn validate_credential(
    bundle: LoadedCredential,
    owner: &str,
    verifier: &FederatedClientCertVerifier,
    usage: CredentialUse<'_>,
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
    // Bootstrap may retain an expired identity while awaiting its projected
    // replacement. TLS and RuntimeScope still refuse expired authority. This
    // avoids a container restart backoff outlasting every renewed credential.
    let is_expired_bootstrap =
        matches!(&usage, CredentialUse::Bootstrap) && cert.validity().not_after < ASN1Time::now();
    if !cert.validity().is_valid() && !is_expired_bootstrap {
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
    u64::try_from(cert.validity().not_after.timestamp()).context("invalid runtime expiry")?;
    let identity = RuntimeIdentity {
        agent: peer
            .agent_name
            .context("runtime certificate lacks an agent subject")?,
        replica_id: lib::transport_primitives::replica_node_id_from_x509(&cert)
            .map_err(anyhow::Error::msg)?,
    };
    if let CredentialUse::Rotation(expected) = usage {
        if &identity != expected {
            bail!("runtime renewal must preserve its agent subject and replica identity");
        }
    }
    Ok(ValidatedCredential { bundle, identity })
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
        || !common.cluster_init.is_empty()
        || !common.cluster_init_mount.is_empty()
        || common.enable_rebac
        || common.http_addr.is_some()
        || !common.mount_drivers.is_empty()
        || common.identity_dir.is_some()
    {
        bail!("serve-user requires a fixed owner, external credential and durable storage with authenticated listeners");
    }
    Ok(())
}

struct ReplicaNetwork {
    node_id: u64,
    hostname: String,
    peers: Vec<String>,
    self_address: String,
}

impl ReplicaNetwork {
    fn from_identity(common: &CommonArgs, identity: &RuntimeIdentity) -> Result<Option<Self>> {
        let Some(node_id) = identity.replica_id else {
            if !common.peers.trim().is_empty() || common.advertise_addr.is_some() {
                bail!("peer routing requires a signed replica identity");
            }
            return Ok(None);
        };
        let peers =
            nexus_raft::transport::NodeAddress::parse_peer_list_operator(&common.peers, true)
                .map_err(|error| anyhow::anyhow!("runtime peer address: {error}"))?;
        let hostname = super::resolve_hostname(common.hostname.as_deref());
        let bind: std::net::SocketAddr = common
            .effective_bind_addr()
            .parse()
            .context("runtime bind address")?;
        let has_remote_peer = peers.iter().any(|peer| {
            super::peer_host(&peer.to_raft_peer_str())
                .is_some_and(|host| !super::host_is_loopback(host))
        });
        let self_address = super::resolve_self_address(
            common.advertise_addr.as_deref(),
            &hostname,
            bind.port(),
            has_remote_peer,
            peers.len(),
        )?;
        let peers = super::peers_excluding_self(&peers, &self_address)
            .iter()
            .map(nexus_raft::transport::NodeAddress::to_raft_peer_str)
            .collect();
        Ok(Some(Self {
            node_id,
            hostname,
            peers,
            self_address,
        }))
    }
}

pub(super) async fn serve(
    common: CommonArgs,
    build_decls: BoxedServiceDeclsBuilder,
    owner: String,
    credential_path: PathBuf,
    backend_config: Option<PathBuf>,
) -> Result<()> {
    super::refuse_retired_env_vars()?;
    validate_options(&common)?;
    let backends = super::runtime_backends::RuntimeBackends::load(backend_config.as_deref())?;
    let scope = RuntimeScope::new(owner.clone(), [])?;
    let initial = AgentCredential::load(&credential_path).map_err(anyhow::Error::msg)?;
    let verifier = FederatedClientCertVerifier::new(&initial.ca_pem).map_err(anyhow::Error::msg)?;
    let initial = validate_credential(initial, &owner, &verifier, CredentialUse::Bootstrap)?;
    let network = ReplicaNetwork::from_identity(&common, &initial.identity)?;
    let identity = SharedTlsConfig::new(Some(initial.tls()));
    let bind = common.effective_bind_addr();
    let self_address = network
        .as_ref()
        .map_or_else(|| bind.clone(), |network| network.self_address.clone());
    let (prepared_zones, local_listener) = match network {
        Some(network) => (
            Some(
                nexus_raft::zone_manager::ZoneManager::prepare_local_root_shared(
                    &network.hostname,
                    network.node_id,
                    network.peers,
                    &bind,
                    identity.clone(),
                    Some(network.self_address),
                )
                .context("prepare user runtime zones")?,
            ),
            None,
        ),
        None => {
            let tls = SharedTlsListener::prepare(identity.clone(), Some(Arc::clone(&verifier)))
                .map_err(anyhow::Error::msg)?;
            let listener = tokio::net::TcpListener::bind(&bind)
                .await
                .with_context(|| format!("bind user runtime {bind}"))?;
            (None, Some((tls, listener)))
        }
    };
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
    let auth: Arc<dyn transport::auth::AuthProvider> =
        Arc::new(auth::ApiKeyAuthProvider::cert_identity_for_user_runtime(
            initial.bundle.server_name.clone(),
        ));
    super::plugin_loading::load(&kernel, common.plugin_dir.as_deref())?;
    let verifier_slot = Arc::new(std::sync::OnceLock::new());
    verifier_slot
        .set(Arc::clone(&verifier))
        .map_err(|_| anyhow::anyhow!("runtime verifier already installed"))?;
    let scope = scope.with_server_identity(identity.clone());
    let ready = DataPlaneReady::pending();
    let routes = build_user_runtime_routes(
        Arc::clone(&kernel),
        Arc::clone(&auth),
        scope.clone(),
        Arc::clone(&verifier_slot),
        Arc::clone(&ready),
        contracts::MAX_GRPC_MESSAGE_BYTES,
        super::daemon_version_string(),
    );
    let routes = super::plugin_loading::routes(
        routes,
        &kernel,
        &auth,
        verifier_slot,
        Arc::clone(&ready),
        Some(Arc::new(scope)),
    );
    let (zones, local_routes) = tokio::task::spawn_blocking(move || {
        use nexus_raft::zone_manager::ZoneManager;
        match prepared_zones {
            Some(prepared) => prepared
                .open(&data_dir, Some(routes))
                .map(|zones| (zones, None)),
            None => ZoneManager::isolated(&data_dir).map(|zones| (zones, Some(routes))),
        }
    })
    .await
    .context("open user runtime zone task")?
    .context("open user runtime zone")?;
    let root = zones
        .create_zone_async(contracts::ROOT_ZONE_ID)
        .await
        .context("open durable user root zone")?;
    let root_for_wait = Arc::clone(&root);
    if !tokio::task::spawn_blocking(move || root_for_wait.wait_for_leader(Duration::from_secs(10)))
        .await
        .context("wait for user root leader task")?
    {
        bail!("user root zone has no leader; durable writes are unavailable");
    }
    let peer_client = Arc::new(transport::federation::FederationClient::with_shared_tls(
        kernel.runtime().handle().clone(),
        identity.clone(),
    ));
    transport::federation::runtime_directory::install(
        &kernel,
        Arc::clone(&peer_client),
        a2a::A2A_INBOX_BASE,
    )
    .map_err(anyhow::Error::msg)?;
    Arc::new(nexus_raft::distributed_coordinator::RaftDistributedCoordinator::new())
        .install_with_kernel(
            Arc::clone(&zones),
            zones.runtime_handle(),
            &self_address,
            &kernel,
            peer_client,
        );
    transport::peer_blob::install_with_shared_tls(kernel.as_ref(), identity.clone());
    super::stream_observers::install_wakeup(&kernel, &zones);
    let ctx = ServiceBootCtx {
        auth_armed: true,
        auth: Arc::clone(&auth),
        runtime: tokio::runtime::Handle::current(),
        credential_plane: None,
    };
    kernel
        .bring_up_services(build_decls(&ctx))
        .map_err(|error| anyhow::anyhow!("bring up user runtime services: {error}"))?;
    backends.install(&kernel)?;
    ready.mark_ready();
    tracing::info!(owner = %owner, bind = %bind, replica = ?initial.identity.replica_id, "confined user runtime ready");
    let reload = tokio::spawn(async move {
        let expected_identity = initial.identity;
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
            let candidate = match validate_credential(
                candidate,
                &owner,
                &verifier,
                CredentialUse::Rotation(&expected_identity),
            ) {
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
                Ok(_) => {
                    identity.replace(TlsPolicy::Configured(candidate.tls()));
                    previous = candidate.bundle;
                    tracing::info!("runtime server identity rotated");
                }
                Err(error) => tracing::warn!(%error, "runtime TLS replacement refused"),
            }
        }
    });
    let result = match (local_listener, local_routes) {
        (Some((tls_listener, listener)), Some(routes)) => {
            lib::transport_primitives::apply_server_limits(tonic::transport::Server::builder())
                .timeout(Duration::from_secs(60))
                .add_routes(routes)
                .serve_with_incoming_shutdown(
                    tls_listener.incoming(listener),
                    super::wait_for_shutdown(),
                )
                .await
                .context("user runtime server")
        }
        (None, None) => {
            super::wait_for_shutdown().await;
            Ok(())
        }
        _ => unreachable!("runtime listener and routes belong to the same transport"),
    };
    reload.abort();
    tokio::task::spawn_blocking(move || zones.shutdown())
        .await
        .context("stop user runtime zones")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_raft::transport::{
        generate_user_replica_cert, generate_user_runtime_cert, generate_zone_ca,
    };

    #[test]
    fn renewal_preserves_the_signed_subject_and_replica_profile() {
        let (ca, ca_key) = generate_zone_ca("root").unwrap();
        let verifier = FederatedClientCertVerifier::new(&ca).unwrap();
        let bundle = |agent: &str, replica| {
            let (cert_pem, key_pem) = match replica {
                Some(id) => generate_user_replica_cert(agent, "alice", id, 300, &ca, &ca_key),
                None => generate_user_runtime_cert(agent, "alice", 300, &ca, &ca_key),
            }
            .unwrap();
            LoadedCredential {
                agent: "manifest-is-not-identity-authority".into(),
                server_name: user_runtime_server_name("alice").unwrap(),
                ca_pem: ca.clone(),
                cert_pem,
                key_pem,
            }
        };
        for replica in [None, Some(31)] {
            let initial = validate_credential(
                bundle("runtime", replica),
                "alice",
                &verifier,
                CredentialUse::Bootstrap,
            )
            .unwrap();
            assert_eq!(initial.identity.agent, "runtime");
            assert_eq!(initial.identity.replica_id, replica);
            let expected = &initial.identity;
            let renewal = validate_credential(
                bundle("runtime", replica),
                "alice",
                &verifier,
                CredentialUse::Rotation(expected),
            )
            .unwrap();
            assert_eq!(&renewal.identity, expected);
            assert_ne!(renewal.bundle.key_pem, initial.bundle.key_pem);
            for (agent, replacement) in [
                ("other-runtime", replica),
                ("runtime", Some(32)),
                ("runtime", if replica.is_some() { None } else { Some(31) }),
            ] {
                let refused = validate_credential(
                    bundle(agent, replacement),
                    "alice",
                    &verifier,
                    CredentialUse::Rotation(expected),
                );
                let error = refused
                    .err()
                    .expect("renewal changed the signed runtime identity");
                assert!(error
                    .to_string()
                    .contains("preserve its agent subject and replica identity"));
            }
        }
    }
}
