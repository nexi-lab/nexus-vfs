//! Local backend assembly for an owner-confined runtime.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use kernel::hal::object_store_provider::{get_provider, ObjectStoreProviderArgs};
use kernel::kernel::convenience::{KernelConvenience, MountOptions};
use kernel::kernel::Kernel;
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeBackends {
    mounts: Vec<BackendMount>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendMount {
    path: String,
    backend_type: String,
    backend_name: String,
    #[serde(default)]
    backend_params: HashMap<String, String>,
}

impl RuntimeBackends {
    pub(super) fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let config: Self = serde_json::from_slice(
            &std::fs::read(path)
                .with_context(|| format!("read runtime backends {}", path.display()))?,
        )
        .context("parse runtime backend configuration")?;
        let mut paths = HashSet::new();
        for mount in &config.mounts {
            if !mount.path.starts_with('/')
                || mount.path.contains('\\')
                || mount.path.chars().any(char::is_control)
                || mount.path[1..]
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || mount.path == "/proc"
                || mount.path.starts_with("/proc/")
                || !paths.insert(&mount.path)
            {
                bail!("runtime backend mount paths must be distinct canonical absolute paths outside /proc");
            }
            if mount.backend_name.is_empty() || mount.backend_type.is_empty() {
                bail!("runtime backends require a name and backend type");
            }
            if mount.backend_type == "remote" {
                bail!("runtime backend configuration cannot introduce a remote kernel");
            }
        }
        Ok(config)
    }

    pub(super) fn install(self, kernel: &Arc<Kernel>) -> Result<()> {
        if self.mounts.is_empty() {
            return Ok(());
        }
        let provider = get_provider().context("runtime ObjectStoreProvider unavailable")?;
        for mount in self.mounts {
            if !provider.can_build(&mount.backend_type) {
                bail!(
                    "runtime backend type {:?} is unavailable in this build",
                    mount.backend_type
                );
            }
            let peer_client = kernel.peer_client_arc();
            let self_address = kernel.self_address_string();
            let built = provider
                .build(&ObjectStoreProviderArgs {
                    backend_type: &mount.backend_type,
                    backend_name: &mount.backend_name,
                    mount_path: Some(&mount.path),
                    backend_params: &mount.backend_params,
                    peer_client: &peer_client,
                    self_address: self_address.as_deref(),
                    runtime: kernel.runtime(),
                })
                .map_err(anyhow::Error::msg)
                .context("construct runtime backend")?;
            if built.pending_remote_meta_store.is_some() {
                bail!("runtime backend cannot replace the owner metastore");
            }
            let backend = built
                .backend
                .context("runtime backend was not constructed")?;
            let parent = mount
                .path
                .rsplit_once('/')
                .map(|(parent, _)| parent)
                .unwrap_or("/");
            let parent = if parent.is_empty() { "/" } else { parent };
            let parent_metastore = kernel
                .vfs_router_arc()
                .route(parent, contracts::ROOT_ZONE_ID)
                .and_then(|route| route.metastore);
            let mut options = MountOptions::new(&mount.backend_name)
                .with_backend(backend)
                .with_zone(contracts::ROOT_ZONE_ID);
            if let Some(metastore) = parent_metastore {
                options = options.with_metastore(metastore);
            }
            kernel.mount(&mount.path, options).map_err(|error| {
                anyhow::anyhow!("install runtime backend at {}: {error:?}", mount.path)
            })?;
            tracing::info!(path = %mount.path, backend_type = %mount.backend_type, "runtime backend installed");
            // Constructor parameters can contain a provider credential. They
            // are consumed by the live backend, never written to the metastore.
        }
        Ok(())
    }
}
