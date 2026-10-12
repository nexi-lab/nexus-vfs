use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use kernel::kernel::Kernel;
use transport::auth::AuthProvider;
use transport::grpc::{DataPlaneReady, ForeignCaVerifierSlot};
use transport::grpc_plugin_access::{AuthenticatedPlugin, PluginGrpcPolicy, RuntimeScopedPlugin};
use transport::grpc_search_access::{SearchGrpcPolicy, SERVICE_NAME};
use transport::runtime_scope::RuntimeScope;

/// Load the deployment's signed plugins into the selected durable kernel.
pub(super) fn load(kernel: &Arc<Kernel>, directory: Option<&Path>) -> Result<()> {
    let Some(directory) = directory else {
        return Ok(());
    };
    let names = kernel.load_plugin_dir(directory).map_err(|error| {
        anyhow::anyhow!("--plugin-dir {} load failed: {error}", directory.display())
    })?;
    if !names.is_empty() {
        tracing::info!(
            count = names.len(),
            names = ?names,
            dir = %directory.display(),
            "plugins loaded from --plugin-dir",
        );
    }
    Ok(())
}

/// Register each signed plugin with its service policy and the endpoint's scope.
pub(super) fn routes(
    routes: tonic::service::Routes,
    kernel: &Arc<Kernel>,
    auth: &Arc<dyn AuthProvider>,
    verifier: ForeignCaVerifierSlot,
    ready: Arc<DataPlaneReady>,
    scope: Option<Arc<RuntimeScope>>,
) -> tonic::service::Routes {
    transport::grpc_plugin_proxy::extend_routes_with_plugin_endpoints(
        routes,
        kernel.plugin_grpc_endpoints(),
        verifier,
        ready,
        |endpoint| {
            let policy: Arc<dyn PluginGrpcPolicy> = if endpoint.service_name == SERVICE_NAME {
                Arc::new(SearchGrpcPolicy::new(Arc::clone(kernel), Arc::clone(auth)))
            } else {
                Arc::new(AuthenticatedPlugin::new(Arc::clone(auth)))
            };
            match &scope {
                Some(scope) => Arc::new(RuntimeScopedPlugin::new(
                    policy,
                    Arc::clone(auth),
                    Arc::clone(scope),
                )),
                None => policy,
            }
        },
    )
}
