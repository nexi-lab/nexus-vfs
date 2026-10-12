use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use kernel::kernel::Kernel;

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
