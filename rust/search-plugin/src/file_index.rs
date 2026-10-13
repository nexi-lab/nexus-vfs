//! Materialize one VFS file through the existing kernel callbacks.

use nexus_plugin_abi::KernelHandle;
use tonic::Status;

use crate::kernel_io::{self, KernelIoError, DT_REG, DT_STREAM};
use crate::search_proto::DocumentInput;

pub(crate) fn read_document(
    handle: &KernelHandle,
    path: &str,
    zone: &str,
) -> Result<Option<DocumentInput>, Status> {
    if !path.starts_with('/') {
        return Err(Status::invalid_argument(
            "path must be an absolute VFS path",
        ));
    }
    let stat = kernel_io::sys_stat(handle, path).map_err(io_status)?;
    if !matches!(stat.entry_type, DT_REG | DT_STREAM) {
        return Err(Status::invalid_argument("path must name a file or stream"));
    }
    // Callbacks use the kernel's canonical namespace. Refuse a source from
    // another partition before reading bytes or changing the requested index.
    let owner = stat.zone_id.ok_or_else(|| {
        Status::failed_precondition("kernel stat did not report the file's owning zone")
    })?;
    if owner != zone {
        return Err(Status::invalid_argument(
            "zone_id does not match the file's owning zone",
        ));
    }
    let bytes = kernel_io::sys_read(handle, path).map_err(io_status)?;
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };
    Ok(Some(DocumentInput {
        path: path.into(),
        text,
        mtime_ms: stat.modified_at_ms,
        zone_id: owner,
    }))
}

fn io_status(error: KernelIoError) -> Status {
    match error {
        KernelIoError::NotFound => Status::not_found("VFS file does not exist"),
        KernelIoError::PathHasNul => Status::invalid_argument("path contains a NUL byte"),
        other => Status::internal(format!("read VFS file for indexing: {other:?}")),
    }
}
